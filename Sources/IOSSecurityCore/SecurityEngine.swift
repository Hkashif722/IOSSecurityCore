import Combine
import Foundation
import IOSSecurityCoreObjC

/// Evaluates the runtime environment of the host app.
///
/// Every evaluation runs on a private background queue, so calling it from
/// `application(_:didFinishLaunchingWithOptions:)` or `App.init` never blocks the main thread:
///
/// ```swift
/// // Fire and forget at launch.
/// SecurityEngine.shared.evaluate { report in
///     if report.isCompromised { /* degrade, log out, tell your backend */ }
/// }
///
/// // Or with async/await.
/// let report = await SecurityEngine.shared.evaluate()
///
/// // A debugger can attach at any time, so keep watching.
/// for await report in SecurityEngine.shared.monitor() { … }
/// ```
///
/// The engine only *reports*. What to do about a compromised device is the host app's decision, and the
/// strongest version of that decision is made on a server.
public final class SecurityEngine: @unchecked Sendable {

    /// The package version.
    public static let version = "1.0.0"

    /// A shared engine for apps that need only one.
    public static let shared = SecurityEngine()

    private let lock = NSLock()
    private var storedConfiguration: SecurityConfiguration
    private let queue = DispatchQueue(label: "IOSSecurityCore.scan", qos: .utility)
    private let reportSubject = PassthroughSubject<SecurityReport, Never>()

    /// Creates an engine.
    /// - Parameter configuration: The initial configuration. Change it later with ``configure(_:)``.
    public init(configuration: SecurityConfiguration = .default) {
        storedConfiguration = configuration
    }

    // MARK: - Configuration

    /// The configuration in effect.
    public var configuration: SecurityConfiguration {
        locked { storedConfiguration }
    }

    /// Replaces the configuration. Evaluations that already started keep the one they began with.
    public func configure(_ configuration: SecurityConfiguration) {
        locked { storedConfiguration = configuration }
    }

    // MARK: - Evaluation

    /// Evaluates the environment off the calling thread and returns the report.
    ///
    /// - Parameter checks: Run only these check families instead of the configured ones.
    public func evaluate(checks: Set<SecurityCheck>? = nil) async -> SecurityReport {
        await withCheckedContinuation { continuation in
            evaluate(checks: checks) { continuation.resume(returning: $0) }
        }
    }

    /// Starts an evaluation and returns immediately; `completion` runs later on a background queue.
    ///
    /// - Parameters:
    ///   - checks: Run only these check families instead of the configured ones.
    ///   - completion: Called once with the report. Hop to the main queue yourself before touching UI.
    public func evaluate(
        checks: Set<SecurityCheck>? = nil,
        completion: @escaping @Sendable (SecurityReport) -> Void
    ) {
        let snapshot = configuration
        queue.async { [self] in
            let report = performScan(configuration: snapshot, checks: checks)
            completion(report)
        }
    }

    /// Evaluates the environment repeatedly: once immediately, then every `interval` seconds.
    ///
    /// Debuggers and instrumentation attach after launch, so a single check at startup is not enough.
    /// The stream ends when the consuming task is cancelled. Slow consumers see only the newest report.
    ///
    /// - Parameters:
    ///   - interval: Seconds between evaluations (at least 1). Default: 30.
    ///   - checks: The check families to repeat. Default: debugger and hooking, which are cheap and are the
    ///     ones an attacker can change at runtime.
    public func monitor(
        interval: TimeInterval = 30,
        checks: Set<SecurityCheck> = [.debugger, .hooking]
    ) -> AsyncStream<SecurityReport> {
        AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now(), repeating: max(interval, 1), leeway: .seconds(1))
            timer.setEventHandler { [weak self] in
                guard let self else {
                    continuation.finish()
                    return
                }
                continuation.yield(performScan(configuration: configuration, checks: checks))
            }
            continuation.onTermination = { _ in timer.cancel() }
            timer.resume()
        }
    }

    /// Every report this engine produces, from ``evaluate(checks:)`` and ``monitor(interval:checks:)``.
    ///
    /// Values are delivered on a background queue; use `receive(on:)` before updating UI.
    public var reports: AnyPublisher<SecurityReport, Never> {
        reportSubject.eraseToAnyPublisher()
    }

    // MARK: - Raw signals

    /// Collects raw integrity signals, for sending to a server that makes the decision.
    ///
    /// - Parameter includingTextDigest: Also hash the code section. That reads the whole binary, so do it
    ///   at most once per launch.
    public func integritySignals(includingTextDigest: Bool = false) async -> IntegritySignals {
        await withCheckedContinuation { continuation in
            queue.async {
                continuation.resume(returning: IntegritySignals.collect(includingTextDigest: includingTextDigest))
            }
        }
    }

    // MARK: - Countermeasures

    /// Asks the kernel to refuse any future debugger attachment (`PT_DENY_ATTACH`).
    ///
    /// This is a countermeasure, not a check, and it has consequences:
    /// - If a debugger is **already attached**, the kernel terminates the process immediately.
    /// - Xcode, Instruments and LLDB can no longer attach, so never call it in debug or QA builds.
    /// - An attacker with a jailbroken device can still hook the call.
    ///
    /// - Returns: `true` if the request was accepted.
    @discardableResult
    public static func denyDebuggerAttachment() -> Bool {
        ISCDebuggerDetector.denyDebuggerAttachment()
    }

    // MARK: - Internals

    private func performScan(configuration: SecurityConfiguration, checks: Set<SecurityCheck>?) -> SecurityReport {
        let options = configuration.makeScanOptions(checksOverride: checks)
        let report = SecurityReport(ISCSecurityScanner(options: options).scan())
        reportSubject.send(report)
        return report
    }

    private func locked<Result>(_ body: () -> Result) -> Result {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
