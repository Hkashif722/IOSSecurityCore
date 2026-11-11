//
//  SecurityEngine.swift
//  IOSSecurityCore
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import Foundation
import IOSSecurityCoreObjC
import os

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
/// let report = try await SecurityEngine.shared.evaluate()
///
/// // A debugger can attach at any time, so keep watching.
/// for await report in SecurityEngine.shared.monitor() { … }
///
/// // Or observe every report the engine produces, wherever it was requested.
/// for await report in SecurityEngine.shared.reports { … }
/// ```
///
/// The engine only *reports*. What to do about a compromised device is the host app's decision (see
/// ``SecurityPolicy``), and the strongest version of that decision is made on a server.
public final class SecurityEngine: Sendable {

    /// The package version.
    public static let version = "1.0.0"

    /// A shared engine for apps that need only one.
    public static let shared = SecurityEngine()

    /// Everything that changes after `init`, behind one lock.
    private struct State {
        var configuration: SecurityConfiguration
        var subscribers: [UUID: AsyncStream<SecurityReport>.Continuation] = [:]
    }

    private let state: OSAllocatedUnfairLock<State>
    private let queue = DispatchQueue(label: "IOSSecurityCore.scan", qos: .utility)

    /// Creates an engine.
    /// - Parameter configuration: The initial configuration. Change it later through ``configuration``.
    public init(configuration: SecurityConfiguration = .default) {
        state = OSAllocatedUnfairLock(initialState: State(configuration: configuration))
    }

    deinit {
        // A task awaiting `reports` must see the sequence end, not wait forever for an engine that is gone.
        for subscriber in state.withLock({ Array($0.subscribers.values) }) {
            subscriber.finish()
        }
    }

    // MARK: - Configuration

    /// The configuration in effect. Evaluations that already started keep the one they began with.
    public var configuration: SecurityConfiguration {
        get { state.withLock { $0.configuration } }
        set { state.withLock { $0.configuration = newValue } }
    }

    // MARK: - Evaluation

    /// Evaluates the environment off the calling thread and returns the report.
    ///
    /// Scans run one at a time, so a call can wait behind others. If the calling task is cancelled before
    /// its scan starts, the scan does not run and this throws `CancellationError`. A scan that has started
    /// takes milliseconds and finishes; its report is returned.
    ///
    /// - Parameter checks: Run only these check families instead of the configured ones.
    /// - Throws: `CancellationError`, and nothing else.
    public func evaluate(checks: Set<SecurityCheck>? = nil) async throws -> SecurityReport {
        try Task.checkCancellation()
        let cancelled = OSAllocatedUnfairLock(initialState: false)
        let snapshot = configuration
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async { [self] in
                    if cancelled.withLock({ $0 }) {
                        continuation.resume(throwing: CancellationError())
                    } else {
                        continuation.resume(returning: performScan(configuration: snapshot, checks: checks))
                    }
                }
            }
        } onCancel: {
            cancelled.withLock { $0 = true }
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
            completion(performScan(configuration: snapshot, checks: checks))
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

    // MARK: - Observation

    /// Every report this engine produces, from ``evaluate(checks:)``, ``evaluate(checks:completion:)``
    /// and ``monitor(interval:checks:)``, in the order they finish.
    ///
    /// Delivery starts when iteration starts, so reports from before the first `for await` are not
    /// replayed. A slow consumer keeps the newest few reports and drops the rest. The sequence ends when
    /// the engine is deallocated. To stop earlier, cancel the consuming task; that is the supported way to
    /// unsubscribe, and on current toolchains letting the iterator go out of scope does the same.
    ///
    /// ```swift
    /// for await report in SecurityEngine.shared.reports where report.isCompromised { … }
    /// ```
    public var reports: Reports {
        Reports(engine: self)
    }

    /// The reports an engine produces, as an asynchronous sequence. Obtain one from ``SecurityEngine/reports``.
    public struct Reports: AsyncSequence, Sendable {
        public typealias Element = SecurityReport
        public typealias AsyncIterator = AsyncStream<SecurityReport>.Iterator

        fileprivate let engine: SecurityEngine

        public func makeAsyncIterator() -> AsyncIterator {
            engine.makeReportStream().makeAsyncIterator()
        }
    }

    /// How many ``reports`` iterations are currently receiving.
    @_spi(Testing) public var reportSubscriberCount: Int {
        state.withLock { $0.subscribers.count }
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

    /// The SHA-256 of a loaded library's `__TEXT,__text` section: the value for
    /// ``SecurityConfiguration/Integrity/expectedImageTextDigests``. Print it from a TestFlight build.
    ///
    /// - Parameter name: The library's trailing path components, for example `"Auth.framework/Auth"`.
    /// - Returns: Lowercase hex, or `nil` when no such library is loaded or its code cannot be read.
    public func textSegmentDigest(ofImageNamed name: String) async -> String? {
        await withCheckedContinuation { continuation in
            queue.async {
                continuation.resume(returning: ISCIntegrityChecker.textSegmentDigest(ofImageNamed: name))
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
        let requested = checks ?? configuration.checks
        let options = configuration.makeScanOptions(checksOverride: checks)
        let report = SecurityReport(ISCPerformScan(options)).verified(
            requested: requested,
            scansUnsupportedEnvironments: configuration.scansUnsupportedEnvironments
        )
        for subscriber in state.withLock({ Array($0.subscribers.values) }) {
            subscriber.yield(report)
        }
        return report
    }

    /// A stream that receives every report from now until it is dropped or its consumer is cancelled.
    private func makeReportStream() -> AsyncStream<SecurityReport> {
        AsyncStream(bufferingPolicy: .bufferingNewest(16)) { continuation in
            let id = UUID()
            state.withLock { $0.subscribers[id] = continuation }
            continuation.onTermination = { [weak self] _ in
                self?.state.withLock { _ = $0.subscribers.removeValue(forKey: id) }
            }
        }
    }
}
