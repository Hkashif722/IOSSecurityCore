import Combine
import XCTest
@testable import IOSSecurityCore

final class SecurityEngineTests: XCTestCase {

    private var scratch: URL!

    override func setUpWithError() throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("isc-engine-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    /// A configuration that examines only what the test supplies, wherever it runs.
    private func isolatedConfiguration() -> SecurityConfiguration {
        var configuration = SecurityConfiguration()
        configuration.includesBuiltInIndicators = false
        configuration.scansUnsupportedEnvironments = true
        configuration.performsSandboxWriteProbe = false
        configuration.performsForkProbe = false
        configuration.probesInstrumentationPorts = false
        configuration.probesRemoteShellPorts = false
        configuration.reportsUnknownLibraries = false
        return configuration
    }

    // MARK: - Platform gating

    func testUnsupportedEnvironmentsAreSkippedNotFlagged() async throws {
        try XCTSkipIf(isRunningOnSupportedDevice, "On a real device the checks run for real.")
        let report = await SecurityEngine().evaluate()

        XCTAssertTrue(report.wasSkipped)
        XCTAssertFalse(report.isCompromised, "a Simulator or Mac must never look compromised")
        XCTAssertEqual(report.threats.count, 1)
        XCTAssertEqual(report.threats.first?.category, .environment)
        XCTAssertEqual(report.threats.first?.severity, .info)
        #if targetEnvironment(simulator)
        XCTAssertTrue(report.contains(.simulator))
        #elseif os(macOS)
        XCTAssertTrue(report.contains(.unsupportedPlatform))
        #endif
    }

    // MARK: - Detection through the Swift API

    func testACustomIndicatorIsReported() async throws {
        let marker = scratch.appendingPathComponent("Cydia.app")
        try Data("x".utf8).write(to: marker)

        var configuration = isolatedConfiguration()
        configuration.additionalSuspiciousPaths = [marker.path]
        let report = await SecurityEngine(configuration: configuration).evaluate(checks: [.jailbreak])

        XCTAssertTrue(report.contains(.jailbreakArtifact))
        XCTAssertTrue(report.isCompromised)
        XCTAssertEqual(report.performedChecks, [.jailbreak])
        XCTAssertEqual(report.threats.first?.category, .jailbreak)
        XCTAssertEqual(report.threats.first?.identifier, "jailbreak.artifact")
        XCTAssertTrue(report.threats.first?.detail?.contains(marker.path) == true)
    }

    func testNoIndicatorMeansACleanReport() async {
        var configuration = isolatedConfiguration()
        configuration.additionalSuspiciousPaths = [scratch.appendingPathComponent("absent").path]
        let report = await SecurityEngine(configuration: configuration).evaluate(checks: [.jailbreak])

        XCTAssertTrue(report.threats.isEmpty)
        XCTAssertFalse(report.isCompromised)
        XCTAssertFalse(report.wasSkipped)
    }

    func testTheCheckOverrideRestrictsWhatRuns() async throws {
        let marker = scratch.appendingPathComponent("marker")
        try Data("x".utf8).write(to: marker)
        var configuration = isolatedConfiguration()
        configuration.additionalSuspiciousPaths = [marker.path]

        let report = await SecurityEngine(configuration: configuration).evaluate(checks: [.hooking])
        XCTAssertEqual(report.performedChecks, [.hooking])
        XCTAssertFalse(report.contains(.jailbreakArtifact), "jailbreak checks were not requested")
    }

    func testTheNetworkFamilyIsReachableFromSwift() async {
        let report = await SecurityEngine(configuration: isolatedConfiguration()).evaluate(checks: [.network])
        XCTAssertEqual(report.performedChecks, [.network])
        XCTAssertTrue(report.threats.allSatisfy { $0.category == .network && $0.kind == .networkProxy })
        XCTAssertFalse(report.isCompromised, "a proxy alone never marks the device compromised")
    }

    func testCustomSuspiciousClassesAreReportedAsABypassTool() async {
        var configuration = isolatedConfiguration()
        configuration.additionalSuspiciousClasses = ["NSObject"]
        let report = await SecurityEngine(configuration: configuration).evaluate(checks: [.jailbreak])
        XCTAssertTrue(report.contains(.jailbreakBypassTool))
        XCTAssertEqual(report.threats(in: .jailbreak).first?.identifier, "jailbreak.bypass_tool")
    }

    func testImageDigestsCanBeComputedAndEnforced() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let missing = await engine.textSegmentDigest(ofImageNamed: "NoSuchLibrary.framework/NoSuchLibrary")
        XCTAssertNil(missing)

        var configuration = isolatedConfiguration()
        configuration.expectedImageTextDigests = ["NoSuchLibrary.framework/NoSuchLibrary": ["00"]]
        let report = await SecurityEngine(configuration: configuration).evaluate(checks: [.integrity])
        XCTAssertTrue(report.contains(.integrityImageUnavailable))
        XCTAssertFalse(report.isCompromised)
    }

    func testIntegrityExpectationsAreEnforced() async {
        var configuration = isolatedConfiguration()
        configuration.expectedBundleIdentifier = "com.definitely.not.this.app"
        let report = await SecurityEngine(configuration: configuration).evaluate(checks: [.integrity])
        XCTAssertTrue(report.contains(.integrityBundleIdentifierMismatch))
        XCTAssertEqual(report.highestSeverity, .critical)
    }

    func testProtectedMethodsAreEnforced() async {
        var configuration = isolatedConfiguration()
        configuration.protectedMethods = [
            .init(className: "NSObject", selector: "description", allowedImagePathPrefixes: ["/nonexistent/"]),
        ]
        let report = await SecurityEngine(configuration: configuration).evaluate(checks: [.hooking])
        XCTAssertTrue(report.contains(.hookSwizzledMethod))
    }

    // MARK: - Configuration

    func testConfigurationChangesApplyToTheNextEvaluation() async throws {
        let marker = scratch.appendingPathComponent("marker")
        try Data("x".utf8).write(to: marker)

        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let before = await engine.evaluate(checks: [.jailbreak])
        XCTAssertTrue(before.threats.isEmpty)

        var changed = isolatedConfiguration()
        changed.additionalSuspiciousPaths = [marker.path]
        engine.configure(changed)
        XCTAssertEqual(engine.configuration.additionalSuspiciousPaths, [marker.path])

        let after = await engine.evaluate(checks: [.jailbreak])
        XCTAssertTrue(after.contains(.jailbreakArtifact))
    }

    func testAnEvaluationKeepsTheConfigurationItStartedWith() async throws {
        let marker = scratch.appendingPathComponent("marker")
        try Data("x".utf8).write(to: marker)
        var withMarker = isolatedConfiguration()
        withMarker.additionalSuspiciousPaths = [marker.path]

        let engine = SecurityEngine(configuration: withMarker)
        let finished = expectation(description: "completion")
        let report = Locked<SecurityReport?>(nil)
        engine.evaluate(checks: [.jailbreak]) { result in
            report.value = result
            finished.fulfill()
        }
        engine.configure(isolatedConfiguration()) // changed right after the call returned
        await fulfillment(of: [finished], timeout: 10)

        XCTAssertEqual(report.value?.contains(.jailbreakArtifact), true)
    }

    // MARK: - Threading

    func testTheCompletionHandlerRunsOffTheMainThread() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let finished = expectation(description: "completion")
        let ranOnMain = Locked<Bool?>(nil)
        engine.evaluate { _ in
            ranOnMain.value = Thread.isMainThread
            finished.fulfill()
        }
        await fulfillment(of: [finished], timeout: 10)
        XCTAssertEqual(ranOnMain.value, false)
    }

    func testEvaluateReturnsBeforeTheWorkRuns() {
        // The queue is held busy by a completion that blocks; if `evaluate` did its work on the calling
        // thread it could never return while that completion is still waiting for the gate.
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let gate = DispatchSemaphore(value: 0)
        let firstFinished = expectation(description: "first completion")
        let secondFinished = expectation(description: "second completion")

        engine.evaluate { _ in
            _ = gate.wait(timeout: .now() + 10)
            firstFinished.fulfill()
        }
        let started = Date()
        engine.evaluate { _ in secondFinished.fulfill() }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1, "evaluate must not wait for earlier work")

        gate.signal()
        wait(for: [firstFinished, secondFinished], timeout: 10)
    }

    func testAsyncEvaluationFromTheMainActorDoesNotBlockIt() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let report = await MainActor.run { () -> Task<SecurityReport, Never> in
            Task { await engine.evaluate() }
        }.value
        XCTAssertFalse(report.threats.contains { $0.severity == .critical })
    }

    func testManyConcurrentEvaluationsAreSafe() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let reports = await withTaskGroup(of: SecurityReport.self, returning: [SecurityReport].self) { group in
            for _ in 0..<40 {
                group.addTask { await engine.evaluate() }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        XCTAssertEqual(reports.count, 40)
    }

    func testConfiguringWhileEvaluatingIsSafe() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        await withTaskGroup(of: Void.self) { group in
            for index in 0..<30 {
                group.addTask {
                    if index.isMultiple(of: 3) {
                        engine.configure(self.isolatedConfiguration())
                    } else {
                        _ = await engine.evaluate()
                    }
                }
            }
        }
    }

    // MARK: - Monitoring and publishing

    func testMonitoringReportsImmediatelyThenPeriodically() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let started = Date()
        var count = 0
        for await report in engine.monitor(interval: 1, checks: [.debugger]) {
            XCTAssertEqual(report.performedChecks, [.debugger])
            count += 1
            if count == 2 { break }
        }
        XCTAssertEqual(count, 2)
        XCTAssertLessThan(Date().timeIntervalSince(started), 8)
    }

    func testMonitoringStopsWhenTheConsumerIsCancelled() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let task = Task { () -> Int in
            var count = 0
            for await _ in engine.monitor(interval: 1, checks: [.debugger]) {
                count += 1
            }
            return count
        }
        try? await Task.sleep(nanoseconds: 1_500_000_000)
        task.cancel()
        let count = await task.value // returns only if cancelling ends the stream
        XCTAssertGreaterThanOrEqual(count, 1)
    }

    func testAnImplausiblyShortIntervalIsClamped() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        var times: [Date] = []
        for await _ in engine.monitor(interval: 0.001, checks: [.debugger]) {
            times.append(Date())
            if times.count == 2 { break }
        }
        XCTAssertGreaterThan(times[1].timeIntervalSince(times[0]), 0.9, "intervals below one second are raised to one")
    }

    func testThePublisherReceivesEveryReport() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let received = Locked<[SecurityReport]>([])
        let cancellable = engine.reports.sink { report in
            received.withLock { $0.append(report) }
        }
        _ = await engine.evaluate()
        _ = await engine.evaluate(checks: [.debugger])
        cancellable.cancel()
        _ = await engine.evaluate()

        XCTAssertEqual(received.value.count, 2, "reports after cancelling must not be delivered")
    }

    // MARK: - Raw signals and utilities

    func testIntegritySignalsCanBeCollected() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let without = await engine.integritySignals()
        XCTAssertNil(without.textSegmentDigest)

        let with = await engine.integritySignals(includingTextDigest: true)
        XCTAssertEqual(with.textSegmentDigest?.count, 64)
        XCTAssertEqual(with.bundleIdentifier, Bundle.main.bundleIdentifier)
    }

    func testIntegritySignalsAreCodable() async throws {
        let signals = await SecurityEngine().integritySignals()
        let decoded = try JSONDecoder().decode(IntegritySignals.self, from: JSONEncoder().encode(signals))
        XCTAssertEqual(decoded, signals)
    }

    func testTheSharedEngineIsASingleton() {
        XCTAssertTrue(SecurityEngine.shared === SecurityEngine.shared)
    }

    func testVersionLooksLikeSemver() {
        XCTAssertNotNil(SecurityEngine.version.range(of: #"^\d+\.\d+\.\d+$"#, options: .regularExpression))
    }
}

/// `true` on a physical iPhone or iPad, where evaluations are not skipped.
private var isRunningOnSupportedDevice: Bool {
    #if os(iOS) && !targetEnvironment(simulator) && !targetEnvironment(macCatalyst)
    return !ProcessInfo.processInfo.isiOSAppOnMac
    #else
    return false
    #endif
}
