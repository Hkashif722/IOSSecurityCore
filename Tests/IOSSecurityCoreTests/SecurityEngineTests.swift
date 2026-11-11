//
//  SecurityEngineTests.swift
//  IOSSecurityCoreTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import IOSSecurityCoreObjC
import ObjectiveC
import XCTest
@_spi(Testing) @testable import IOSSecurityCore

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
        configuration.jailbreak.performsSandboxWriteProbe = false
        configuration.jailbreak.performsForkProbe = false
        configuration.jailbreak.probesRemoteShellPorts = false
        configuration.hooking.probesInstrumentationPorts = false
        configuration.hooking.reportsUnknownLibraries = false
        return configuration
    }

    // MARK: - Platform gating

    func testUnsupportedEnvironmentsAreSkippedNotFlagged() async throws {
        try XCTSkipIf(isRunningOnSupportedDevice, "On a real device the checks run for real.")
        let report = try await SecurityEngine().evaluate()

        XCTAssertTrue(report.wasSkipped)
        XCTAssertNotNil(report.skipReason)
        XCTAssertFalse(report.isCompromised, "a Simulator or Mac must never look compromised")
        XCTAssertEqual(report.threats.count, 1)
        XCTAssertEqual(report.threats.first?.category, .environment)
        XCTAssertEqual(report.threats.first?.severity, .info)
        #if targetEnvironment(simulator)
        XCTAssertEqual(report.skipReason, .simulator)
        XCTAssertTrue(report.contains(.simulator))
        #elseif os(macOS)
        XCTAssertEqual(report.skipReason, .unsupportedPlatform)
        XCTAssertTrue(report.contains(.unsupportedPlatform))
        #endif
    }

    func testRequestingNoChecksIsNotASkip() async throws {
        let report = try await SecurityEngine(configuration: isolatedConfiguration()).evaluate(checks: [])
        XCTAssertTrue(report.performedChecks.isEmpty)
        XCTAssertFalse(report.wasSkipped, "nothing ran, but not because of the platform")
        XCTAssertNil(report.skipReason)
    }

    // MARK: - Detection through the Swift API

    func testACustomIndicatorIsReported() async throws {
        let marker = scratch.appendingPathComponent("Cydia.app")
        try Data("x".utf8).write(to: marker)

        var configuration = isolatedConfiguration()
        configuration.jailbreak.additionalSuspiciousPaths = [marker.path]
        let report = try await SecurityEngine(configuration: configuration).evaluate(checks: [.jailbreak])

        XCTAssertTrue(report.contains(.jailbreakArtifact))
        XCTAssertTrue(report.isCompromised)
        XCTAssertEqual(report.performedChecks, [.jailbreak])
        XCTAssertEqual(report.threats.first?.category, .jailbreak)
        XCTAssertEqual(report.threats.first?.identifier, "jailbreak.artifact")
        XCTAssertTrue(report.threats.first?.detail?.contains(marker.path) == true)
    }

    func testNoIndicatorMeansACleanReport() async throws {
        var configuration = isolatedConfiguration()
        configuration.jailbreak.additionalSuspiciousPaths = [scratch.appendingPathComponent("absent").path]
        let report = try await SecurityEngine(configuration: configuration).evaluate(checks: [.jailbreak])

        XCTAssertTrue(report.threats.isEmpty)
        XCTAssertFalse(report.isCompromised)
        XCTAssertFalse(report.wasSkipped)
    }

    func testTheCheckOverrideRestrictsWhatRuns() async throws {
        let marker = scratch.appendingPathComponent("marker")
        try Data("x".utf8).write(to: marker)
        var configuration = isolatedConfiguration()
        configuration.jailbreak.additionalSuspiciousPaths = [marker.path]

        let report = try await SecurityEngine(configuration: configuration).evaluate(checks: [.hooking])
        XCTAssertEqual(report.performedChecks, [.hooking])
        XCTAssertFalse(report.contains(.jailbreakArtifact), "jailbreak checks were not requested")
    }

    func testTheNetworkFamilyIsReachableFromSwift() async throws {
        let report = try await SecurityEngine(configuration: isolatedConfiguration()).evaluate(checks: [.network])
        XCTAssertEqual(report.performedChecks, [.network])
        XCTAssertTrue(report.threats.allSatisfy { $0.category == .network && $0.kind == .networkProxy })
        XCTAssertFalse(report.isCompromised, "a proxy alone never marks the device compromised")
    }

    func testCustomSuspiciousClassesAreReportedAsABypassTool() async throws {
        var configuration = isolatedConfiguration()
        configuration.jailbreak.additionalSuspiciousClasses = ["NSObject"]
        let report = try await SecurityEngine(configuration: configuration).evaluate(checks: [.jailbreak])
        XCTAssertTrue(report.contains(.jailbreakBypassTool))
        XCTAssertEqual(report.threats(in: .jailbreak).first?.identifier, "jailbreak.bypass_tool")
    }

    func testImageDigestsCanBeComputedAndEnforced() async throws {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let missing = await engine.textSegmentDigest(ofImageNamed: "NoSuchLibrary.framework/NoSuchLibrary")
        XCTAssertNil(missing)

        var configuration = isolatedConfiguration()
        configuration.integrity.expectedImageTextDigests = ["NoSuchLibrary.framework/NoSuchLibrary": ["00"]]
        let report = try await SecurityEngine(configuration: configuration).evaluate(checks: [.integrity])
        XCTAssertTrue(report.contains(.integrityImageUnavailable))
        XCTAssertFalse(report.isCompromised)
    }

    func testIntegrityExpectationsAreEnforced() async throws {
        var configuration = isolatedConfiguration()
        configuration.integrity.expectedBundleIdentifier = "com.definitely.not.this.app"
        let report = try await SecurityEngine(configuration: configuration).evaluate(checks: [.integrity])
        XCTAssertTrue(report.contains(.integrityBundleIdentifierMismatch))
        XCTAssertEqual(report.highestSeverity, .critical)
    }

    func testProtectedMethodsAreEnforced() async throws {
        var configuration = isolatedConfiguration()
        configuration.hooking.protectedMethods = [
            .init(className: "NSObject", selector: "description", allowedImagePathPrefixes: ["/nonexistent/"]),
        ]
        let report = try await SecurityEngine(configuration: configuration).evaluate(checks: [.hooking])
        XCTAssertTrue(report.contains(.hookSwizzledMethod))
    }

    // MARK: - Configuration

    func testConfigurationChangesApplyToTheNextEvaluation() async throws {
        let marker = scratch.appendingPathComponent("marker")
        try Data("x".utf8).write(to: marker)

        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let before = try await engine.evaluate(checks: [.jailbreak])
        XCTAssertTrue(before.threats.isEmpty)

        var changed = isolatedConfiguration()
        changed.jailbreak.additionalSuspiciousPaths = [marker.path]
        engine.configuration = changed
        XCTAssertEqual(engine.configuration.jailbreak.additionalSuspiciousPaths, [marker.path])

        let after = try await engine.evaluate(checks: [.jailbreak])
        XCTAssertTrue(after.contains(.jailbreakArtifact))
    }

    func testAnEvaluationKeepsTheConfigurationItStartedWith() async throws {
        let marker = scratch.appendingPathComponent("marker")
        try Data("x".utf8).write(to: marker)
        var withMarker = isolatedConfiguration()
        withMarker.jailbreak.additionalSuspiciousPaths = [marker.path]

        let engine = SecurityEngine(configuration: withMarker)
        let finished = expectation(description: "completion")
        let report = Locked<SecurityReport?>(nil)
        engine.evaluate(checks: [.jailbreak]) { result in
            report.value = result
            finished.fulfill()
        }
        engine.configuration = isolatedConfiguration() // changed right after the call returned
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

    func testAsyncEvaluationFromTheMainActorDoesNotBlockIt() async throws {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let report = try await MainActor.run { () -> Task<SecurityReport, Error> in
            Task { try await engine.evaluate() }
        }.value
        XCTAssertFalse(report.threats.contains { $0.severity == .critical })
    }

    func testManyConcurrentEvaluationsAreSafe() async throws {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let reports = try await withThrowingTaskGroup(of: SecurityReport.self, returning: [SecurityReport].self) { group in
            for _ in 0..<40 {
                group.addTask { try await engine.evaluate() }
            }
            return try await group.reduce(into: []) { $0.append($1) }
        }
        XCTAssertEqual(reports.count, 40)
    }

    func testConfiguringWhileEvaluatingIsSafe() async {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let replacement = isolatedConfiguration()
        await withTaskGroup(of: Void.self) { group in
            for index in 0..<30 {
                group.addTask {
                    if index.isMultiple(of: 3) {
                        engine.configuration = replacement
                    } else {
                        _ = try? await engine.evaluate()
                    }
                }
            }
        }
    }

    func testTheEngineIsSendable() {
        // Compile-time check: the engine crosses isolation boundaries without `@unchecked`.
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let box: @Sendable () -> SecurityEngine = { engine }
        XCTAssertTrue(box() === engine)
    }

    // MARK: - Monitoring and observing

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

    func testTheReportSequenceDeliversEveryReportWhileItIsIterated() async throws {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        XCTAssertEqual(engine.reportSubscriberCount, 0)

        // Making the iterator is what subscribes, so the two evaluations below are delivered to it.
        var iterator: SecurityEngine.Reports.AsyncIterator? = engine.reports.makeAsyncIterator()
        XCTAssertEqual(engine.reportSubscriberCount, 1)

        let first = try await engine.evaluate()
        let second = try await engine.evaluate(checks: [.debugger])
        let receivedFirst = await iterator?.next()
        let receivedSecond = await iterator?.next()
        XCTAssertEqual(receivedFirst, first)
        XCTAssertEqual(receivedSecond, second)

        iterator = nil
        // Cancelling the consumer is the documented way out; dropping the iterator also unsubscribes on
        // current toolchains, which this pins so a change in AsyncStream's teardown is noticed.
        XCTAssertEqual(engine.reportSubscriberCount, 0, "dropping the iterator unsubscribes")
        _ = try await engine.evaluate()
    }

    func testTheReportSequenceEndsWhenTheEngineIsDeallocated() async {
        var engine: SecurityEngine? = SecurityEngine(configuration: isolatedConfiguration())
        var iterator = engine!.reports.makeAsyncIterator()
        XCTAssertEqual(engine!.reportSubscriberCount, 1)

        engine = nil
        let next = await iterator.next() // returns only if deallocation ends the sequence
        XCTAssertNil(next, "a consumer must not wait forever for an engine that is gone")
    }

    func testEveryIterationOfReportsIsItsOwnSubscription() async throws {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let reports = engine.reports
        var one: SecurityEngine.Reports.AsyncIterator? = reports.makeAsyncIterator()
        var two: SecurityEngine.Reports.AsyncIterator? = reports.makeAsyncIterator()
        XCTAssertEqual(engine.reportSubscriberCount, 2)

        let report = try await engine.evaluate()
        let fromOne = await one?.next()
        let fromTwo = await two?.next()
        XCTAssertEqual(fromOne, report)
        XCTAssertEqual(fromTwo, report)

        one = nil
        two = nil
        XCTAssertEqual(engine.reportSubscriberCount, 0)
    }

    func testCancellingAReportConsumerEndsItsSubscription() async throws {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let subscribed = expectation(description: "subscribed")
        let consumer = Task {
            var count = 0
            for await _ in engine.reports {
                count += 1
            }
            return count
        }
        // The subscription exists once the loop has asked for its first element.
        Task {
            while engine.reportSubscriberCount == 0 {
                try? await Task.sleep(nanoseconds: 10_000_000)
            }
            subscribed.fulfill()
        }
        await fulfillment(of: [subscribed], timeout: 10)

        _ = try await engine.evaluate()
        consumer.cancel()
        _ = await consumer.value // returns only if cancelling ends the sequence
        XCTAssertEqual(engine.reportSubscriberCount, 0)
    }

    // MARK: - Cancellation

    func testAnAlreadyCancelledTaskDoesNotScan() async throws {
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await engine.evaluate()
        }
        do {
            _ = try await task.value
            XCTFail("a cancelled evaluation must not return a report")
        } catch {
            XCTAssertTrue(error is CancellationError, "\(error)")
        }
    }

    func testCancellingWhileQueuedSkipsTheScan() async throws {
        // Hold the engine's queue with a completion that waits on a gate, queue an evaluation behind it,
        // cancel that evaluation, then open the gate: the queued scan must not run.
        let engine = SecurityEngine(configuration: isolatedConfiguration())
        let gate = DispatchSemaphore(value: 0)
        let holding = expectation(description: "queue held")
        engine.evaluate { _ in
            holding.fulfill()
            _ = gate.wait(timeout: .now() + 10)
        }
        await fulfillment(of: [holding], timeout: 10)

        var reports = engine.reports.makeAsyncIterator()
        let queued = Task { try await engine.evaluate() }
        try await Task.sleep(nanoseconds: 50_000_000) // let it reach the queue
        queued.cancel()
        gate.signal()

        do {
            _ = try await queued.value
            XCTFail("the queued evaluation must not have run")
        } catch {
            XCTAssertTrue(error is CancellationError, "\(error)")
        }

        // The only report produced after subscribing is from an evaluation started now, not the cancelled one.
        let marker = try await engine.evaluate(checks: [.network])
        let next = await reports.next()
        XCTAssertEqual(next, marker, "the cancelled evaluation published a report")
    }

    // MARK: - Verifying the Objective-C result

    private func report(skip: SecurityReport.SkipReason?, performed: Set<SecurityCheck>) -> SecurityReport {
        SecurityReport(threats: [], performedChecks: performed, startedAt: Date(timeIntervalSince1970: 1_000),
                       duration: 0, exactSkipReason: skip)
    }

    func testAConsistentResultIsLeftAlone() {
        let ran = report(skip: nil, performed: [.jailbreak, .debugger])
        XCTAssertEqual(ran.verified(requested: [.jailbreak, .debugger], scansUnsupportedEnvironments: true), ran)

        let skipped = report(skip: SecurityReport.SkipReason.expectedForThisProcess, performed: [])
        XCTAssertEqual(skipped.verified(requested: [.jailbreak], scansUnsupportedEnvironments: false), skipped)
    }

    func testAFamilyThatSilentlyDidNotRunIsTampering() {
        let verified = report(skip: nil, performed: [.jailbreak])
            .verified(requested: [.jailbreak, .hooking], scansUnsupportedEnvironments: true)
        XCTAssertTrue(verified.contains(.hookSelfIntegrity))
        XCTAssertTrue(verified.isCompromised)
        XCTAssertEqual(verified.threats.first?.detail, "performed jailbreak, requested hooking+jailbreak")
    }

    func testAForgedSkipIsTamperingAndNoLongerASkip() {
        // Wherever this runs, `.simulator` is wrong for one of the two settings; pick the one where it is.
        let forged: SecurityReport.SkipReason =
            SecurityReport.SkipReason.expectedForThisProcess == .simulator ? .macRuntime : .simulator
        let verified = report(skip: forged, performed: []).verified(requested: [.jailbreak], scansUnsupportedEnvironments: false)
        XCTAssertTrue(verified.contains(.hookSelfIntegrity))
        XCTAssertFalse(verified.wasSkipped, "a skip the platform does not explain must not hide the report")

        // Forcing the checks to run means no skip is expected at all.
        let skippedAnyway = report(skip: .simulator, performed: []).verified(requested: [.jailbreak], scansUnsupportedEnvironments: true)
        XCTAssertTrue(skippedAnyway.contains(.hookSelfIntegrity))
    }

    func testASwizzledOptionsGetterIsCaughtByTheEngine() async throws {
        // A tweak makes every family look disabled. The Objective-C result is then empty and consistent with
        // itself; only the Swift layer knows which families it asked for.
        let method = try XCTUnwrap(class_getInstanceMethod(ISCScanOptions.self, #selector(getter: ISCScanOptions.checks)))
        let original = method_getImplementation(method)
        let none: @convention(block) (AnyObject) -> UInt = { _ in 0 }
        let lie = imp_implementationWithBlock(none)
        method_setImplementation(method, lie)
        defer {
            method_setImplementation(method, original)
            imp_removeBlock(lie)
        }

        let report = try await SecurityEngine(configuration: isolatedConfiguration()).evaluate(checks: [.jailbreak, .debugger])
        XCTAssertTrue(report.performedChecks.isEmpty)
        XCTAssertTrue(report.contains(.hookSelfIntegrity))
        XCTAssertTrue(report.isCompromised)
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
