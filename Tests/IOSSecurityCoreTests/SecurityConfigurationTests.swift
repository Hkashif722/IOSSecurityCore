//
//  SecurityConfigurationTests.swift
//  IOSSecurityCoreTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import IOSSecurityCoreObjC
import XCTest
@_spi(Testing) @testable import IOSSecurityCore

final class SecurityConfigurationTests: XCTestCase {

    func testDefaultsMatchTheObjectiveCDefaults() {
        // The two layers declare their defaults separately; they must never drift apart.
        let swift = SecurityConfiguration().makeScanOptions()
        let objc = ISCScanOptions.default()

        XCTAssertEqual(swift.checks, objc.checks)
        XCTAssertEqual(swift.includesBuiltInIndicators, objc.includesBuiltInIndicators)
        XCTAssertEqual(swift.scansUnsupportedEnvironments, objc.scansUnsupportedEnvironments)
        XCTAssertEqual(swift.additionalSuspiciousPaths, objc.additionalSuspiciousPaths)
        XCTAssertEqual(swift.performsSandboxWriteProbe, objc.performsSandboxWriteProbe)
        XCTAssertEqual(swift.performsForkProbe, objc.performsForkProbe)
        XCTAssertEqual(swift.additionalSuspiciousClasses, objc.additionalSuspiciousClasses)
        XCTAssertEqual(swift.probesRemoteShellPorts, objc.probesRemoteShellPorts)
        XCTAssertEqual(swift.additionalSuspiciousLibraries, objc.additionalSuspiciousLibraries)
        XCTAssertEqual(swift.allowedImagePathPrefixes, objc.allowedImagePathPrefixes)
        XCTAssertEqual(swift.reportsUnknownLibraries, objc.reportsUnknownLibraries)
        XCTAssertEqual(swift.allowedBundleLibraries, objc.allowedBundleLibraries)
        XCTAssertEqual(swift.probesInstrumentationPorts, objc.probesInstrumentationPorts)
        XCTAssertEqual(swift.protectedMethods.count, objc.protectedMethods.count)
        XCTAssertEqual(swift.expectedBundleIdentifier, objc.expectedBundleIdentifier)
        XCTAssertEqual(swift.expectedTeamIdentifier, objc.expectedTeamIdentifier)
        XCTAssertEqual(swift.expectedTextSegmentDigests, objc.expectedTextSegmentDigests)
        XCTAssertEqual(swift.expectedImageTextDigests, objc.expectedImageTextDigests)
        XCTAssertEqual(swift.expectedDistribution, objc.expectedDistribution)
    }

    func testEveryPropertyIsForwarded() {
        var configuration = SecurityConfiguration()
        configuration.checks = [.jailbreak, .integrity]
        configuration.includesBuiltInIndicators = false
        configuration.scansUnsupportedEnvironments = true
        configuration.jailbreak.additionalSuspiciousPaths = ["/a", "/b"]
        configuration.jailbreak.performsSandboxWriteProbe = false
        configuration.jailbreak.performsForkProbe = false
        configuration.jailbreak.additionalSuspiciousClasses = ["HideMe"]
        configuration.jailbreak.probesRemoteShellPorts = false
        configuration.hooking.additionalSuspiciousLibraries = ["evil"]
        configuration.hooking.allowedImagePathPrefixes = ["/opt/"]
        configuration.hooking.reportsUnknownLibraries = false
        configuration.hooking.allowedBundleLibraries = ["Auth.framework/Auth"]
        configuration.hooking.probesInstrumentationPorts = false
        configuration.hooking.protectedMethods = [
            .init(className: "Auth", selector: "isLoggedIn", scope: .instance, allowedImagePathPrefixes: ["/app/"]),
            .init(className: "Crypto", selector: "key", scope: .class),
        ]
        configuration.integrity.expectedBundleIdentifier = "com.example.app"
        configuration.integrity.expectedTeamIdentifier = "ABCDE12345"
        configuration.integrity.expectedTextSegmentDigests = ["bb", "aa"]
        configuration.integrity.expectedImageTextDigests = ["Auth.framework/Auth": ["dd", "cc"]]
        configuration.integrity.expectedDistribution = .appStore

        let options = configuration.makeScanOptions()
        XCTAssertEqual(options.checks, [.jailbreak, .integrity])
        XCTAssertEqual(options.additionalSuspiciousClasses, ["HideMe"])
        XCTAssertFalse(options.probesRemoteShellPorts)
        XCTAssertEqual(options.expectedImageTextDigests, ["Auth.framework/Auth": ["cc", "dd"]],
                       "a Set has no order; the forwarded list must be stable")
        XCTAssertFalse(options.includesBuiltInIndicators)
        XCTAssertTrue(options.scansUnsupportedEnvironments)
        XCTAssertEqual(options.additionalSuspiciousPaths, ["/a", "/b"])
        XCTAssertFalse(options.performsSandboxWriteProbe)
        XCTAssertFalse(options.performsForkProbe)
        XCTAssertEqual(options.additionalSuspiciousLibraries, ["evil"])
        XCTAssertEqual(options.allowedImagePathPrefixes, ["/opt/"])
        XCTAssertFalse(options.reportsUnknownLibraries)
        XCTAssertEqual(options.allowedBundleLibraries, ["Auth.framework/Auth"])
        XCTAssertFalse(options.probesInstrumentationPorts)
        XCTAssertEqual(options.expectedBundleIdentifier, "com.example.app")
        XCTAssertEqual(options.expectedTeamIdentifier, "ABCDE12345")
        XCTAssertEqual(options.expectedTextSegmentDigests, ["aa", "bb"], "a Set has no order; the forwarded list must be stable")
        XCTAssertEqual(options.expectedDistribution, .appStore)

        XCTAssertEqual(options.protectedMethods.count, 2)
        XCTAssertEqual(options.protectedMethods[0].targetClassName, "Auth")
        XCTAssertEqual(options.protectedMethods[0].selectorName, "isLoggedIn")
        XCTAssertFalse(options.protectedMethods[0].isClassMethod)
        XCTAssertEqual(options.protectedMethods[0].allowedImagePathPrefixes, ["/app/"])
        XCTAssertTrue(options.protectedMethods[1].isClassMethod)
    }

    func testTheChecksOverrideReplacesTheConfiguredChecks() {
        var configuration = SecurityConfiguration()
        configuration.checks = [.jailbreak]
        XCTAssertEqual(configuration.makeScanOptions().checks, [.jailbreak])
        XCTAssertEqual(configuration.makeScanOptions(checksOverride: [.debugger, .hooking]).checks, [.debugger, .hooking])
        XCTAssertEqual(configuration.makeScanOptions(checksOverride: []).checks, [])
    }

    func testEachCallBuildsAnIndependentOptionsObject() {
        let configuration = SecurityConfiguration()
        let first = configuration.makeScanOptions()
        let second = configuration.makeScanOptions()
        first.additionalSuspiciousPaths = ["/mutated"]
        XCTAssertTrue(second.additionalSuspiciousPaths.isEmpty, "ISCScanOptions is mutable; scans must not share one")
    }

    func testCheckSetsRoundTripThroughTheObjectiveCOptionSet() {
        for subset in [Set<SecurityCheck>(), [.jailbreak], [.debugger, .integrity], Set(SecurityCheck.allCases)] {
            XCTAssertEqual(Set<SecurityCheck>(objc: subset.objcValue), subset)
        }
    }

    func testFamiliesAreValueTypesWithEquality() {
        var left = SecurityConfiguration()
        var right = left
        XCTAssertEqual(left, right)

        left.integrity.expectedTeamIdentifier = "ABCDE12345"
        XCTAssertNotEqual(left, right, "a change inside one family must change the whole configuration")
        right.integrity = left.integrity
        XCTAssertEqual(left, right, "a family can be copied as one value")
    }

    func testSecurityConfigurationIsSendable() {
        // Compile-time check: handing a configuration to another task must not need `@unchecked`.
        let configuration = SecurityConfiguration()
        let box: @Sendable () -> Int = { configuration.jailbreak.additionalSuspiciousPaths.count }
        XCTAssertEqual(box(), 0)
    }
}
