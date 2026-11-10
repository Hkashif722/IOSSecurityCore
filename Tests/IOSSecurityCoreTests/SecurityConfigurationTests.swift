import IOSSecurityCoreObjC
import XCTest
@testable import IOSSecurityCore

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
        XCTAssertEqual(swift.additionalSuspiciousLibraries, objc.additionalSuspiciousLibraries)
        XCTAssertEqual(swift.allowedImagePathPrefixes, objc.allowedImagePathPrefixes)
        XCTAssertEqual(swift.reportsUnknownLibraries, objc.reportsUnknownLibraries)
        XCTAssertEqual(swift.allowedBundleLibraries, objc.allowedBundleLibraries)
        XCTAssertEqual(swift.probesInstrumentationPorts, objc.probesInstrumentationPorts)
        XCTAssertEqual(swift.protectedMethods.count, objc.protectedMethods.count)
        XCTAssertEqual(swift.expectedBundleIdentifier, objc.expectedBundleIdentifier)
        XCTAssertEqual(swift.expectedTeamIdentifier, objc.expectedTeamIdentifier)
        XCTAssertEqual(swift.expectedTextSegmentDigests, objc.expectedTextSegmentDigests)
        XCTAssertEqual(swift.expectedDistribution, objc.expectedDistribution)
    }

    func testEveryPropertyIsForwarded() {
        var configuration = SecurityConfiguration()
        configuration.checks = [.jailbreak, .integrity]
        configuration.includesBuiltInIndicators = false
        configuration.scansUnsupportedEnvironments = true
        configuration.additionalSuspiciousPaths = ["/a", "/b"]
        configuration.performsSandboxWriteProbe = false
        configuration.performsForkProbe = false
        configuration.additionalSuspiciousLibraries = ["evil"]
        configuration.allowedImagePathPrefixes = ["/opt/"]
        configuration.reportsUnknownLibraries = false
        configuration.allowedBundleLibraries = ["Auth.framework/Auth"]
        configuration.probesInstrumentationPorts = false
        configuration.protectedMethods = [
            .init(className: "Auth", selector: "isLoggedIn", scope: .instance, allowedImagePathPrefixes: ["/app/"]),
            .init(className: "Crypto", selector: "key", scope: .class),
        ]
        configuration.expectedBundleIdentifier = "com.example.app"
        configuration.expectedTeamIdentifier = "ABCDE12345"
        configuration.expectedTextSegmentDigests = ["bb", "aa"]
        configuration.expectedDistribution = .appStore

        let options = configuration.makeScanOptions()
        XCTAssertEqual(options.checks, [.jailbreak, .integrity])
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

    func testSecurityConfigurationIsSendable() {
        // Compile-time check: handing a configuration to another task must not need `@unchecked`.
        let configuration = SecurityConfiguration()
        let box: @Sendable () -> Int = { configuration.additionalSuspiciousPaths.count }
        XCTAssertEqual(box(), 0)
    }
}
