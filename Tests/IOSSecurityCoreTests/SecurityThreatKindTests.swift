import IOSSecurityCoreObjC
import XCTest
@testable import IOSSecurityCore

/// The numeric values of `SecurityThreat.Kind` are persisted by backends, so they are API.
final class SecurityThreatKindTests: XCTestCase {

    func testRawValuesAreStable() {
        let expected: [(SecurityThreat.Kind, Int)] = [
            (.simulator, 100), (.unsupportedPlatform, 101), (.macRuntime, 102),
            (.jailbreakArtifact, 200), (.jailbreakSymlink, 201), (.jailbreakSandboxEscape, 202),
            (.jailbreakForkAllowed, 203), (.jailbreakInjectedLibrary, 204), (.jailbreakInjectionEnvironment, 205),
            (.jailbreakBypassTool, 206), (.jailbreakRemoteShellPort, 207),
            (.debuggerAttached, 300), (.debuggerHardwareBreakpoint, 301), (.debuggerUnexpectedParent, 302),
            (.hookInstrumentationLibrary, 400), (.hookInstrumentationPort, 401), (.hookInstrumentationThread, 402),
            (.hookInstrumentationArtifact, 403), (.hookUnknownLibrary, 404), (.hookSwizzledMethod, 405),
            (.hookProtectedMethodUnresolved, 406), (.hookSelfIntegrity, 407), (.hookUnexpectedBundleLibrary, 408),
            (.hookInlinePatchedFunction, 409), (.hookReboundSymbol, 410),
            (.integrityBundleIdentifierMismatch, 500), (.integrityTeamIdentifierMismatch, 501),
            (.integrityBinaryDecrypted, 502), (.integrityTextSegmentModified, 503), (.integrityDebuggableBuild, 504),
            (.integrityUnexpectedProvisioningProfile, 505), (.integrityTeamIdentifierUnavailable, 506),
            (.integrityTextSegmentUnavailable, 507), (.integrityImageModified, 508), (.integrityImageUnavailable, 509),
            (.networkProxy, 600),
        ]
        for (kind, rawValue) in expected {
            XCTAssertEqual(kind.rawValue, rawValue)
        }
        XCTAssertEqual(Set(expected.map(\.1)).count, expected.count, "two kinds share a value")
    }

    func testEveryObjectiveCFindingMapsToAThreatWithTheSameCategoryAndSeverity() {
        let codes: [ISCFindingCode] = [
            .simulator, .unsupportedPlatform, .macRuntime,
            .jailbreakArtifact, .jailbreakSymlink, .jailbreakSandboxEscape, .jailbreakForkAllowed,
            .jailbreakInjectedLibrary, .jailbreakInjectionEnvironment, .jailbreakBypassTool,
            .jailbreakRemoteShellPort, .debuggerAttached, .debuggerHardwareBreakpoint, .debuggerUnexpectedParent,
            .hookInstrumentationLibrary, .hookInstrumentationPort, .hookInstrumentationThread,
            .hookInstrumentationArtifact, .hookUnknownLibrary, .hookSwizzledMethod,
            .hookProtectedMethodUnresolved, .hookSelfIntegrity, .hookUnexpectedBundleLibrary,
            .hookInlinePatchedFunction, .hookReboundSymbol,
            .integrityBundleIdentifierMismatch, .integrityTeamIdentifierMismatch, .integrityBinaryDecrypted,
            .integrityTextSegmentModified, .integrityDebuggableBuild, .integrityUnexpectedProvisioningProfile,
            .integrityTeamIdentifierUnavailable, .integrityTextSegmentUnavailable, .integrityImageModified,
            .integrityImageUnavailable, .networkProxy,
        ]
        var identifiers = Set<String>()
        for code in codes {
            let finding = ISCFinding(code: code, detail: "detail")
            let threat = SecurityThreat(finding)

            XCTAssertEqual(threat.kind.rawValue, code.rawValue)
            XCTAssertEqual(threat.severity.rawValue, finding.severity.rawValue, "\(code)")
            XCTAssertEqual(threat.detail, "detail")
            XCTAssertTrue(identifiers.insert(threat.identifier).inserted, "duplicate identifier \(threat.identifier)")
            XCTAssertTrue(
                threat.identifier.hasPrefix(threat.category.rawValue + "."),
                "\(threat.identifier) is not under \(threat.category)"
            )
        }
    }

    func testUnknownKindsRoundTripSoANewerBackendValueDoesNotBreakDecoding() throws {
        let future = SecurityThreat.Kind(rawValue: 9_999)
        let data = try JSONEncoder().encode(future)
        XCTAssertEqual(try JSONDecoder().decode(SecurityThreat.Kind.self, from: data), future)
    }
}
