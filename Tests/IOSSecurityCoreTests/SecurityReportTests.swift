//
//  SecurityReportTests.swift
//  IOSSecurityCoreTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import XCTest
@testable import IOSSecurityCore

final class SecurityReportTests: XCTestCase {

    private func threat(
        _ kind: SecurityThreat.Kind,
        _ category: SecurityThreat.Category,
        _ severity: SecurityThreat.Severity,
        detail: String? = nil
    ) -> SecurityThreat {
        SecurityThreat(kind: kind, category: category, severity: severity, identifier: "test.\(kind.rawValue)", detail: detail)
    }

    private func report(
        _ threats: [SecurityThreat],
        performed: Set<SecurityCheck> = Set(SecurityCheck.allCases)
    ) -> SecurityReport {
        SecurityReport(threats: threats, performedChecks: performed, startedAt: Date(timeIntervalSince1970: 1_000), duration: 0.01)
    }

    func testAnEmptyReportIsNotCompromised() {
        let empty = report([])
        XCTAssertFalse(empty.isCompromised)
        XCTAssertNil(empty.highestSeverity)
        XCTAssertFalse(empty.wasSkipped)
    }

    func testOnlyHighAndCriticalThreatsCompromise() {
        for severity in SecurityThreat.Severity.allCases {
            let single = report([threat(.jailbreakArtifact, .jailbreak, severity)])
            XCTAssertEqual(single.isCompromised, severity >= .high, "\(severity)")
        }
    }

    func testManyWeakSignalsDoNotAddUpToACompromise() {
        let weak = (0..<20).map { threat(SecurityThreat.Kind(rawValue: 9_000 + $0), .hooking, .medium) }
        XCTAssertFalse(report(weak).isCompromised, "heuristics alone must never lock a user out")
    }

    func testHighestSeverityPicksTheWorst() {
        let mixed = report([
            threat(.hookUnknownLibrary, .hooking, .medium),
            threat(.integrityTextSegmentModified, .integrity, .critical),
            threat(.debuggerAttached, .debugger, .high),
        ])
        XCTAssertEqual(mixed.highestSeverity, .critical)
    }

    func testAReportWithNoPerformedChecksWasSkipped() {
        let skipped = report([threat(.simulator, .environment, .info)], performed: [])
        XCTAssertTrue(skipped.wasSkipped)
        XCTAssertFalse(skipped.isCompromised)
    }

    func testFilteringByCategoryAndKind() {
        let mixed = report([
            threat(.jailbreakArtifact, .jailbreak, .high),
            threat(.jailbreakForkAllowed, .jailbreak, .high),
            threat(.debuggerAttached, .debugger, .high),
        ])
        XCTAssertEqual(mixed.threats(in: .jailbreak).count, 2)
        XCTAssertEqual(mixed.threats(in: .debugger).count, 1)
        XCTAssertTrue(mixed.threats(in: .integrity).isEmpty)
        XCTAssertTrue(mixed.contains(.debuggerAttached))
        XCTAssertFalse(mixed.contains(.hookSwizzledMethod))
    }

    func testSeveritiesAreOrdered() {
        XCTAssertLessThan(SecurityThreat.Severity.info, .low)
        XCTAssertLessThan(SecurityThreat.Severity.low, .medium)
        XCTAssertLessThan(SecurityThreat.Severity.medium, .high)
        XCTAssertLessThan(SecurityThreat.Severity.high, .critical)
        XCTAssertEqual(SecurityThreat.Severity.allCases.sorted(), SecurityThreat.Severity.allCases)
    }

    func testReportsSurviveAJSONRoundTrip() throws {
        let original = report(
            [
                threat(.jailbreakArtifact, .jailbreak, .high, detail: "/var/jb"),
                threat(.integrityTeamIdentifierMismatch, .integrity, .critical),
            ],
            performed: [.jailbreak, .integrity]
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SecurityReport.self, from: data)
        XCTAssertEqual(decoded, original)
        XCTAssertEqual(decoded.threats.first?.detail, "/var/jb")
    }

    func testThreatKindsEncodeAsPlainIntegers() throws {
        // A backend must be able to read the wire format without knowing Swift.
        let data = try JSONEncoder().encode(SecurityThreat.Kind.debuggerAttached)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "300")
    }

    func testThreatDescriptionMentionsIdentifierSeverityAndDetail() {
        let described = threat(.jailbreakArtifact, .jailbreak, .high, detail: "/var/jb").description
        XCTAssertTrue(described.contains("test.200"))
        XCTAssertTrue(described.contains("high"))
        XCTAssertTrue(described.contains("/var/jb"))
    }
}
