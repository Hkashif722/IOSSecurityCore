//
//  SecurityReport.swift
//  IOSSecurityCore
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import Foundation

/// The outcome of one evaluation.
public struct SecurityReport: Hashable, Sendable, Codable {

    /// Everything that was found, most severe first.
    public let threats: [SecurityThreat]

    /// The check families that actually ran. Empty when the environment is unsupported (Simulator, Mac).
    public let performedChecks: Set<SecurityCheck>

    /// When the evaluation started.
    public let startedAt: Date

    /// How long the evaluation took, in seconds.
    public let duration: TimeInterval

    public init(
        threats: [SecurityThreat],
        performedChecks: Set<SecurityCheck>,
        startedAt: Date,
        duration: TimeInterval
    ) {
        self.threats = threats
        self.performedChecks = performedChecks
        self.startedAt = startedAt
        self.duration = duration
    }

    /// `true` when at least one threat is ``SecurityThreat/Severity/high`` or worse: the runtime
    /// environment cannot be trusted.
    public var isCompromised: Bool {
        threats.contains { $0.severity >= .high }
    }

    /// The most severe threat, or `nil` when nothing was found.
    public var highestSeverity: SecurityThreat.Severity? {
        threats.map(\.severity).max()
    }

    /// `true` when the evaluation was skipped because the environment is unsupported, so an empty
    /// ``threats`` list says nothing about the device.
    public var wasSkipped: Bool {
        performedChecks.isEmpty
    }

    /// The threats in one category.
    public func threats(in category: SecurityThreat.Category) -> [SecurityThreat] {
        threats.filter { $0.category == category }
    }

    /// Whether the report contains a threat of the given kind.
    public func contains(_ kind: SecurityThreat.Kind) -> Bool {
        threats.contains { $0.kind == kind }
    }
}
