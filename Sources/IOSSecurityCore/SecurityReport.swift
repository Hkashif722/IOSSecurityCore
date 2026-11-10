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

    /// Why an evaluation did not run.
    public enum SkipReason: String, CaseIterable, Hashable, Sendable, Codable {
        /// The iOS Simulator.
        case simulator
        /// A Mac: Mac Catalyst, or an iOS app on Apple silicon.
        case macRuntime
        /// A platform the checks do not support.
        case unsupportedPlatform
    }

    /// Everything that was found, most severe first.
    public let threats: [SecurityThreat]

    /// The check families that actually ran. Empty when the environment is unsupported (Simulator, Mac),
    /// and also when no families were requested; ``skipReason`` tells the two apart.
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

    // MARK: - Verdict

    /// `true` when ``SecurityPolicy/default`` judges the environment compromised: at least one threat is
    /// ``SecurityThreat/Severity/high`` or worse.
    public var isCompromised: Bool {
        isCompromised(under: .default)
    }

    /// Whether `policy` judges the environment compromised.
    public func isCompromised(under policy: SecurityPolicy) -> Bool {
        policy.isCompromised(by: self)
    }

    /// The most severe threat, or `nil` when nothing was found.
    public var highestSeverity: SecurityThreat.Severity? {
        threats.map(\.severity).max()
    }

    // MARK: - Skipped evaluations

    /// Why the evaluation was skipped, or `nil` when the checks ran. A skipped report says nothing about
    /// the device; its only threat is the informational one that names the platform.
    public var skipReason: SkipReason? {
        threats.lazy.compactMap { SkipReason(kind: $0.kind) }.first
    }

    /// `true` when the evaluation was skipped because the platform is unsupported. Requesting no check
    /// families at all is not a skip: ``performedChecks`` is empty then too, but this stays `false`.
    public var wasSkipped: Bool {
        skipReason != nil
    }

    // MARK: - Queries

    /// The threats in one category.
    public func threats(in category: SecurityThreat.Category) -> [SecurityThreat] {
        threats.filter { $0.category == category }
    }

    /// Whether the report contains a threat of the given kind.
    public func contains(_ kind: SecurityThreat.Kind) -> Bool {
        threats.contains { $0.kind == kind }
    }
}

extension SecurityReport.SkipReason {
    /// The reason an environment threat stands for, or `nil` for any other kind.
    init?(kind: SecurityThreat.Kind) {
        switch kind {
        case .simulator: self = .simulator
        case .macRuntime: self = .macRuntime
        case .unsupportedPlatform: self = .unsupportedPlatform
        default: return nil
        }
    }
}
