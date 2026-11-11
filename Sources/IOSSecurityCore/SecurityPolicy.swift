//
//  SecurityPolicy.swift
//  IOSSecurityCore
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import Foundation

/// Turns a ``SecurityReport`` into a verdict.
///
/// The engine reports; the host decides. ``default`` is the rule most apps want: any threat of
/// ``SecurityThreat/Severity/high`` or worse means the environment cannot be trusted. Tighten or loosen it
/// per app, or per feature within an app:
///
/// ```swift
/// // A payments screen treats a configured proxy as disqualifying, even though it is only medium.
/// var strict = SecurityPolicy()
/// strict.escalatedKinds = [.networkProxy]
/// if report.isCompromised(under: strict) { … }
/// ```
///
/// Environment threats (``SecurityThreat/Category/environment``) never count, whatever the policy says:
/// they describe where the app runs, not whether it is under attack.
public struct SecurityPolicy: Hashable, Sendable {

    /// The least severe threat that still counts as a compromise. Default: ``SecurityThreat/Severity/high``.
    public var minimumSeverity: SecurityThreat.Severity

    /// Threat kinds that never count, whatever their severity. For a signal you have confirmed is a false
    /// positive in your app, or one you handle some other way. A kind listed here is ignored even if it
    /// is also in ``escalatedKinds``.
    public var ignoredKinds: Set<SecurityThreat.Kind>

    /// Threat kinds that count whatever their severity, unless ``ignoredKinds`` also lists them, which wins.
    public var escalatedKinds: Set<SecurityThreat.Kind>

    public init(
        minimumSeverity: SecurityThreat.Severity = .high,
        ignoredKinds: Set<SecurityThreat.Kind> = [],
        escalatedKinds: Set<SecurityThreat.Kind> = []
    ) {
        self.minimumSeverity = minimumSeverity
        self.ignoredKinds = ignoredKinds
        self.escalatedKinds = escalatedKinds
    }

    /// Any threat of `high` severity or worse compromises the environment.
    public static let `default` = SecurityPolicy()

    /// Whether `report` contains a threat this policy counts as a compromise.
    public func isCompromised(by report: SecurityReport) -> Bool {
        report.threats.contains { threat in
            if threat.category == .environment || ignoredKinds.contains(threat.kind) {
                return false
            }
            return escalatedKinds.contains(threat.kind) || threat.severity >= minimumSeverity
        }
    }
}
