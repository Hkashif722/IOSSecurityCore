//
//  ObjCBridge.swift
//  IOSSecurityCore
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import Foundation
import IOSSecurityCoreObjC

// Conversions between the Swift value types and the Objective-C layer. Nothing here is public: the
// Objective-C types never appear in this module's API.

extension SecurityConfiguration {
    /// A fresh Objective-C options object. `ISCScanOptions` is a mutable reference type, so a new one is
    /// made for every scan instead of being shared.
    func makeScanOptions(checksOverride: Set<SecurityCheck>? = nil) -> ISCScanOptions {
        let options = ISCScanOptions()
        options.checks = (checksOverride ?? checks).objcValue
        options.includesBuiltInIndicators = includesBuiltInIndicators
        options.scansUnsupportedEnvironments = scansUnsupportedEnvironments

        options.additionalSuspiciousPaths = jailbreak.additionalSuspiciousPaths
        options.performsSandboxWriteProbe = jailbreak.performsSandboxWriteProbe
        options.performsForkProbe = jailbreak.performsForkProbe
        options.additionalSuspiciousClasses = jailbreak.additionalSuspiciousClasses
        options.probesRemoteShellPorts = jailbreak.probesRemoteShellPorts

        options.additionalSuspiciousLibraries = hooking.additionalSuspiciousLibraries
        options.allowedImagePathPrefixes = hooking.allowedImagePathPrefixes
        options.reportsUnknownLibraries = hooking.reportsUnknownLibraries
        options.allowedBundleLibraries = hooking.allowedBundleLibraries
        options.probesInstrumentationPorts = hooking.probesInstrumentationPorts
        options.protectedMethods = hooking.protectedMethods.map { method in
            ISCProtectedMethod(
                targetClassName: method.className,
                selectorName: method.selector,
                isClassMethod: method.scope == .class,
                allowedImagePathPrefixes: method.allowedImagePathPrefixes
            )
        }

        options.expectedBundleIdentifier = integrity.expectedBundleIdentifier
        options.expectedTeamIdentifier = integrity.expectedTeamIdentifier
        options.expectedTextSegmentDigests = integrity.expectedTextSegmentDigests.sorted()
        options.expectedImageTextDigests = integrity.expectedImageTextDigests.mapValues { $0.sorted() }
        options.expectedDistribution = integrity.expectedDistribution.objcValue
        return options
    }
}

extension SecurityConfiguration.Distribution {
    var objcValue: ISCDistribution {
        switch self {
        case .any: return .any
        case .appStore: return .appStore
        }
    }
}

extension SecurityThreat {
    init(_ finding: ISCFinding) {
        self.init(
            kind: Kind(finding.code),
            category: Category(finding.category),
            severity: Severity(finding.severity),
            identifier: finding.identifier,
            detail: finding.detail
        )
    }
}

extension SecurityThreat.Category {
    init(_ category: ISCCategory) {
        switch category {
        case .environment: self = .environment
        case .jailbreak: self = .jailbreak
        case .debugger: self = .debugger
        case .hooking: self = .hooking
        case .integrity: self = .integrity
        case .network: self = .network
        @unknown default: self = .environment
        }
    }
}

extension SecurityThreat.Severity {
    init(_ severity: ISCSeverity) {
        switch severity {
        case .info: self = .info
        case .low: self = .low
        case .medium: self = .medium
        case .high: self = .high
        case .critical: self = .critical
        }
    }
}

extension SecurityReport.SkipReason {
    /// Why this build skips a scan, from compile-time facts and one runtime fact the Objective-C layer cannot
    /// change: `nil` on a physical iPhone or iPad.
    static var expectedForThisProcess: Self? {
        #if targetEnvironment(simulator)
        return .simulator
        #elseif targetEnvironment(macCatalyst)
        return .macRuntime
        #elseif os(iOS)
        return ProcessInfo.processInfo.isiOSAppOnMac ? .macRuntime : nil
        #else
        return .unsupportedPlatform
        #endif
    }
}

extension SecurityReport {
    /// The report, checked against what the Swift layer knows independently of the Objective-C result: whether
    /// this process should have been skipped, and which families were asked for. A result that disagrees
    /// was tampered with on the way (a forged "skipped" on a real device, a family that silently did not
    /// run), so the report gains a critical ``SecurityThreat/Kind/hookSelfIntegrity`` threat and loses the
    /// skip it claimed.
    func verified(requested: Set<SecurityCheck>, scansUnsupportedEnvironments: Bool) -> SecurityReport {
        let expectedSkip = scansUnsupportedEnvironments ? nil : SkipReason.expectedForThisProcess
        let problem: String?
        if skipReason != expectedSkip {
            problem = "skip \(skipReason?.rawValue ?? "none"), expected \(expectedSkip?.rawValue ?? "none")"
        } else if skipReason == nil && performedChecks != requested {
            let names = { (checks: Set<SecurityCheck>) in checks.map(\.rawValue).sorted().joined(separator: "+") }
            problem = "performed \(names(performedChecks)), requested \(names(requested))"
        } else {
            problem = nil
        }
        guard let problem else { return self }

        let tampering = SecurityThreat(ISCFinding(code: .hookSelfIntegrity, detail: problem))
        return SecurityReport(
            threats: [tampering] + threats,
            performedChecks: performedChecks,
            startedAt: startedAt,
            duration: duration,
            exactSkipReason: nil
        )
    }

    init(_ result: ISCScanResult) {
        let threats = result.findings.map(SecurityThreat.init)
        // The scanner ran nothing and said why: that is the only time a report is skipped.
        let skipReason = result.performedChecks.isEmpty
            ? threats.lazy.compactMap { SkipReason(kind: $0.kind) }.first
            : nil
        self.init(
            threats: threats,
            performedChecks: Set(objc: result.performedChecks),
            startedAt: result.startedAt,
            duration: result.duration,
            skipReason: skipReason
        )
    }
}
