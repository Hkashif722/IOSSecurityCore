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

        options.additionalSuspiciousPaths = additionalSuspiciousPaths
        options.performsSandboxWriteProbe = performsSandboxWriteProbe
        options.performsForkProbe = performsForkProbe

        options.additionalSuspiciousLibraries = additionalSuspiciousLibraries
        options.allowedImagePathPrefixes = allowedImagePathPrefixes
        options.reportsUnknownLibraries = reportsUnknownLibraries
        options.allowedBundleLibraries = allowedBundleLibraries
        options.probesInstrumentationPorts = probesInstrumentationPorts
        options.protectedMethods = protectedMethods.map { method in
            ISCProtectedMethod(
                targetClassName: method.className,
                selectorName: method.selector,
                isClassMethod: method.scope == .class,
                allowedImagePathPrefixes: method.allowedImagePathPrefixes
            )
        }

        options.expectedBundleIdentifier = expectedBundleIdentifier
        options.expectedTeamIdentifier = expectedTeamIdentifier
        options.expectedTextSegmentDigests = expectedTextSegmentDigests.sorted()
        options.expectedDistribution = expectedDistribution.objcValue
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

extension SecurityReport {
    init(_ result: ISCScanResult) {
        self.init(
            threats: result.findings.map(SecurityThreat.init),
            performedChecks: Set(objc: result.performedChecks),
            startedAt: result.startedAt,
            duration: result.duration
        )
    }
}
