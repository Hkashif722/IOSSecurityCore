//
//  ISCFinding.m
//  IOSSecurityCoreObjC
//

#import "ISCFinding.h"
#import "ISCObfuscation.h"

// MARK: - Code table

typedef struct {
    ISCCategory category;
    ISCSeverity severity;
} ISCCodeTraits;

/// The single source of truth for a code's category and severity.
static ISCCodeTraits ISCTraitsForCode(ISCFindingCode code) {
    switch (code) {
        case ISCFindingCodeSimulator:
        case ISCFindingCodeUnsupportedPlatform:
        case ISCFindingCodeMacRuntime:
            return (ISCCodeTraits){ISCCategoryEnvironment, ISCSeverityInfo};

        case ISCFindingCodeJailbreakArtifact:
        case ISCFindingCodeJailbreakSymlink:
        case ISCFindingCodeJailbreakForkAllowed:
        case ISCFindingCodeJailbreakInjectedLibrary:
        case ISCFindingCodeJailbreakInjectionEnvironment:
            return (ISCCodeTraits){ISCCategoryJailbreak, ISCSeverityHigh};
        case ISCFindingCodeJailbreakSandboxEscape:
            return (ISCCodeTraits){ISCCategoryJailbreak, ISCSeverityCritical};

        case ISCFindingCodeDebuggerAttached:
            return (ISCCodeTraits){ISCCategoryDebugger, ISCSeverityHigh};

        case ISCFindingCodeHookInstrumentationLibrary:
        case ISCFindingCodeHookSelfIntegrity:
            return (ISCCodeTraits){ISCCategoryHooking, ISCSeverityCritical};
        case ISCFindingCodeHookInstrumentationPort:
        case ISCFindingCodeHookInstrumentationArtifact:
        case ISCFindingCodeHookSwizzledMethod:
        case ISCFindingCodeHookUnexpectedBundleLibrary:
            return (ISCCodeTraits){ISCCategoryHooking, ISCSeverityHigh};
        case ISCFindingCodeHookInstrumentationThread:
        case ISCFindingCodeHookUnknownLibrary:
            return (ISCCodeTraits){ISCCategoryHooking, ISCSeverityMedium};
        case ISCFindingCodeHookProtectedMethodUnresolved:
            return (ISCCodeTraits){ISCCategoryHooking, ISCSeverityLow};

        case ISCFindingCodeIntegrityBundleIdentifierMismatch:
        case ISCFindingCodeIntegrityTeamIdentifierMismatch:
        case ISCFindingCodeIntegrityTextSegmentModified:
            return (ISCCodeTraits){ISCCategoryIntegrity, ISCSeverityCritical};
        case ISCFindingCodeIntegrityBinaryDecrypted:
        case ISCFindingCodeIntegrityDebuggableBuild:
        case ISCFindingCodeIntegrityUnexpectedProvisioningProfile:
            return (ISCCodeTraits){ISCCategoryIntegrity, ISCSeverityHigh};
        case ISCFindingCodeIntegrityTeamIdentifierUnavailable:
        case ISCFindingCodeIntegrityTextSegmentUnavailable:
            return (ISCCodeTraits){ISCCategoryIntegrity, ISCSeverityMedium};
    }
    return (ISCCodeTraits){ISCCategoryEnvironment, ISCSeverityInfo};
}

/// Identifiers are obfuscated like every other literal, so `strings` does not list the checks.
static NSString *ISCIdentifierForCode(ISCFindingCode code) {
    switch (code) {
        case ISCFindingCodeSimulator:
            return ISC_OBF_NSSTRING("environment.simulator");
        case ISCFindingCodeUnsupportedPlatform:
            return ISC_OBF_NSSTRING("environment.unsupported_platform");
        case ISCFindingCodeMacRuntime:
            return ISC_OBF_NSSTRING("environment.mac_runtime");

        case ISCFindingCodeJailbreakArtifact:
            return ISC_OBF_NSSTRING("jailbreak.artifact");
        case ISCFindingCodeJailbreakSymlink:
            return ISC_OBF_NSSTRING("jailbreak.symlink");
        case ISCFindingCodeJailbreakSandboxEscape:
            return ISC_OBF_NSSTRING("jailbreak.sandbox_escape");
        case ISCFindingCodeJailbreakForkAllowed:
            return ISC_OBF_NSSTRING("jailbreak.fork_allowed");
        case ISCFindingCodeJailbreakInjectedLibrary:
            return ISC_OBF_NSSTRING("jailbreak.injected_library");
        case ISCFindingCodeJailbreakInjectionEnvironment:
            return ISC_OBF_NSSTRING("jailbreak.injection_environment");

        case ISCFindingCodeDebuggerAttached:
            return ISC_OBF_NSSTRING("debugger.attached");

        case ISCFindingCodeHookInstrumentationLibrary:
            return ISC_OBF_NSSTRING("hooking.instrumentation_library");
        case ISCFindingCodeHookInstrumentationPort:
            return ISC_OBF_NSSTRING("hooking.instrumentation_port");
        case ISCFindingCodeHookInstrumentationThread:
            return ISC_OBF_NSSTRING("hooking.instrumentation_thread");
        case ISCFindingCodeHookInstrumentationArtifact:
            return ISC_OBF_NSSTRING("hooking.instrumentation_artifact");
        case ISCFindingCodeHookUnknownLibrary:
            return ISC_OBF_NSSTRING("hooking.unknown_library");
        case ISCFindingCodeHookSwizzledMethod:
            return ISC_OBF_NSSTRING("hooking.swizzled_method");
        case ISCFindingCodeHookProtectedMethodUnresolved:
            return ISC_OBF_NSSTRING("hooking.protected_method_unresolved");
        case ISCFindingCodeHookSelfIntegrity:
            return ISC_OBF_NSSTRING("hooking.self_integrity");
        case ISCFindingCodeHookUnexpectedBundleLibrary:
            return ISC_OBF_NSSTRING("hooking.unexpected_bundle_library");

        case ISCFindingCodeIntegrityBundleIdentifierMismatch:
            return ISC_OBF_NSSTRING("integrity.bundle_identifier_mismatch");
        case ISCFindingCodeIntegrityTeamIdentifierMismatch:
            return ISC_OBF_NSSTRING("integrity.team_identifier_mismatch");
        case ISCFindingCodeIntegrityBinaryDecrypted:
            return ISC_OBF_NSSTRING("integrity.binary_decrypted");
        case ISCFindingCodeIntegrityTextSegmentModified:
            return ISC_OBF_NSSTRING("integrity.text_segment_modified");
        case ISCFindingCodeIntegrityDebuggableBuild:
            return ISC_OBF_NSSTRING("integrity.debuggable_build");
        case ISCFindingCodeIntegrityUnexpectedProvisioningProfile:
            return ISC_OBF_NSSTRING("integrity.unexpected_provisioning_profile");
        case ISCFindingCodeIntegrityTeamIdentifierUnavailable:
            return ISC_OBF_NSSTRING("integrity.team_identifier_unavailable");
        case ISCFindingCodeIntegrityTextSegmentUnavailable:
            return ISC_OBF_NSSTRING("integrity.text_segment_unavailable");
    }
    return ISC_OBF_NSSTRING("unknown");
}

// MARK: - ISCFinding

@implementation ISCFinding

- (instancetype)initWithCode:(ISCFindingCode)code detail:(NSString *)detail {
    self = [super init];
    if (self != nil) {
        ISCCodeTraits traits = ISCTraitsForCode(code);
        _code = code;
        _category = traits.category;
        _severity = traits.severity;
        _identifier = [ISCIdentifierForCode(code) copy];
        _detail = [detail copy];
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    return self; // immutable
}

- (BOOL)isEqual:(id)object {
    if (self == object) {
        return YES;
    }
    if (![object isKindOfClass:ISCFinding.class]) {
        return NO;
    }
    ISCFinding *other = object;
    return self.code == other.code && (self.detail == other.detail || [self.detail isEqualToString:other.detail]);
}

- (NSUInteger)hash {
    return (NSUInteger)self.code ^ self.detail.hash;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<%@ %ld %@ severity=%ld%@>",
            NSStringFromClass(self.class), (long)self.code, self.identifier, (long)self.severity,
            self.detail != nil ? [NSString stringWithFormat:@" detail=\"%@\"", self.detail] : @""];
}

@end

// MARK: - ISCScanResult

@implementation ISCScanResult

- (instancetype)initWithFindings:(NSArray<ISCFinding *> *)findings
                 performedChecks:(ISCChecks)performedChecks
                       startedAt:(NSDate *)startedAt
                        duration:(NSTimeInterval)duration {
    self = [super init];
    if (self != nil) {
        _findings = [findings copy];
        _performedChecks = performedChecks;
        _startedAt = [startedAt copy];
        _duration = duration;
    }
    return self;
}

- (BOOL)isCompromised {
    for (ISCFinding *finding in self.findings) {
        if (finding.severity >= ISCSeverityHigh) {
            return YES;
        }
    }
    return NO;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<%@ compromised=%d findings=%lu duration=%.3fs>",
            NSStringFromClass(self.class), self.isCompromised, (unsigned long)self.findings.count, self.duration];
}

@end
