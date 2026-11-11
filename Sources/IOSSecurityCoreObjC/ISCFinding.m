//
//  ISCFinding.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCFinding.h"
#import "ISCFindingSupport.h"
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
        case ISCFindingCodeJailbreakBypassTool:
        case ISCFindingCodeJailbreakRemoteShellPort:
            return (ISCCodeTraits){ISCCategoryJailbreak, ISCSeverityHigh};
        case ISCFindingCodeJailbreakSandboxEscape:
            return (ISCCodeTraits){ISCCategoryJailbreak, ISCSeverityCritical};

        case ISCFindingCodeDebuggerAttached:
        case ISCFindingCodeDebuggerHardwareBreakpoint:
            return (ISCCodeTraits){ISCCategoryDebugger, ISCSeverityHigh};
        case ISCFindingCodeDebuggerUnexpectedParent:
            return (ISCCodeTraits){ISCCategoryDebugger, ISCSeverityMedium};

        case ISCFindingCodeHookInstrumentationLibrary:
        case ISCFindingCodeHookSelfIntegrity:
        case ISCFindingCodeHookInlinePatchedFunction:
        case ISCFindingCodeHookReboundSymbol:
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
        case ISCFindingCodeIntegrityImageModified:
            return (ISCCodeTraits){ISCCategoryIntegrity, ISCSeverityCritical};
        case ISCFindingCodeIntegrityBinaryDecrypted:
        case ISCFindingCodeIntegrityDebuggableBuild:
        case ISCFindingCodeIntegrityUnexpectedProvisioningProfile:
            return (ISCCodeTraits){ISCCategoryIntegrity, ISCSeverityHigh};
        case ISCFindingCodeIntegrityTeamIdentifierUnavailable:
        case ISCFindingCodeIntegrityTextSegmentUnavailable:
        case ISCFindingCodeIntegrityImageUnavailable:
            return (ISCCodeTraits){ISCCategoryIntegrity, ISCSeverityMedium};

        case ISCFindingCodeNetworkProxy:
            // Corporate and school networks configure proxies legitimately.
            return (ISCCodeTraits){ISCCategoryNetwork, ISCSeverityMedium};
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
        case ISCFindingCodeJailbreakBypassTool:
            return ISC_OBF_NSSTRING("jailbreak.bypass_tool");
        case ISCFindingCodeJailbreakRemoteShellPort:
            return ISC_OBF_NSSTRING("jailbreak.remote_shell_port");

        case ISCFindingCodeDebuggerAttached:
            return ISC_OBF_NSSTRING("debugger.attached");
        case ISCFindingCodeDebuggerHardwareBreakpoint:
            return ISC_OBF_NSSTRING("debugger.hardware_breakpoint");
        case ISCFindingCodeDebuggerUnexpectedParent:
            return ISC_OBF_NSSTRING("debugger.unexpected_parent");

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
        case ISCFindingCodeHookInlinePatchedFunction:
            return ISC_OBF_NSSTRING("hooking.inline_patched_function");
        case ISCFindingCodeHookReboundSymbol:
            return ISC_OBF_NSSTRING("hooking.rebound_symbol");

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
        case ISCFindingCodeIntegrityImageModified:
            return ISC_OBF_NSSTRING("integrity.image_modified");
        case ISCFindingCodeIntegrityImageUnavailable:
            return ISC_OBF_NSSTRING("integrity.image_unavailable");

        case ISCFindingCodeNetworkProxy:
            return ISC_OBF_NSSTRING("network.proxy");
    }
    return ISC_OBF_NSSTRING("unknown");
}

// MARK: - ISCFinding

@implementation ISCFinding

/// Fills in every field from `code`. Defined inside the implementation so it can set the ivars directly.
static void ISCFindingFill(ISCFinding *finding, ISCFindingCode code, NSString *detail) {
    ISCCodeTraits traits = ISCTraitsForCode(code);
    finding->_code = code;
    finding->_category = traits.category;
    finding->_severity = traits.severity;
    finding->_identifier = [ISCIdentifierForCode(code) copy];
    finding->_detail = [detail copy];
}

ISCFinding *ISCMakeFinding(ISCFindingCode code, NSString *detail) {
    // NSObject's -init does nothing, so skipping it (and any swizzle on it) loses nothing.
    ISCFinding *finding = [ISCFinding alloc];
    ISCFindingFill(finding, code, detail);
    return finding;
}

- (instancetype)initWithCode:(ISCFindingCode)code detail:(NSString *)detail {
    self = [super init];
    if (self != nil) {
        ISCFindingFill(self, code, detail);
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
