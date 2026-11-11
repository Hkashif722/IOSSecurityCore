//
//  ISCDetectorRegistry.m
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  The composition root: the only file that imports every detector and the scanner.
//

#import "ISCDetector.h"
#import "ISCDebuggerDetector.h"
#import "ISCEnvironment.h"
#import "ISCFindingSupport.h"
#import "ISCHookDetector.h"
#import "ISCInstrumentationProbe.h"
#import "ISCIntegrityChecker.h"
#import "ISCJailbreakDetector.h"
#import "ISCNetworkDetector.h"
#import "ISCObfuscation.h"
#import "ISCRuntimeSupport.h"
#import "ISCSecurityScanner.h"
#import "ISCSelfIntegrityProbe.h"
#import "ISCSystemFunctionProbe.h"

/// Scan order. Jailbreak first because its findings give the later ones context; network last because it
/// is the weakest signal.
static const ISCDetectorEntry ISCDetectorTable[] = {
    {ISCChecksJailbreak, ISCJailbreakScan},
    {ISCChecksDebugger, ISCDebuggerScan},
    {ISCChecksHooking, ISCHookingScan},
    {ISCChecksIntegrity, ISCIntegrityScan},
    {ISCChecksNetwork, ISCNetworkScan},
};

const ISCDetectorEntry *ISCDetectorEntries(size_t *outCount) {
    *outCount = sizeof(ISCDetectorTable) / sizeof(ISCDetectorTable[0]);
    return ISCDetectorTable;
}

NSArray<NSValue *> *ISCSelfIntegrityTargets(void) {
    static NSArray<NSValue *> *targets;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // The scans call C functions, so swizzling these does not change a scan. It does change what a host
        // reads directly, what `IntegritySignals` sends to a server, and how a report is read back.
        const ISCMethodTarget table[] = {
            {ISCEnvironment.class, @selector(isSimulator), YES},
            {ISCEnvironment.class, @selector(isMacCatalystApp), YES},
            {ISCEnvironment.class, @selector(isiOSAppOnMac), YES},
            {ISCEnvironment.class, @selector(isSupportedDevicePlatform), YES},

            {ISCJailbreakDetector.class, @selector(scanWithOptions:), YES},
            {ISCJailbreakDetector.class, @selector(existingPathsAmong:), YES},
            {ISCJailbreakDetector.class, @selector(registeredClassesAmong:), YES},

            {ISCDebuggerDetector.class, @selector(scanWithOptions:), YES},
            {ISCDebuggerDetector.class, @selector(isDebuggerAttached), YES},
            {ISCDebuggerDetector.class, @selector(hasHardwareBreakpoints), YES},
            {ISCDebuggerDetector.class, @selector(isParentProcessUnexpected), YES},
            {ISCDebuggerDetector.class, @selector(denyDebuggerAttachment), YES},

            {ISCHookDetector.class, @selector(scanWithOptions:), YES},
            {ISCHookDetector.class, @selector(loadedImagePaths), YES},
            {ISCHookDetector.class, @selector(isFunctionInlineHooked:), YES},
            {ISCHookDetector.class, @selector(verifyProtectedMethods:), YES},

            {ISCIntegrityChecker.class, @selector(scanWithOptions:), YES},
            {ISCIntegrityChecker.class, @selector(codeSigningEntitlements), YES},
            {ISCIntegrityChecker.class, @selector(codeSigningTeamIdentifier), YES},
            {ISCIntegrityChecker.class, @selector(teamIdentifierFromEntitlements:), YES},
            {ISCIntegrityChecker.class, @selector(binaryEncryptionState), YES},
            {ISCIntegrityChecker.class, @selector(hasEmbeddedProvisioningProfile), YES},
            {ISCIntegrityChecker.class, @selector(embeddedProvisioningProfile), YES},
            {ISCIntegrityChecker.class, @selector(textSegmentDigest), YES},
            {ISCIntegrityChecker.class, @selector(textSegmentDigestOfImageNamed:), YES},
            {ISCIntegrityChecker.class, @selector(entitlementsFromCodeSignatureData:), YES},

            {ISCNetworkDetector.class, @selector(scanWithOptions:), YES},
            {ISCNetworkDetector.class, @selector(configuredProxyKinds), YES},
            {ISCNetworkDetector.class, @selector(proxyKindsInSettings:), YES},

            // The options that gate a scan, the scanner, and everything a report is read back through.
            {ISCScanOptions.class, @selector(checks), NO},
            {ISCScanOptions.class, @selector(includesBuiltInIndicators), NO},
            {ISCScanOptions.class, @selector(scansUnsupportedEnvironments), NO},
            {ISCSecurityScanner.class, @selector(scan), NO},
            {ISCFinding.class, @selector(initWithCode:detail:), NO},
            {ISCFinding.class, @selector(code), NO},
            {ISCFinding.class, @selector(category), NO},
            {ISCFinding.class, @selector(severity), NO},
            {ISCFinding.class, @selector(identifier), NO},
            {ISCFinding.class, @selector(detail), NO},
            {ISCScanResult.class, @selector(findings), NO},
            {ISCScanResult.class, @selector(performedChecks), NO},
            {ISCScanResult.class, @selector(isCompromised), NO},
        };
        NSMutableArray<NSValue *> *boxed = [NSMutableArray array];
        for (size_t index = 0; index < sizeof(table) / sizeof(table[0]); index++) {
            [boxed addObject:[NSValue valueWithBytes:&table[index] objCType:@encode(ISCMethodTarget)]];
        }
        targets = boxed;
    });
    return targets;
}

#define ISC_SELF_INTEGRITY_FUNCTIONS(X) \
    X(ISCPerformScan)                   \
    X(ISCJailbreakScan)                 \
    X(ISCDebuggerScan)                  \
    X(ISCHookingScan)                   \
    X(ISCIntegrityScan)                 \
    X(ISCNetworkScan)                   \
    X(ISCSelfIntegrityFindings)         \
    X(ISCSystemFunctionFindings)        \
    X(ISCInstrumentationFindings)       \
    X(ISCMakeFinding)

#define ISC_VISIT_SELF_INTEGRITY_FUNCTION(function) \
    visit(ISC_OBF_NSSTRING(#function), (const void *)(uintptr_t)ISC_STRIP_CODE_POINTER(function));

void ISCForEachSelfIntegrityFunction(void (NS_NOESCAPE ^visit)(NSString *name, const void *function)) {
    ISC_SELF_INTEGRITY_FUNCTIONS(ISC_VISIT_SELF_INTEGRITY_FUNCTION)
}
