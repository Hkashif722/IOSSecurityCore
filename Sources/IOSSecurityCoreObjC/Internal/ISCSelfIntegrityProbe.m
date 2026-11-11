//
//  ISCSelfIntegrityProbe.m
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCSelfIntegrityProbe.h"
#import "ISCFindingSupport.h"
#import "ISCCodeTrust.h"
#import "ISCDetector.h"
#import "ISCRuntimeSupport.h"

/// A function in this file, used to find the image this package was linked into.
static void ISCSelfAnchor(void) {}

NSArray<ISCFinding *> *ISCSelfIntegrityFindings(void) {
    const void *anchor = (const void *)(uintptr_t)ISC_STRIP_CODE_POINTER(ISCSelfAnchor);
    const void *ownBase = NULL;
    if (!ISCImageForAddress(anchor, NULL, &ownBase) || ownBase == NULL) {
        return @[];
    }

    // This package's code may branch into itself (a compiler tail call) or into the OS, and nowhere else.
    // In particular not into the app bundle: a dylib injected into a repackaged app lives there.
    ISCCodeTrust trust = ISCMakeCodeTrust(@[], ISCBundleTrustNone, @[], ownBase);

    NSMutableArray<NSString *> *tampered = [NSMutableArray array];
    for (NSValue *value in ISCSelfIntegrityTargets()) {
        ISCMethodTarget target;
        [value getValue:&target size:sizeof(target)];

        Method method = ISCResolveMethod(target.cls, target.selector, target.isClassMethod);
        const void *implementation = method != NULL ? ISCMethodImplementationAddress(method) : NULL;
        const void *base = NULL;
        BOOL isOurs = implementation != NULL && ISCImageForAddress(implementation, NULL, &base) && base == ownBase;
        NSString *destination = nil;
        if (!isOurs || ISCFunctionIsInlineHooked(implementation, &trust, &destination)) {
            [tampered addObject:[NSString stringWithFormat:@"%c[%@ %@]",
                                 target.isClassMethod ? '+' : '-',
                                 NSStringFromClass(target.cls),
                                 NSStringFromSelector(target.selector)]];
        }
    }

    // The C functions a scan runs through: an inline patch can redirect them without touching any method.
    ISCForEachSelfIntegrityFunction(^(NSString *name, const void *function) {
        NSString *destination = nil;
        if (ISCFunctionIsInlineHooked(function, &trust, &destination)) {
            [tampered addObject:name];
        }
    });

    if (tampered.count == 0) {
        return @[];
    }
    return @[ISCMakeFinding(ISCFindingCodeHookSelfIntegrity, ISCSummarizeValues(tampered, ISCDetailLimit))];
}
