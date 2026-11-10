//
//  ISCSelfIntegrityProbe.m
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCSelfIntegrityProbe.h"
#import "ISCCodeTrust.h"
#import "ISCDetector.h"
#import "ISCRuntimeSupport.h"
#import "ISCTrampoline.h"

/// A function in this file, used to find the image this package was linked into.
static void ISCSelfAnchor(void) {}

/// `YES` when one of this package's own functions starts with a branch into code that is neither this
/// image nor the OS. A branch that stays in this image is a tail call the compiler emitted, not a hook.
static BOOL ISCOwnFunctionIsInlineHooked(const void *function, const void *ownBase) {
    const void *target = NULL;
    if (!ISCDecodeTrampoline(function, &target)) {
        return NO;
    }
    const void *targetBase = NULL;
    if (ISCImageForAddress(target, NULL, &targetBase) && targetBase == ownBase) {
        return NO;
    }
    NSString *path = nil;
    return !ISCAddressIsTrustedCode(target, @[], &path);
}

NSArray<ISCFinding *> *ISCSelfIntegrityFindings(void) {
    const void *anchor = (const void *)(uintptr_t)ISC_STRIP_CODE_POINTER(ISCSelfAnchor);
    const void *ownBase = NULL;
    if (!ISCImageForAddress(anchor, NULL, &ownBase) || ownBase == NULL) {
        return @[];
    }

    size_t count = 0;
    const ISCMethodTarget *targets = ISCSelfIntegrityTargets(&count);

    NSMutableArray<NSString *> *tampered = [NSMutableArray array];
    for (size_t index = 0; index < count; index++) {
        Method method = ISCResolveMethod(targets[index].cls, targets[index].selector, targets[index].isClassMethod);
        const void *implementation = method != NULL ? ISCMethodImplementationAddress(method) : NULL;
        const void *base = NULL;
        BOOL isOurs = implementation != NULL &&
                      ISCImageForAddress(implementation, NULL, &base) &&
                      base == ownBase;
        if (!isOurs || ISCOwnFunctionIsInlineHooked(implementation, ownBase)) {
            [tampered addObject:[NSString stringWithFormat:@"%c[%@ %@]",
                                 targets[index].isClassMethod ? '+' : '-',
                                 NSStringFromClass(targets[index].cls),
                                 NSStringFromSelector(targets[index].selector)]];
        }
    }

    if (tampered.count == 0) {
        return @[];
    }
    return @[[[ISCFinding alloc] initWithCode:ISCFindingCodeHookSelfIntegrity
                                       detail:ISCSummarizeValues(tampered, ISCDetailLimit)]];
}
