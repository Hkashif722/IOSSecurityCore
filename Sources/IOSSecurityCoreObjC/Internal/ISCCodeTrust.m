//
//  ISCCodeTrust.m
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCCodeTrust.h"
#import "ISCRuntimeSupport.h"
#import "ISCTrampoline.h"

#import <TargetConditionals.h>

NSArray<NSString *> *ISCTrustedSystemPrefixes(void) {
    return @[
        @"/System/",
        @"/usr/lib/",
        @"/Developer/",
        @"/Library/Apple/",
        @"/private/preboot/Cryptexes/",
    ];
}

NSArray<NSString *> *ISCTrustedCodePrefixes(void) {
    return @[
        @"/System/",
        @"/Developer/",
        @"/Library/Apple/",
        @"/private/preboot/Cryptexes/",
#if TARGET_OS_SIMULATOR
        @"/usr/lib/",
#endif
    ];
}

BOOL ISCAddressIsTrustedCode(const void *address, NSArray<NSString *> *extraTrustedPrefixes, NSString **outImagePath) {
    *outImagePath = nil;
    NSString *path = nil;
    const void *base = NULL;
    if (!ISCImageForAddress(address, &path, &base)) {
        return NO;
    }
    *outImagePath = path;
    if (ISCImageIsInSharedCache(base) || [path isEqualToString:@"/usr/lib/dyld"]) {
        return YES;
    }
    NSMutableArray<NSString *> *trusted = [NSMutableArray arrayWithArray:ISCTrustedCodePrefixes()];
    [trusted addObjectsFromArray:ISCAppBundleRoots()];
    [trusted addObjectsFromArray:extraTrustedPrefixes];
    return ISCPathMatchesAnyPrefix(path, trusted);
}

BOOL ISCFunctionIsInlineHooked(const void *function, NSArray<NSString *> *extraTrustedPrefixes, NSString **outDestination) {
    *outDestination = nil;
    const void *target = NULL;
    if (!ISCDecodeTrampoline(function, &target)) {
        return NO;
    }
    NSString *path = nil;
    if (ISCAddressIsTrustedCode(target, extraTrustedPrefixes, &path)) {
        return NO;
    }
    *outDestination = path;
    return YES;
}

const void *ISCMethodImplementationAddress(Method method) {
    IMP implementation = method_getImplementation(method);
    return (const void *)(uintptr_t)ISC_STRIP_CODE_POINTER(implementation);
}

Method ISCResolveMethod(Class cls, SEL selector, BOOL isClassMethod) {
    if (cls == Nil || selector == NULL) {
        return NULL;
    }
    return isClassMethod ? class_getClassMethod(cls, selector) : class_getInstanceMethod(cls, selector);
}
