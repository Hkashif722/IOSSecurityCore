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

/// Where non-cached OS code lives: the developer disk image and cryptexes. Deliberately not `/usr/lib/`
/// on a device: every genuine library there is in the shared cache, and rootful tweak loaders install
/// into it. The Simulator is different: it loads some of `/usr/lib/system/` from outside its cache.
static NSArray<NSString *> *ISCTrustedCodePrefixes(void) {
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

ISCCodeTrust ISCMakeCodeTrust(NSArray<NSString *> *extraPrefixes, ISCBundleTrust bundleTrust,
                              NSArray<NSString *> *bundleLibraries, const void *trustedImageBase) {
    NSMutableArray<NSString *> *prefixes = [NSMutableArray arrayWithArray:ISCTrustedCodePrefixes()];
    [prefixes addObjectsFromArray:extraPrefixes];
    return (ISCCodeTrust){
        .codePrefixes = prefixes,
        .bundleRoots = bundleTrust == ISCBundleTrustNone ? @[] : ISCAppBundleRoots(),
        .bundleLibraries = [bundleLibraries copy],
        .bundleTrust = bundleTrust,
        .trustedImageBase = trustedImageBase,
    };
}

/// Whether the bundle image at `path` is one `trust` admits. `path` is known to be inside the bundle.
static BOOL ISCBundleImageIsTrusted(NSString *path, const ISCCodeTrust *trust) {
    switch (trust->bundleTrust) {
        case ISCBundleTrustNone:
            return NO;
        case ISCBundleTrustAll:
            return YES;
        case ISCBundleTrustListed:
            for (NSString *name in trust->bundleLibraries) {
                if (ISCPathHasComponentSuffix(path, name)) {
                    return YES;
                }
            }
            return NO;
    }
    return NO;
}

BOOL ISCAddressIsTrustedCode(const void *address, const ISCCodeTrust *trust, NSString **outImagePath) {
    *outImagePath = nil;
    NSString *path = nil;
    const void *base = NULL;
    if (!ISCImageForAddress(address, &path, &base)) {
        return NO;
    }
    *outImagePath = path;
    if (trust->trustedImageBase != NULL && base == trust->trustedImageBase) {
        return YES;
    }
    if (ISCImageIsInSharedCache(base) || [path isEqualToString:@"/usr/lib/dyld"]) {
        return YES;
    }
    if (ISCPathMatchesAnyPrefix(path, trust->codePrefixes)) {
        return YES;
    }
    return ISCPathMatchesAnyPrefix(path, trust->bundleRoots) && ISCBundleImageIsTrusted(path, trust);
}

BOOL ISCFunctionIsInlineHooked(const void *function, const ISCCodeTrust *trust, NSString **outDestination) {
    *outDestination = nil;
    const void *target = NULL;
    if (!ISCDecodeTrampoline(function, &target)) {
        return NO;
    }
    NSString *path = nil;
    if (ISCAddressIsTrustedCode(target, trust, &path)) {
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
