//
//  ISCCodeTrust.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Decides whether a code address, or the code a function branches to, lives somewhere legitimate.
//

#import <Foundation/Foundation.h>
#import "ISCVisibility.h"
#import <objc/runtime.h>

NS_ASSUME_NONNULL_BEGIN


/// Locations a loaded image may come from without raising suspicion: the OS (including the cryptex and
/// developer disk images) and Apple-signed system support.
ISC_HIDDEN NSArray<NSString *> *ISCTrustedSystemPrefixes(void);

/// Which images inside the app bundle count as trusted code.
typedef NS_ENUM(NSInteger, ISCBundleTrust) {
    /// None. For checks where only the OS and one known image may appear.
    ISCBundleTrustNone = 0,
    /// Every image in the app bundle. Only when nothing better is known: an injected dylib lives there too.
    ISCBundleTrustAll = 1,
    /// Only bundle images whose path ends in one of `bundleLibraries` (whole path components).
    ISCBundleTrustListed = 2,
};

/// What counts as trusted code for one check. Build it once per scan with `ISCMakeCodeTrust`; nothing in it
/// changes while a scan runs.
typedef struct {
    /// OS code locations, plus prefixes the host trusts.
    NSArray<NSString *> *codePrefixes;
    /// The app bundle and, inside an extension, its containing app.
    NSArray<NSString *> *bundleRoots;
    /// Library names for `ISCBundleTrustListed`.
    NSArray<NSString *> *bundleLibraries;
    ISCBundleTrust bundleTrust;
    /// One more image trusted by load address (this package's own image), or NULL.
    const void *_Nullable trustedImageBase;
} ISCCodeTrust;

/// A trust scope: the OS and `extraPrefixes`, the bundle images `bundleTrust` allows, and the image loaded
/// at `trustedImageBase` when it is not NULL.
ISC_HIDDEN ISCCodeTrust ISCMakeCodeTrust(NSArray<NSString *> *extraPrefixes,
                              ISCBundleTrust bundleTrust,
                              NSArray<NSString *> *bundleLibraries,
                              const void *_Nullable trustedImageBase);

/// Whether `address` lies in code `trust` allows: the OS (shared cache, dyld, developer and cryptex images),
/// a host prefix, the trusted image, or a bundle image the scope admits. `outImagePath` receives the
/// containing image, or nil for memory no image owns (a hook's trampoline page).
ISC_HIDDEN BOOL ISCAddressIsTrustedCode(const void *_Nullable address,
                             const ISCCodeTrust *trust,
                             NSString *_Nullable *_Nonnull outImagePath);

/// `YES` when `function` starts with a branch into code `trust` does not allow. `outDestination` receives
/// the destination's image path, or nil for anonymous memory.
ISC_HIDDEN BOOL ISCFunctionIsInlineHooked(const void *_Nullable function,
                               const ISCCodeTrust *trust,
                               NSString *_Nullable *_Nonnull outDestination);

/// The address of a method's implementation with any pointer-authentication signature removed.
ISC_HIDDEN const void *ISCMethodImplementationAddress(Method method);

/// The method `selector` resolves to on `cls`, or NULL.
ISC_HIDDEN Method _Nullable ISCResolveMethod(Class _Nullable cls, SEL _Nullable selector, BOOL isClassMethod);

NS_ASSUME_NONNULL_END
