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
#import <objc/runtime.h>

NS_ASSUME_NONNULL_BEGIN

/// Locations a loaded image may come from without raising suspicion: the OS (including the cryptex and
/// developer disk images) and Apple-signed system support.
NSArray<NSString *> *ISCTrustedSystemPrefixes(void);

/// Where non-cached OS code lives: the developer disk image and cryptexes. Deliberately not `/usr/lib/`
/// on a device: every genuine library there is in the shared cache, and rootful tweak loaders install
/// into it. The Simulator is different: it loads some of `/usr/lib/system/` from outside its cache.
NSArray<NSString *> *ISCTrustedCodePrefixes(void);

/// Whether `address` lies in code a system function may legitimately reach: the OS (shared cache, dyld,
/// developer and cryptex images), the app bundle, or a prefix the host trusts. `outImagePath` receives
/// the containing image, or nil for memory no image owns (a hook's trampoline page).
BOOL ISCAddressIsTrustedCode(const void *_Nullable address,
                             NSArray<NSString *> *extraTrustedPrefixes,
                             NSString *_Nullable *_Nonnull outImagePath);

/// `YES` when `function` starts with a branch into untrusted code. `outDestination` receives the
/// destination's image path, or nil for anonymous memory.
BOOL ISCFunctionIsInlineHooked(const void *_Nullable function,
                               NSArray<NSString *> *extraTrustedPrefixes,
                               NSString *_Nullable *_Nonnull outDestination);

/// The address of a method's implementation with any pointer-authentication signature removed.
const void *ISCMethodImplementationAddress(Method method);

/// The method `selector` resolves to on `cls`, or NULL.
Method _Nullable ISCResolveMethod(Class _Nullable cls, SEL _Nullable selector, BOOL isClassMethod);

NS_ASSUME_NONNULL_END
