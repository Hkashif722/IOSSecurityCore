//
//  ISCHookDetector.h
//  IOSSecurityCoreObjC
//
//  Detects dynamic instrumentation and runtime manipulation.
//

#import <Foundation/Foundation.h>
#import "ISCFinding.h"
#import "ISCScanOptions.h"
#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

/// Detects hooking frameworks and runtime tampering using `<objc/runtime.h>`, `<dlfcn.h>` and dyld.
///
/// The checks, in order:
/// 1. **Self-integrity**: this package's own detector methods must still be implemented inside the
///    image that contains them. A swizzled detector is the first thing an attacker does.
/// 2. **Instrumentation libraries**: Frida, Cycript, SSL Kill Switch and similar in the loaded-image list.
/// 3. **Instrumentation artifacts**: `frida-server` on disk, and a listener on its default loopback port.
/// 4. **Instrumentation threads**: the worker threads Frida's agent starts.
/// 5. **Unknown images**: libraries outside the system locations and the app bundle.
/// 6. **Unexpected bundle libraries**: dylibs injected into a repackaged app (needs `allowedBundleLibraries`).
/// 7. **Protected methods**: swizzled implementations of the methods you register.
///
/// All methods are thread-safe and synchronous. Do not call them on the main thread.
ISC_RN_HOOK_DETECTOR
@interface ISCHookDetector : NSObject

/// Runs the hooking checks enabled in `options` and returns what they found.
+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options;

/// Checks only the given protected methods and returns one finding per method that moved (or cannot
/// be resolved).
+ (NSArray<ISCFinding *> *)verifyProtectedMethods:(NSArray<ISCProtectedMethod *> *)methods;

/// The path of every image dyld has loaded into this process, in load order.
+ (NSArray<NSString *> *)loadedImagePaths;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
