//
//  ISCJailbreakDetector.h
//  IOSSecurityCoreObjC
//
//  Detects a jailbroken or sandbox-weakened device.
//

#import <Foundation/Foundation.h>
#import "ISCFinding.h"
#import "ISCScanOptions.h"
#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

/// Looks for the footprints jailbreaks leave behind. Every check uses documented APIs only.
///
/// The checks, in order:
/// 1. Known jailbreak files and directories (Cydia, Sileo, Zebra, `/var/jb`, MobileSubstrate, sshd, ...).
/// 2. System directories that are symbolic links on jailbroken devices.
/// 3. Injection through `DYLD_INSERT_LIBRARIES`.
/// 4. Loaded tweak-injection libraries (Substrate, Substitute, libhooker, ElleKit, ...).
/// 5. A write outside the app sandbox, which only succeeds when the sandbox is broken.
/// 6. `fork()`, which only succeeds when the sandbox is weakened.
///
/// Modern rootless jailbreaks and bypass tweaks can defeat any single client-side check, so treat the
/// result as a risk signal and combine it with server-side verification (for example App Attest).
///
/// All methods are thread-safe and synchronous. Do not call them on the main thread.
ISC_RN_JAILBREAK_DETECTOR
@interface ISCJailbreakDetector : NSObject

/// Runs the jailbreak checks enabled in `options` and returns what they found.
+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options;

/// The subset of `paths` that exist on this device. Uses `access(2)` and `open(2)`; the `stat` family
/// is deliberately avoided because Apple classifies it as a "required reason" API.
+ (NSArray<NSString *> *)existingPathsAmong:(NSArray<NSString *> *)paths;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
