//
//  ISCScanOptions.h
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Everything that tunes a scan.
//

#import <Foundation/Foundation.h>
#import "ISCTypes.h"
#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

/// An Objective-C method whose implementation must stay inside a known set of images.
///
/// If a tweak or instrumentation framework swizzles the method (`method_setImplementation`,
/// `MSHookMessageEx`, Frida's `ObjC.implement`, ...), the implementation pointer moves into the
/// attacker's image and the scan reports `ISCFindingCodeHookSwizzledMethod`.
ISC_RN_PROTECTED_METHOD
@interface ISCProtectedMethod : NSObject <NSCopying>

/// The class that declares the method, as accepted by `NSClassFromString`.
@property (nonatomic, copy, readonly) NSString *targetClassName;

/// The selector, for example `isUserAuthenticated` or `validateToken:`.
@property (nonatomic, copy, readonly) NSString *selectorName;

/// `YES` for a class method (`+`), `NO` for an instance method (`-`).
@property (nonatomic, readonly) BOOL isClassMethod;

/// Path prefixes the implementation is allowed to live under. When empty, the app bundle (and, for
/// app extensions, the containing app bundle) is used. For system classes pass `/System/` and
/// `/usr/lib/`.
@property (nonatomic, copy, readonly) NSArray<NSString *> *allowedImagePathPrefixes;

- (instancetype)initWithTargetClassName:(NSString *)targetClassName
                           selectorName:(NSString *)selectorName
                          isClassMethod:(BOOL)isClassMethod
               allowedImagePathPrefixes:(NSArray<NSString *> *)allowedImagePathPrefixes
    NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

/// Configuration for one scan. Copy it before mutating if it is shared between threads.
ISC_RN_SCAN_OPTIONS
@interface ISCScanOptions : NSObject <NSCopying>

/// Options with every default applied.
+ (instancetype)defaultOptions;

// MARK: General

/// The detector families to run. Default: `ISCChecksAll`.
@property (nonatomic) ISCChecks checks;

/// When `NO`, the built-in lists and heuristics (jailbreak paths, hooking-framework names, the
/// parent-process check, the system-function verification, ...) are skipped and only the custom
/// entries below are examined. Intended for tests. Default: `YES`.
@property (nonatomic) BOOL includesBuiltInIndicators;

/// When `YES`, checks also run on the Simulator, on macOS and under Mac Catalyst, where results are
/// not meaningful (the Simulator exposes the Mac's file system, for example). Intended for tests and
/// tooling. Default: `NO`.
@property (nonatomic) BOOL scansUnsupportedEnvironments;

// MARK: Jailbreak

/// Extra file-system paths whose presence indicates a compromised device.
@property (nonatomic, copy) NSArray<NSString *> *additionalSuspiciousPaths;

/// Try to create a file outside the app sandbox. Succeeds only when the sandbox is broken. The file
/// is removed immediately. Default: `YES`.
@property (nonatomic) BOOL performsSandboxWriteProbe;

/// Call `fork()`. It fails inside a stock iOS sandbox and succeeds on devices with a weakened one; a
/// successful child exits immediately and is reaped. Default: `YES`.
@property (nonatomic) BOOL performsForkProbe;

/// Extra Objective-C class names that only a jailbreak-detection bypass tool or tweak registers. A
/// tweak can hide its library from the loaded-image list and its files from `access(2)`, but its
/// classes stay registered with the runtime. Reported as `ISCFindingCodeJailbreakBypassTool`.
@property (nonatomic, copy) NSArray<NSString *> *additionalSuspiciousClasses;

/// Probe the loopback interface for an SSH server (port 22) or checkra1n's shell (port 44). Nothing
/// listens there on a stock device. Never leaves the device. Default: `YES`.
@property (nonatomic) BOOL probesRemoteShellPorts;

// MARK: Hooking

/// Extra substrings; a loaded image whose path contains one of them (case-insensitive) is reported as
/// an instrumentation library.
@property (nonatomic, copy) NSArray<NSString *> *additionalSuspiciousLibraries;

/// Extra path prefixes that count as trusted when looking for unknown images, on top of the system
/// locations and the app bundle.
@property (nonatomic, copy) NSArray<NSString *> *allowedImagePathPrefixes;

/// Report images that live outside the system locations and the app bundle. Default: `YES`.
@property (nonatomic) BOOL reportsUnknownLibraries;

/// File names (for example `Auth.framework/Auth`, `libFoo.dylib`) of every dynamic library you embed
/// in the app bundle. When non-empty, any other image loaded from inside the bundle is reported. This
/// is the effective defence against a repackaged app with an injected dylib. The list also narrows the
/// system-function check: a system function bound to, or branching into, a bundle image not listed here is
/// reported. Without a list, every bundle image is trusted there. Default: empty (off).
@property (nonatomic, copy) NSArray<NSString *> *allowedBundleLibraries;

/// Probe the loopback interface for a listening `frida-server`. Never leaves the device. Default: `YES`.
@property (nonatomic) BOOL probesInstrumentationPorts;

/// Methods whose implementations must not move. See `ISCProtectedMethod`.
@property (nonatomic, copy) NSArray<ISCProtectedMethod *> *protectedMethods;

// MARK: Integrity

/// The bundle identifier the app must ship with. A mismatch means the app was re-signed or repackaged.
@property (nonatomic, copy, nullable) NSString *expectedBundleIdentifier;

/// The Apple developer Team ID the app must be signed with, read from the code signature.
@property (nonatomic, copy, nullable) NSString *expectedTeamIdentifier;

/// Lowercase hex SHA-256 digests of the release binary's `__TEXT,__text` section. A running binary
/// whose digest is not in this list was modified. Computing the digest touches every page of the
/// code section, so enable this only for release builds. Default: empty (off).
@property (nonatomic, copy) NSArray<NSString *> *expectedTextSegmentDigests;

/// Expected `__TEXT,__text` digests of embedded dynamic libraries, keyed by the library's trailing
/// path components (for example `Auth.framework/Auth`), each mapped to its accepted lowercase hex
/// SHA-256 digests. Images inside the app bundle are matched first. Compute the values with
/// `Scripts/text-digest.swift` or `+[ISCIntegrityChecker textSegmentDigestOfImageNamed:]`.
/// Default: empty (off).
@property (nonatomic, copy) NSDictionary<NSString *, NSArray<NSString *> *> *expectedImageTextDigests;

/// How the app is distributed. Default: `ISCDistributionAny`.
@property (nonatomic) ISCDistribution expectedDistribution;

@end

NS_ASSUME_NONNULL_END
