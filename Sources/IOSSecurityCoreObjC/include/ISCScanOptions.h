//
//  ISCScanOptions.h
//  IOSSecurityCoreObjC
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

/// When `NO`, the built-in lists (jailbreak paths, hooking-framework names, ...) are ignored and only
/// the custom entries below are examined. Intended for tests. Default: `YES`.
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
/// is the effective defence against a repackaged app with an injected dylib. Default: empty (off).
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

/// How the app is distributed. Default: `ISCDistributionAny`.
@property (nonatomic) ISCDistribution expectedDistribution;

@end

NS_ASSUME_NONNULL_END
