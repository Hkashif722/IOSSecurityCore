//
//  ISCIntegrityChecker.h
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Detects a repackaged, re-signed, cracked or patched app.
//

#import <Foundation/Foundation.h>
#import "ISCFinding.h"
#import "ISCScanOptions.h"
#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

/// Verifies that the running app is the one you shipped.
///
/// iOS refuses to run a modified binary unless the device's code-signing enforcement is disabled, so
/// the realistic attacks are re-signing (a different Team ID or bundle identifier), decrypting the
/// App Store binary, and patching on a device with enforcement off. The checks, all opt-in through
/// `ISCScanOptions` except where noted:
/// 1. Bundle identifier against `expectedBundleIdentifier`.
/// 2. Team ID, read from the entitlements inside the app's own code signature, against
///    `expectedTeamIdentifier`.
/// 3. With `ISCDistributionAppStore`: no embedded provisioning profile, an encrypted binary, and no
///    `get-task-allow` entitlement.
/// 4. The SHA-256 of the `__TEXT,__text` section against `expectedTextSegmentDigests`.
/// 5. The same for embedded dynamic libraries, against `expectedImageTextDigests`.
///
/// The raw signals are also exposed, so you can send them to a server and decide there. A decision made
/// on a server cannot be patched out of the app.
///
/// All methods are thread-safe and synchronous. Do not call them on the main thread.
ISC_RN_INTEGRITY_CHECKER
@interface ISCIntegrityChecker : NSObject

/// Runs the integrity checks enabled in `options` and returns what they found.
+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options;

// MARK: Raw signals

/// Lowercase hex SHA-256 of the main executable's `__TEXT,__text` section, or `nil` if it cannot be
/// read. Compare with the value `Scripts/text-digest.swift` prints for your release binary.
///
/// This reads the whole code section, which pages in (and, for App Store builds, decrypts) the entire
/// binary. Call it at most once per launch, on a background queue.
@property (class, nonatomic, readonly, nullable) NSString *textSegmentDigest;

/// Lowercase hex SHA-256 of the `__TEXT,__text` section of a loaded library, or `nil` if no loaded
/// library's path ends in the path components `name` (for example `Auth.framework/Auth`) or its code
/// cannot be read. Libraries inside the app bundle are preferred. Same cost caveats as
/// `textSegmentDigest`.
+ (nullable NSString *)textSegmentDigestOfImageNamed:(NSString *)name;

/// The entitlements embedded in the main executable's code signature, or `nil` if there are none or
/// they cannot be read. The kernel validated this signature when it loaded the binary.
@property (class, nonatomic, readonly, nullable) NSDictionary<NSString *, id> *codeSigningEntitlements;

/// The Apple developer Team ID the main executable is signed with (from the signature's
/// `com.apple.developer.team-identifier`, or the prefix of `application-identifier`), or `nil`.
@property (class, nonatomic, readonly, nullable) NSString *codeSigningTeamIdentifier;

/// Whether the main executable is FairPlay-encrypted.
@property (class, nonatomic, readonly) ISCEncryptionState binaryEncryptionState;

/// Whether the app bundle contains an `embedded.mobileprovision`. App Store and TestFlight builds have
/// none; development, ad hoc and enterprise builds do. This is the signal the App Store expectation uses,
/// so a profile that is present but unreadable still counts.
@property (class, nonatomic, readonly) BOOL hasEmbeddedProvisioningProfile;

/// The contents of `embedded.mobileprovision`, or `nil` when the app has none or it cannot be parsed.
/// Use `hasEmbeddedProvisioningProfile` to ask only whether one exists.
@property (class, nonatomic, readonly, nullable) NSDictionary<NSString *, id> *embeddedProvisioningProfile;

/// Parses the entitlements out of a raw code-signature blob (the data `LC_CODE_SIGNATURE` points to).
/// Reads the XML entitlements slot, and falls back to the DER slot Apple has required since iOS 15, so
/// the result survives the XML slot being dropped. Returns `nil` for anything that is not a well-formed
/// signature carrying entitlements in either form. Never reads out of bounds, whatever the input.
+ (nullable NSDictionary<NSString *, id> *)entitlementsFromCodeSignatureData:(NSData *)data;

/// The Team ID named by an entitlements dictionary: `com.apple.developer.team-identifier` if present,
/// otherwise the part of `application-identifier` before the first dot. `nil` if neither is usable.
+ (nullable NSString *)teamIdentifierFromEntitlements:(nullable NSDictionary<NSString *, id> *)entitlements;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
