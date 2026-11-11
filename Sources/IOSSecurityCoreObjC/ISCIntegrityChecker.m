//
//  ISCIntegrityChecker.m
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import "ISCIntegrityChecker.h"
#import "ISCFindingSupport.h"
#import "ISCDEREntitlements.h"
#import "ISCDetector.h"
#import "ISCObfuscation.h"
#import "ISCRuntimeSupport.h"

#import <CommonCrypto/CommonDigest.h>

#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <string.h>

// MARK: - Constants

/// Code-signature container magic numbers and the slots that hold entitlements, XML (the historical
/// form) and DER (required since iOS 15). These are fixed by the on-disk format (big-endian on disk).
static const uint32_t ISCSuperBlobMagic = 0xfade0cc0;
static const uint32_t ISCEntitlementsBlobMagic = 0xfade7171;
static const uint32_t ISCEntitlementsSlot = 5;
static const uint32_t ISCDEREntitlementsBlobMagic = 0xfade7172;
static const uint32_t ISCDEREntitlementsSlot = 7;

/// Sanity limits: real signatures are kilobytes. Anything bigger is corrupt, and a limit keeps a
/// malformed one from making us copy or parse megabytes.
static const uint64_t ISCMaximumSignatureSize = 16u * 1024 * 1024;
static const uint64_t ISCMaximumPropertyListSize = 1u * 1024 * 1024;

/// Bytes hashed per `CC_SHA256_Update` call. `CC_LONG` is 32-bit, so large sections are fed in pieces.
static const size_t ISCDigestChunkSize = 1u << 20;

// MARK: - Mach-O access

typedef struct {
    const struct mach_header_64 *header;
    intptr_t slide;
} ISCMainImage;

/// The main executable's header and ASLR slide. dyld lists it first, but searching by file type does
/// not depend on that.
static BOOL ISCLocateMainImage(ISCMainImage *image) {
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const struct mach_header *header = _dyld_get_image_header(index);
        if (header != NULL && header->magic == MH_MAGIC_64 && header->filetype == MH_EXECUTE) {
            image->header = (const struct mach_header_64 *)header;
            image->slide = _dyld_get_image_vmaddr_slide(index);
            return YES;
        }
    }
    return NO;
}

/// The header of the first loaded 64-bit image whose path ends in the path components `name`, preferring
/// images inside the app bundle so an embedded `Auth.framework/Auth` wins over anything else.
static const struct mach_header_64 *ISCLocateImageNamed(NSString *name) {
    if (name.length == 0) {
        return NULL;
    }
    NSArray<NSString *> *bundleRoots = ISCAppBundleRoots();
    const struct mach_header_64 *outsideBundle = NULL;
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const char *cPath = _dyld_get_image_name(index);
        const struct mach_header *header = _dyld_get_image_header(index);
        if (cPath == NULL || header == NULL || header->magic != MH_MAGIC_64) {
            continue;
        }
        NSString *path = [NSString stringWithUTF8String:cPath];
        if (path == nil || !ISCPathHasComponentSuffix(path, name)) {
            continue;
        }
        if (ISCPathMatchesAnyPrefix(path, bundleRoots)) {
            return (const struct mach_header_64 *)header;
        }
        if (outsideBundle == NULL) {
            outsideBundle = (const struct mach_header_64 *)header;
        }
    }
    return outsideBundle;
}

/// Lowercase hex SHA-256 of `__TEXT,__text` in the loaded image at `header`, or nil.
static NSString *ISCTextDigestOfImage(const struct mach_header_64 *header) {
    if (header == NULL) {
        return nil;
    }
    unsigned long size = 0;
    const uint8_t *text = getsectiondata(header, SEG_TEXT, SECT_TEXT, &size);
    if (text == NULL || size == 0) {
        return nil;
    }

    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    size_t remaining = size;
    while (remaining > 0) {
        size_t chunk = remaining < ISCDigestChunkSize ? remaining : ISCDigestChunkSize;
        CC_SHA256_Update(&context, text, (CC_LONG)chunk);
        text += chunk;
        remaining -= chunk;
    }
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);

    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) {
        [hex appendFormat:@"%02x", digest[index]];
    }
    return hex;
}

/// Whether `digest` is one of `expected` (case-insensitive). Non-string entries are ignored.
static BOOL ISCDigestIsExpected(NSString *digest, NSArray *expected) {
    for (id candidate in expected) {
        if ([candidate isKindOfClass:NSString.class] && [candidate caseInsensitiveCompare:digest] == NSOrderedSame) {
            return YES;
        }
    }
    return NO;
}

/// Calls `visit` for each load command, stopping at the first malformed one.
static void ISCEnumerateLoadCommands(const struct mach_header_64 *header,
                                     void (^visit)(const struct load_command *command)) {
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *end = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) {
            return;
        }
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command) || command->cmdsize > (size_t)(end - cursor)) {
            return;
        }
        visit(command);
        cursor += command->cmdsize;
    }
}

/// The raw code-signature blob of the main executable, copied out of its (read-only) `__LINKEDIT`
/// segment. The kernel verified this signature when it mapped the binary.
static NSData *ISCCopyMainExecutableSignature(void) {
    ISCMainImage image;
    if (!ISCLocateMainImage(&image)) {
        return nil;
    }

    __block const struct linkedit_data_command *signatureCommand = NULL;
    __block const struct segment_command_64 *linkedit = NULL;
    ISCEnumerateLoadCommands(image.header, ^(const struct load_command *command) {
        if (command->cmd == LC_CODE_SIGNATURE && command->cmdsize >= sizeof(struct linkedit_data_command)) {
            signatureCommand = (const struct linkedit_data_command *)command;
        } else if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, SEG_LINKEDIT, sizeof(segment->segname)) == 0) {
                linkedit = segment;
            }
        }
    });
    if (signatureCommand == NULL || linkedit == NULL) {
        return nil;
    }

    // dataoff is a file offset. Translate it to memory through __LINKEDIT, checking every step.
    uint64_t dataOffset = signatureCommand->dataoff;
    uint64_t dataSize = signatureCommand->datasize;
    if (dataSize == 0 || dataSize > ISCMaximumSignatureSize) {
        return nil;
    }
    if (dataOffset < linkedit->fileoff) {
        return nil;
    }
    uint64_t offsetInSegment = dataOffset - linkedit->fileoff;
    if (offsetInSegment > linkedit->filesize || dataSize > linkedit->filesize - offsetInSegment) {
        return nil;
    }

    uint64_t address = (uint64_t)((int64_t)linkedit->vmaddr + (int64_t)offsetInSegment + (int64_t)image.slide);
    return [NSData dataWithBytes:(const void *)(uintptr_t)address length:(NSUInteger)dataSize];
}

// MARK: - Code-signature parsing

static inline uint32_t ISCReadBigEndian32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

/// Parses a property list that must be a dictionary.
static NSDictionary<NSString *, id> *ISCDictionaryFromPropertyListData(NSData *data) {
    if (data.length == 0 || data.length > ISCMaximumPropertyListSize) {
        return nil;
    }
    id object = [NSPropertyListSerialization propertyListWithData:data
                                                          options:NSPropertyListImmutable
                                                           format:NULL
                                                            error:NULL];
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

// MARK: - Cached, immutable signals

static NSDictionary<NSString *, id> *ISCMainExecutableEntitlements(void) {
    static NSDictionary<NSString *, id> *entitlements;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSData *signature = ISCCopyMainExecutableSignature();
        if (signature != nil) {
            entitlements = [ISCIntegrityChecker entitlementsFromCodeSignatureData:signature];
        }
    });
    return entitlements;
}

/// Where the embedded provisioning profile would be. Nil for App Store and TestFlight builds.
static NSString *ISCEmbeddedProvisioningProfilePath(void) {
    return [NSBundle.mainBundle pathForResource:@"embedded" ofType:@"mobileprovision"];
}

/// The Team ID an entitlements dictionary names: `com.apple.developer.team-identifier`, or the part of
/// `application-identifier` before the first dot.
static NSString *ISCTeamIdentifierFromEntitlements(NSDictionary<NSString *, id> *entitlements) {
    id team = entitlements[@"com.apple.developer.team-identifier"];
    if ([team isKindOfClass:NSString.class] && [team length] > 0) {
        return team;
    }
    // "TEAMID.com.example.App": the Team ID is everything before the first dot.
    id applicationIdentifier = entitlements[@"application-identifier"];
    if ([applicationIdentifier isKindOfClass:NSString.class]) {
        NSRange dot = [applicationIdentifier rangeOfString:@"."];
        if (dot.location != NSNotFound && dot.location > 0) {
            return [applicationIdentifier substringToIndex:dot.location];
        }
    }
    return nil;
}

/// Whether the main executable's code is FairPlay-encrypted (`cryptid` in `LC_ENCRYPTION_INFO_64`).
static ISCEncryptionState ISCMainBinaryEncryptionState(void) {
    ISCMainImage image;
    if (!ISCLocateMainImage(&image)) {
        return ISCEncryptionStateUnknown;
    }
    __block ISCEncryptionState state = ISCEncryptionStateUnknown;
    ISCEnumerateLoadCommands(image.header, ^(const struct load_command *command) {
        if (command->cmd == LC_ENCRYPTION_INFO_64 && command->cmdsize >= sizeof(struct encryption_info_command_64)) {
            const struct encryption_info_command_64 *encryption = (const struct encryption_info_command_64 *)command;
            state = encryption->cryptid != 0 ? ISCEncryptionStateEncrypted : ISCEncryptionStateDecrypted;
        }
    });
    return state;
}

/// Lowercase hex SHA-256 of the main executable's `__TEXT,__text`, or nil.
static NSString *ISCMainTextDigest(void) {
    ISCMainImage image;
    if (!ISCLocateMainImage(&image)) {
        return nil;
    }
    return ISCTextDigestOfImage(image.header);
}

// MARK: - ISCIntegrityChecker

@implementation ISCIntegrityChecker

// MARK: Raw signals

+ (NSDictionary<NSString *, id> *)codeSigningEntitlements {
    return ISCMainExecutableEntitlements();
}

+ (NSString *)codeSigningTeamIdentifier {
    return ISCTeamIdentifierFromEntitlements(ISCMainExecutableEntitlements());
}

+ (NSString *)teamIdentifierFromEntitlements:(NSDictionary<NSString *, id> *)entitlements {
    return ISCTeamIdentifierFromEntitlements(entitlements);
}

+ (ISCEncryptionState)binaryEncryptionState {
    return ISCMainBinaryEncryptionState();
}

+ (BOOL)hasEmbeddedProvisioningProfile {
    return ISCEmbeddedProvisioningProfilePath() != nil;
}

+ (NSDictionary<NSString *, id> *)embeddedProvisioningProfile {
    NSString *path = ISCEmbeddedProvisioningProfilePath();
    if (path == nil) {
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:NULL];
    if (data.length == 0 || data.length > ISCMaximumPropertyListSize) {
        return nil;
    }

    // The profile is a CMS envelope around an XML property list. Cut the plist out instead of
    // verifying the envelope: the kernel already verified the app, this only reads metadata.
    NSData *startMarker = [@"<?xml" dataUsingEncoding:NSASCIIStringEncoding];
    NSData *endMarker = [@"</plist>" dataUsingEncoding:NSASCIIStringEncoding];
    NSRange start = [data rangeOfData:startMarker options:0 range:NSMakeRange(0, data.length)];
    if (start.location == NSNotFound) {
        return nil;
    }
    NSRange end = [data rangeOfData:endMarker
                            options:0
                              range:NSMakeRange(start.location, data.length - start.location)];
    if (end.location == NSNotFound) {
        return nil;
    }
    return ISCDictionaryFromPropertyListData(
        [data subdataWithRange:NSMakeRange(start.location, NSMaxRange(end) - start.location)]);
}

+ (NSString *)textSegmentDigest {
    return ISCMainTextDigest();
}

+ (NSString *)textSegmentDigestOfImageNamed:(NSString *)name {
    return ISCTextDigestOfImage(ISCLocateImageNamed(name));
}

/// Finds the payload of the blob in `slot`, if that blob carries `magic` and lies inside the SuperBlob
/// (whose header has already been validated). The payload is at most `ISCMaximumPropertyListSize`.
static BOOL ISCLocateBlobPayload(const uint8_t *bytes, uint64_t superLength, uint32_t slot, uint32_t magic,
                                 const uint8_t **outPayload, size_t *outLength) {
    uint64_t count = ISCReadBigEndian32(bytes + 8);
    for (uint64_t index = 0; index < count; index++) {
        const uint8_t *entry = bytes + 12 + index * 8;
        if (ISCReadBigEndian32(entry) != slot) {
            continue;
        }
        uint64_t offset = ISCReadBigEndian32(entry + 4);
        if (offset > superLength || superLength - offset < 8) {
            continue;
        }
        const uint8_t *blob = bytes + offset;
        uint64_t blobLength = ISCReadBigEndian32(blob + 4);
        if (ISCReadBigEndian32(blob) != magic || blobLength < 8 || blobLength > superLength - offset ||
            blobLength - 8 > ISCMaximumPropertyListSize) {
            continue;
        }
        *outPayload = blob + 8;
        *outLength = (size_t)(blobLength - 8);
        return YES;
    }
    return NO;
}

+ (NSDictionary<NSString *, id> *)entitlementsFromCodeSignatureData:(NSData *)data {
    const uint8_t *bytes = data.bytes;
    uint64_t length = data.length;

    // Layout (all big-endian): SuperBlob { magic, length, count, count x { type, offset } }, where each
    // offset points at a blob { magic, length, payload } inside the SuperBlob.
    if (bytes == NULL || length < 12 || ISCReadBigEndian32(bytes) != ISCSuperBlobMagic) {
        return nil;
    }
    uint64_t superLength = ISCReadBigEndian32(bytes + 4);
    uint64_t count = ISCReadBigEndian32(bytes + 8);
    if (superLength < 12 || superLength > length || count > (superLength - 12) / 8) {
        return nil;
    }

    // XML first: the slot every signature has carried for years. DER is the fallback, so the day Apple
    // stops emitting the XML slot nothing changes for callers.
    const uint8_t *payload = NULL;
    size_t payloadLength = 0;
    if (ISCLocateBlobPayload(bytes, superLength, ISCEntitlementsSlot, ISCEntitlementsBlobMagic, &payload, &payloadLength)) {
        NSDictionary<NSString *, id> *xml = ISCDictionaryFromPropertyListData([NSData dataWithBytes:payload length:payloadLength]);
        if (xml != nil) {
            return xml;
        }
    }
    if (ISCLocateBlobPayload(bytes, superLength, ISCDEREntitlementsSlot, ISCDEREntitlementsBlobMagic, &payload, &payloadLength)) {
        return ISCDictionaryFromDEREntitlements(payload, payloadLength);
    }
    return nil;
}

// MARK: Scan

NSArray<ISCFinding *> *ISCIntegrityScan(ISCScanOptions *options) {
    if (!ISCChecksInclude(options, ISCChecksIntegrity)) {
        return @[];
    }
    NSMutableArray<ISCFinding *> *findings = [NSMutableArray array];

    // 1. Bundle identifier: a re-signer who cannot reuse yours must change it.
    NSString *expectedBundleIdentifier = options.expectedBundleIdentifier;
    if (expectedBundleIdentifier.length > 0) {
        NSString *actual = NSBundle.mainBundle.bundleIdentifier;
        if (![actual isEqualToString:expectedBundleIdentifier]) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityBundleIdentifierMismatch, [NSString stringWithFormat:@"expected %@, found %@", expectedBundleIdentifier, actual != nil ? actual : @"none"])];
        }
    }

    // 2. Team ID from the code signature: a re-signer cannot reuse yours.
    NSString *expectedTeamIdentifier = options.expectedTeamIdentifier;
    if (expectedTeamIdentifier.length > 0) {
        NSString *actual = ISCTeamIdentifierFromEntitlements(ISCMainExecutableEntitlements());
        if (actual == nil) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityTeamIdentifierUnavailable, nil)];
        } else if ([actual caseInsensitiveCompare:expectedTeamIdentifier] != NSOrderedSame) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityTeamIdentifierMismatch, [NSString stringWithFormat:@"expected %@, found %@", expectedTeamIdentifier, actual])];
        }
    }

    // 3. App Store and TestFlight builds look a specific way; copies that were re-signed or dumped do not.
    if (options.expectedDistribution == ISCDistributionAppStore) {
        // Presence is the signal. A profile that fails to parse is still a profile App Store builds do not have.
        if (ISCEmbeddedProvisioningProfilePath() != nil) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityUnexpectedProvisioningProfile, nil)];
        }
        if (ISCMainBinaryEncryptionState() == ISCEncryptionStateDecrypted) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityBinaryDecrypted, nil)];
        }
        id getTaskAllow = ISCMainExecutableEntitlements()[@"get-task-allow"];
        if ([getTaskAllow isKindOfClass:NSNumber.class] && [getTaskAllow boolValue]) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityDebuggableBuild, nil)];
        }
    }

    // 4. The code itself.
    if (options.expectedTextSegmentDigests.count > 0) {
        NSString *digest = ISCMainTextDigest();
        if (digest == nil) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityTextSegmentUnavailable, nil)];
        } else if (!ISCDigestIsExpected(digest, options.expectedTextSegmentDigests)) {
            [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityTextSegmentModified, digest)];
        }
    }

    // 5. The code of embedded libraries.
    NSMutableArray<NSString *> *modified = [NSMutableArray array];
    NSMutableArray<NSString *> *unavailable = [NSMutableArray array];
    NSDictionary *imageDigests = options.expectedImageTextDigests;
    // Configuration comes from the host app: skip anything malformed instead of raising.
    NSMutableArray<NSString *> *names = [NSMutableArray array];
    for (id name in imageDigests) {
        id expected = imageDigests[name];
        if ([name isKindOfClass:NSString.class] && [name length] > 0 &&
            [expected isKindOfClass:NSArray.class] && [expected count] > 0) {
            [names addObject:name];
        }
    }
    [names sortUsingSelector:@selector(compare:)];
    for (NSString *name in names) {
        NSArray *expected = imageDigests[name];
        NSString *digest = ISCTextDigestOfImage(ISCLocateImageNamed(name));
        if (digest == nil) {
            [unavailable addObject:name];
        } else if (!ISCDigestIsExpected(digest, expected)) {
            [modified addObject:[NSString stringWithFormat:@"%@: %@", name, digest]];
        }
    }
    if (modified.count > 0) {
        [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityImageModified, ISCSummarizeValues(modified, ISCDetailLimit))];
    }
    if (unavailable.count > 0) {
        [findings addObject:ISCMakeFinding(ISCFindingCodeIntegrityImageUnavailable, ISCSummarizeValues(unavailable, ISCDetailLimit))];
    }

    return findings;
}

+ (NSArray<ISCFinding *> *)scanWithOptions:(ISCScanOptions *)options {
    return ISCIntegrityScan(options);
}

@end
