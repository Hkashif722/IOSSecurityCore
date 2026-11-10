//
//  ISCIntegrityCheckerTests.m
//  IOSSecurityCoreObjCTests
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

@interface ISCIntegrityCheckerTests : XCTestCase
@end

@implementation ISCIntegrityCheckerTests

// MARK: - Code-signature parsing

- (void)testParsesEntitlementsFromAWellFormedSignature {
    NSDictionary *entitlements = @{
        @"application-identifier": @"ABCDE12345.com.example.app",
        @"com.apple.developer.team-identifier": @"ABCDE12345",
        @"get-task-allow": @NO,
        @"keychain-access-groups": @[@"ABCDE12345.com.example.app"],
    };
    NSDictionary *parsed = [ISCIntegrityChecker entitlementsFromCodeSignatureData:ISCMakeSignatureBlob(entitlements)];
    XCTAssertEqualObjects(parsed, entitlements);
}

- (void)testSignatureWithoutAnEntitlementsSlotYieldsNil {
    // A SuperBlob with one slot that is not the entitlements slot.
    uint32_t words[] = {CFSwapInt32HostToBig(0xfade0cc0), CFSwapInt32HostToBig(20),
                        CFSwapInt32HostToBig(1), CFSwapInt32HostToBig(0), CFSwapInt32HostToBig(20)};
    XCTAssertNil([ISCIntegrityChecker entitlementsFromCodeSignatureData:[NSData dataWithBytes:words length:sizeof(words)]]);
}

- (void)testEveryTruncationOfASignatureIsRejectedWithoutReadingOutOfBounds {
    NSData *blob = ISCMakeSignatureBlob(@{@"application-identifier": @"ABCDE12345.com.example.app"});
    for (NSUInteger length = 0; length < blob.length; length++) {
        // A fresh exact-size allocation, so AddressSanitizer flags any read past `length`.
        NSData *truncated = [NSData dataWithBytes:blob.bytes length:length];
        XCTAssertNil([ISCIntegrityChecker entitlementsFromCodeSignatureData:truncated], @"length %lu", (unsigned long)length);
    }
}

- (void)testMalformedHeadersAreRejected {
    NSData *valid = ISCMakeSignatureBlob(@{@"a": @"b"});

    void (^expectNilAfterPatching)(NSUInteger, uint32_t, NSString *) = ^(NSUInteger offset, uint32_t value, NSString *why) {
        NSMutableData *patched = [valid mutableCopy];
        uint32_t big = CFSwapInt32HostToBig(value);
        [patched replaceBytesInRange:NSMakeRange(offset, 4) withBytes:&big];
        XCTAssertNil([ISCIntegrityChecker entitlementsFromCodeSignatureData:patched], @"%@", why);
    };

    expectNilAfterPatching(0, 0xdeadbeef, @"wrong SuperBlob magic");
    expectNilAfterPatching(4, 0xffffffff, @"length larger than the data");
    expectNilAfterPatching(4, 4, @"length smaller than the header");
    expectNilAfterPatching(8, 0xffffffff, @"count that cannot fit");
    expectNilAfterPatching(8, 0x20000000, @"count that overflows 32-bit arithmetic");
    expectNilAfterPatching(12 + 8 + 4, 0xffffffff, @"entitlements offset beyond the blob");
    expectNilAfterPatching(12 + 8 + 4, 0xfffffffc, @"entitlements offset that overflows when 8 is added");

    // Entitlements blob header: magic, then length.
    NSUInteger blobOffset = 12 + 16 + 16;
    expectNilAfterPatching(blobOffset, 0x12345678, @"wrong entitlements magic");
    expectNilAfterPatching(blobOffset + 4, 0xffffffff, @"entitlements length beyond the blob");
    expectNilAfterPatching(blobOffset + 4, 4, @"entitlements length smaller than its own header");
}

- (void)testGarbageInsideTheEntitlementsSlotIsRejected {
    NSMutableData *blob = [ISCMakeSignatureBlob(@{@"a": @"b"}) mutableCopy];
    // Replace the XML payload (everything after the 8-byte blob header) with non-plist bytes.
    NSUInteger payloadOffset = 12 + 16 + 16 + 8;
    memset((uint8_t *)blob.mutableBytes + payloadOffset, 0xAB, blob.length - payloadOffset);
    XCTAssertNil([ISCIntegrityChecker entitlementsFromCodeSignatureData:blob]);
}

- (void)testAPropertyListThatIsNotADictionaryIsRejected {
    NSData *plist = [NSPropertyListSerialization dataWithPropertyList:@[@"not", @"a", @"dictionary"]
                                                               format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    NSMutableData *entitlementsBlob = [NSMutableData data];
    uint32_t header[2] = {CFSwapInt32HostToBig(0xfade7171), CFSwapInt32HostToBig((uint32_t)(8 + plist.length))};
    [entitlementsBlob appendBytes:header length:sizeof(header)];
    [entitlementsBlob appendData:plist];

    NSMutableData *blob = [NSMutableData data];
    uint32_t words[5] = {CFSwapInt32HostToBig(0xfade0cc0),
                         CFSwapInt32HostToBig((uint32_t)(20 + entitlementsBlob.length)),
                         CFSwapInt32HostToBig(1), CFSwapInt32HostToBig(5), CFSwapInt32HostToBig(20)};
    [blob appendBytes:words length:sizeof(words)];
    [blob appendData:entitlementsBlob];
    XCTAssertNil([ISCIntegrityChecker entitlementsFromCodeSignatureData:blob]);
}

- (void)testRandomlyMutatedSignaturesNeverCrash {
    NSData *valid = ISCMakeSignatureBlob(@{@"application-identifier": @"ABCDE12345.com.example.app",
                                           @"get-task-allow": @YES});
    // A fixed-seed generator keeps the run reproducible while still covering many shapes.
    __block uint64_t state = 0x9E3779B97F4A7C15ull;
    uint64_t (^next)(void) = ^uint64_t {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    };

    for (int round = 0; round < 3000; round++) {
        NSMutableData *mutated = [valid mutableCopy];
        int flips = 1 + (int)(next() % 6);
        for (int flip = 0; flip < flips; flip++) {
            ((uint8_t *)mutated.mutableBytes)[next() % mutated.length] = (uint8_t)next();
        }
        // Exact-size copy so out-of-bounds reads are visible to AddressSanitizer.
        NSData *input = [NSData dataWithBytes:mutated.bytes length:mutated.length];
        id result = [ISCIntegrityChecker entitlementsFromCodeSignatureData:input];
        XCTAssertTrue(result == nil || [result isKindOfClass:NSDictionary.class]);
    }
}

- (void)testEmptyAndTinyInputsAreRejected {
    XCTAssertNil([ISCIntegrityChecker entitlementsFromCodeSignatureData:[NSData data]]);
    XCTAssertNil([ISCIntegrityChecker entitlementsFromCodeSignatureData:[NSData dataWithBytes:"\xfa" length:1]]);
}

// MARK: - Team identifier

- (void)testTeamIdentifierPrefersTheExplicitEntitlement {
    NSDictionary *entitlements = @{@"com.apple.developer.team-identifier": @"TEAM000001",
                                   @"application-identifier": @"OTHER00002.com.example"};
    XCTAssertEqualObjects([ISCIntegrityChecker teamIdentifierFromEntitlements:entitlements], @"TEAM000001");
}

- (void)testTeamIdentifierFallsBackToTheApplicationIdentifierPrefix {
    XCTAssertEqualObjects([ISCIntegrityChecker teamIdentifierFromEntitlements:
                           @{@"application-identifier": @"ABCDE12345.com.example.app"}], @"ABCDE12345");
}

- (void)testTeamIdentifierRejectsUnusableValues {
    XCTAssertNil([ISCIntegrityChecker teamIdentifierFromEntitlements:nil]);
    XCTAssertNil([ISCIntegrityChecker teamIdentifierFromEntitlements:@{}]);
    XCTAssertNil([ISCIntegrityChecker teamIdentifierFromEntitlements:@{@"application-identifier": @".leading.dot"}]);
    XCTAssertNil([ISCIntegrityChecker teamIdentifierFromEntitlements:@{@"application-identifier": @"nodots"}]);
    XCTAssertNil([ISCIntegrityChecker teamIdentifierFromEntitlements:@{@"application-identifier": @42}]);
    XCTAssertNil([ISCIntegrityChecker teamIdentifierFromEntitlements:@{@"com.apple.developer.team-identifier": @""}]);
}

// MARK: - Text digest

- (void)testTextSegmentDigestIsLowercaseHexSHA256AndStable {
    NSString *first = ISCIntegrityChecker.textSegmentDigest;
    XCTAssertNotNil(first);
    XCTAssertEqual(first.length, 64u);
    NSCharacterSet *notHex = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
    XCTAssertEqual([first rangeOfCharacterFromSet:notHex].location, (NSUInteger)NSNotFound, @"%@", first);
    XCTAssertEqualObjects(ISCIntegrityChecker.textSegmentDigest, first, @"the digest of unchanged code must not change");
}

// MARK: - Scan

- (void)testNothingConfiguredMeansNothingChecked {
    XCTAssertEqual([ISCIntegrityChecker scanWithOptions:ISCTestOptions()].count, 0u);
}

- (void)testBundleIdentifierMismatchIsCritical {
    ISCScanOptions *options = ISCTestOptions();
    options.expectedBundleIdentifier = @"com.definitely.not.this.app";

    ISCFinding *finding = ISCFindingWithCode([ISCIntegrityChecker scanWithOptions:options],
                                             ISCFindingCodeIntegrityBundleIdentifierMismatch);
    XCTAssertNotNil(finding);
    XCTAssertEqual(finding.severity, ISCSeverityCritical);
    XCTAssertTrue([finding.detail containsString:@"com.definitely.not.this.app"]);
}

- (void)testMatchingBundleIdentifierIsClean {
    NSString *actual = NSBundle.mainBundle.bundleIdentifier;
    if (actual == nil) {
        XCTSkip(@"The test process has no bundle identifier.");
    }
    ISCScanOptions *options = ISCTestOptions();
    options.expectedBundleIdentifier = actual;
    XCTAssertEqual([ISCIntegrityChecker scanWithOptions:options].count, 0u);
}

- (void)testATeamMismatchIsNeverSilent {
    ISCScanOptions *options = ISCTestOptions();
    options.expectedTeamIdentifier = @"ZZZZZZZZZZ";
    NSArray<ISCFinding *> *findings = [ISCIntegrityChecker scanWithOptions:options];

    if (ISCIntegrityChecker.codeSigningTeamIdentifier != nil) {
        XCTAssertTrue(ISCContainsCode(findings, ISCFindingCodeIntegrityTeamIdentifierMismatch));
    } else {
        // Not being able to read the signature is reported, just more mildly than a proven mismatch.
        ISCFinding *finding = ISCFindingWithCode(findings, ISCFindingCodeIntegrityTeamIdentifierUnavailable);
        XCTAssertNotNil(finding);
        XCTAssertLessThan(finding.severity, ISCSeverityHigh);
    }
}

- (void)testMatchingTeamIdentifierIsCleanRegardlessOfCase {
    NSString *actual = ISCIntegrityChecker.codeSigningTeamIdentifier;
    if (actual == nil) {
        XCTSkip(@"The test process carries no readable Team ID.");
    }
    ISCScanOptions *options = ISCTestOptions();
    options.expectedTeamIdentifier = actual.lowercaseString;
    XCTAssertEqual([ISCIntegrityChecker scanWithOptions:options].count, 0u);
}

- (void)testUnexpectedTextDigestIsCriticalAndMatchingDigestIsClean {
    NSString *actual = ISCIntegrityChecker.textSegmentDigest;
    XCTAssertNotNil(actual);

    ISCScanOptions *options = ISCTestOptions();
    options.expectedTextSegmentDigests = @[[@"" stringByPaddingToLength:64 withString:@"0" startingAtIndex:0]];
    ISCFinding *finding = ISCFindingWithCode([ISCIntegrityChecker scanWithOptions:options],
                                             ISCFindingCodeIntegrityTextSegmentModified);
    XCTAssertNotNil(finding);
    XCTAssertEqual(finding.severity, ISCSeverityCritical);
    XCTAssertEqualObjects(finding.detail, actual, @"the finding carries the digest so it can be investigated");

    options.expectedTextSegmentDigests = @[@"00", actual.uppercaseString];
    XCTAssertEqual([ISCIntegrityChecker scanWithOptions:options].count, 0u, @"any listed digest is accepted, case-insensitively");
}

- (void)testAppStoreExpectationReportsNothingForAnArtifactThatLooksLikeAppStore {
    // The provisioning-profile check is the only App Store expectation the test process can control:
    // a test process has no embedded profile, so it must not be flagged for one.
    ISCScanOptions *options = ISCTestOptions();
    options.expectedDistribution = ISCDistributionAppStore;
    if (ISCIntegrityChecker.embeddedProvisioningProfile == nil) {
        XCTAssertFalse(ISCContainsCode([ISCIntegrityChecker scanWithOptions:options],
                                       ISCFindingCodeIntegrityUnexpectedProvisioningProfile));
    }
}

- (void)testDistributionChecksAreOffByDefault {
    ISCScanOptions *options = ISCTestOptions();
    NSArray<ISCFinding *> *findings = [ISCIntegrityChecker scanWithOptions:options];
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeIntegrityBinaryDecrypted));
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeIntegrityDebuggableBuild));
    XCTAssertFalse(ISCContainsCode(findings, ISCFindingCodeIntegrityUnexpectedProvisioningProfile));
}

// MARK: - Raw signals

- (void)testRawSignalsAreSafeToReadInAnyProcess {
    // None of these may crash, whatever the process is signed with.
    (void)ISCIntegrityChecker.codeSigningEntitlements;
    (void)ISCIntegrityChecker.codeSigningTeamIdentifier;
    (void)ISCIntegrityChecker.embeddedProvisioningProfile;
    ISCEncryptionState state = ISCIntegrityChecker.binaryEncryptionState;
    XCTAssertTrue(state == ISCEncryptionStateUnknown || state == ISCEncryptionStateDecrypted ||
                  state == ISCEncryptionStateEncrypted);
}

@end
