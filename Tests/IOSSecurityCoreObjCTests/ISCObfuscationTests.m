//
//  ISCObfuscationTests.m
//  IOSSecurityCoreObjCTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

#import <XCTest/XCTest.h>
#import "ISCTestSupport.h"

@interface ISCObfuscationTests : XCTestCase
@end

@implementation ISCObfuscationTests

- (void)testNSStringMacroDecodesLiteral {
    XCTAssertEqualObjects(ISC_OBF_NSSTRING("/Applications/Cydia.app"), @"/Applications/Cydia.app");
}

- (void)testNSStringMacroHandlesEmptyAndSingleCharacterLiterals {
    XCTAssertEqualObjects(ISC_OBF_NSSTRING(""), @"");
    XCTAssertEqualObjects(ISC_OBF_NSSTRING("x"), @"x");
}

- (void)testNSStringMacroHandlesMaximumLengthLiteral {
    // Exactly ISC_OBF_MAX_LENGTH (64) characters.
    NSString *expected = @"0123456789012345678901234567890123456789012345678901234567890123";
    XCTAssertEqual(expected.length, (NSUInteger)ISC_OBF_MAX_LENGTH);
    XCTAssertEqualObjects(ISC_OBF_NSSTRING("0123456789012345678901234567890123456789012345678901234567890123"), expected);
}

- (void)testNSStringMacroPreservesUTF8Escapes {
    XCTAssertEqualObjects(ISC_OBF_NSSTRING("caf\xC3\xA9"), @"café");
}

- (void)testCStringMacroDecodesAndWipes {
    ISC_OBF_CSTRING(buffer, "ptrace");
    XCTAssertEqual(strcmp(buffer, "ptrace"), 0);
    XCTAssertEqual(sizeof(buffer), strlen("ptrace") + 1);

    ISC_OBF_WIPE(buffer);
    for (size_t index = 0; index < sizeof(buffer); index++) {
        XCTAssertEqual(buffer[index], 0, @"byte %zu survived the wipe", index);
    }
}

- (void)testTwoUsesOfTheSameLiteralBothDecode {
    // Each expansion has its own key; both must still round-trip.
    NSString *first = ISC_OBF_NSSTRING("frida-server");
    NSString *second = ISC_OBF_NSSTRING("frida-server");
    XCTAssertEqualObjects(first, @"frida-server");
    XCTAssertEqualObjects(second, @"frida-server");
}

- (void)testRuntimeFunctionsRoundTripArbitraryBytes {
    const uint8_t plain[] = {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, 'a', 'z'};
    uint8_t encoded[sizeof(plain)];
    char scratch[sizeof(plain) + 1];

    for (unsigned key = 0; key < 256; key += 17) {
        // The mask is its own inverse: applying it twice restores the input.
        ISCDeobfuscateBytes(plain, sizeof(plain), (uint8_t)key, scratch);
        memcpy(encoded, scratch, sizeof(encoded));
        char restored[sizeof(plain) + 1];
        ISCDeobfuscateBytes(encoded, sizeof(encoded), (uint8_t)key, restored);
        XCTAssertEqual(memcmp(restored, plain, sizeof(plain)), 0, @"key %u", key);
    }
}

- (void)testDecodedStringMatchesIndependentReimplementation {
    // Re-derive the key stream here, independently of the library, so a change to either side shows up.
    const char *plain = "MobileSubstrate";
    size_t length = strlen(plain);
    uint8_t key = 0x2B;

    uint8_t encoded[32];
    for (size_t index = 0; index < length; index++) {
        encoded[index] = (uint8_t)plain[index] ^ (uint8_t)((key + index * 31 + 7) & 0xFF);
    }
    XCTAssertEqualObjects(ISCStringFromObfuscatedBytes(encoded, length, key), @"MobileSubstrate");
}

- (void)testSecureZeroClearsBuffer {
    char buffer[16];
    memset(buffer, 0xAB, sizeof(buffer));
    ISCSecureZero(buffer, sizeof(buffer));
    for (size_t index = 0; index < sizeof(buffer); index++) {
        XCTAssertEqual(buffer[index], 0);
    }
    ISCSecureZero(NULL, 10); // must not crash
}

@end
