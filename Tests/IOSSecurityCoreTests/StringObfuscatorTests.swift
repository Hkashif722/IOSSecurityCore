//
//  StringObfuscatorTests.swift
//  IOSSecurityCoreTests
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import XCTest
@testable import IOSSecurityCore

final class StringObfuscatorTests: XCTestCase {

    func testRoundTrip() {
        for text in ["", "a", "https://internal.example.com/api", "caf\u{00E9} \u{1F510}", String(repeating: "x", count: 500)] {
            for key in [UInt8(0), 1, 0x2B, 0x80, 255] {
                let encoded = StringObfuscator.encode(text, key: key)
                XCTAssertEqual(StringObfuscator.decode(encoded, key: key), text, "key \(key)")
            }
        }
    }

    func testEncodingHidesThePlainText() {
        let secret = "https://internal.example.com"
        let encoded = StringObfuscator.encode(secret, key: 0x2B)
        XCTAssertEqual(encoded.count, secret.utf8.count)
        XCTAssertNotEqual(encoded, Array(secret.utf8))
        XCTAssertNil(String(bytes: encoded, encoding: .utf8)?.range(of: "example"))
    }

    func testTheKeyMatters() {
        let encoded = StringObfuscator.encode("secret value", key: 1)
        XCTAssertNotEqual(StringObfuscator.decode(encoded, key: 2), "secret value")
    }

    func testEncodingMatchesAnIndependentReimplementationOfTheKeyStream() {
        // The scheme is shared with the Objective-C macros. Re-deriving it here, independently of the
        // library, makes any accidental change to either side visible.
        let plain = Array("MobileSubstrate".utf8)
        let key: UInt8 = 0x2B
        let expected = plain.enumerated().map { index, byte in
            byte ^ UInt8(truncatingIfNeeded: Int(key) + index * 31 + 7)
        }
        XCTAssertEqual(StringObfuscator.encode("MobileSubstrate", key: key), expected)
    }

    func testDecodingBytesThatAreNotUTF8ReturnsNil() {
        // 0xC3 0x28 is an invalid UTF-8 sequence; pick a key stream that reproduces it.
        let invalid: [UInt8] = [0xC3, 0x28]
        let key: UInt8 = 9
        let encoded = invalid.enumerated().map { index, byte in
            byte ^ UInt8(truncatingIfNeeded: Int(key) + index * 31 + 7)
        }
        XCTAssertNil(StringObfuscator.decode(encoded, key: key))
    }

    func testEmptyInputs() {
        XCTAssertEqual(StringObfuscator.encode("", key: 7), [])
        XCTAssertEqual(StringObfuscator.decode([], key: 7), "")
    }
}
