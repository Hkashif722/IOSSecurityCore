#!/usr/bin/env swift
//
//  text-digest.swift
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Prints the lowercase hex SHA-256 of a Mach-O binary's `__TEXT,__text` section: the value to put in
//  `SecurityConfiguration.expectedTextSegmentDigests` (the app) or `expectedImageTextDigests` (a framework).
//
//  Usage:
//      swift Scripts/text-digest.swift path/to/App.app/App
//      swift Scripts/text-digest.swift path/to/App.app/Frameworks/Auth.framework/Auth
//
//  Run it on the *release* binary you ship. For an App Store build, Apple re-signs and FairPlay-encrypts
//  the binary, so compute the digest from the decrypted code the device sees (for example, print
//  `ISCIntegrityChecker.textSegmentDigest` from a TestFlight build) rather than from your archive.
//
//  Fat binaries: the arm64 slice is used.
//

import CryptoKit
import Foundation

let headerSize64 = 32
let magic64: UInt32 = 0xFEEDFACF
let fatMagic: UInt32 = 0xCAFEBABE
let cpuTypeARM64: UInt32 = 0x0100000C
let lcSegment64: UInt32 = 0x19

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    exit(1)
}

func read32(_ data: Data, _ offset: Int, bigEndian: Bool = false) -> UInt32? {
    guard offset >= 0, offset + 4 <= data.count else { return nil }
    let value = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
    return bigEndian ? UInt32(bigEndian: value) : value
}

func read64(_ data: Data, _ offset: Int) -> UInt64? {
    guard offset >= 0, offset + 8 <= data.count else { return nil }
    return data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self) }
}

func fixedString(_ data: Data, _ offset: Int, _ length: Int) -> String? {
    guard offset >= 0, offset + length <= data.count else { return nil }
    let bytes = data[offset..<offset + length].prefix { $0 != 0 }
    return String(decoding: bytes, as: UTF8.self)
}

guard CommandLine.arguments.count == 2 else {
    fail("usage: swift Scripts/text-digest.swift <path-to-mach-o>")
}
guard let file = FileManager.default.contents(atPath: CommandLine.arguments[1]) else {
    fail("cannot read \(CommandLine.arguments[1])")
}

// Select the arm64 slice of a fat binary.
var sliceStart = 0
if read32(file, 0, bigEndian: true) == fatMagic {
    guard let count = read32(file, 4, bigEndian: true) else { fail("truncated fat header") }
    var found = false
    for index in 0..<Int(count) {
        let entry = 8 + index * 20
        guard let cpu = read32(file, entry, bigEndian: true),
              let offset = read32(file, entry + 8, bigEndian: true) else { fail("truncated fat header") }
        if cpu == cpuTypeARM64 {
            sliceStart = Int(offset)
            found = true
            break
        }
    }
    if !found { fail("no arm64 slice in this universal binary") }
}

guard read32(file, sliceStart) == magic64 else { fail("not a 64-bit Mach-O file") }
guard let commandCount = read32(file, sliceStart + 16) else { fail("truncated header") }

var cursor = sliceStart + headerSize64
for _ in 0..<commandCount {
    guard let command = read32(file, cursor), let size = read32(file, cursor + 4), size >= 8 else {
        fail("malformed load command")
    }
    if command == lcSegment64, fixedString(file, cursor + 8, 16) == "__TEXT" {
        guard let sectionCount = read32(file, cursor + 64) else { fail("truncated segment") }
        var section = cursor + 72
        for _ in 0..<sectionCount {
            guard fixedString(file, section, 16) == "__text" else {
                section += 80
                continue
            }
            guard let length = read64(file, section + 40), let offset = read32(file, section + 48) else {
                fail("truncated section")
            }
            let start = sliceStart + Int(offset)
            guard start >= 0, start + Int(length) <= file.count else { fail("section lies outside the file") }
            let digest = SHA256.hash(data: file[start..<start + Int(length)])
            print(digest.map { String(format: "%02x", $0) }.joined())
            exit(0)
        }
    }
    cursor += Int(size)
}
fail("no __TEXT,__text section found")
