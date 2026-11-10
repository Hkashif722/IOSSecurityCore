//
//  ISCDEREntitlements.h
//  IOSSecurityCoreObjC (private)
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Reads the DER-encoded entitlements Apple has required in code signatures since iOS 15.
//

#import <Foundation/Foundation.h>
#include <stddef.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN

/// Parses the payload of a `0xfade7172` blob (DER entitlements) into a dictionary.
///
/// The encoding is CoreFoundation's DER property list: a dictionary is a `SET` of `SEQUENCE { UTF8String
/// key, value }`; values are `BOOLEAN`, `INTEGER`, `UTF8String`, `OCTET STRING`, `SEQUENCE` (array) or a
/// nested `SET`. Apple wraps the whole thing in `[APPLICATION 16] { INTEGER version, SET }`. A value of a
/// type this reader does not know becomes `NSNull`, so one new type never hides the other entitlements.
///
/// Returns `nil` for anything structurally malformed. Never reads out of bounds, whatever the input.
NSDictionary<NSString *, id> *_Nullable ISCDictionaryFromDEREntitlements(const uint8_t *_Nullable bytes, size_t length);

NS_ASSUME_NONNULL_END
