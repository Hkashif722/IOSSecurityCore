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
#import "ISCVisibility.h"
#include <stddef.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN


/// Parses the payload of a `0xfade7172` blob (DER entitlements) into a dictionary.
///
/// The encoding is CoreFoundation's DER property list: a dictionary is a context-specific `[16]` (tag `0xB0`,
/// what Apple's signing emits; a universal `SET` is accepted too) of `SEQUENCE { UTF8String
/// key, value }`; values are `BOOLEAN`, `INTEGER`, `UTF8String`, `OCTET STRING`, `GeneralizedTime` (an
/// `NSDate`, as the XML slot gives), `SEQUENCE` (array) or a nested dictionary. Apple wraps the whole thing
/// in `[APPLICATION 16] { INTEGER version, dictionary }`. A value this reader cannot represent (an unknown type, an
/// integer wider than 64 bits, an unparseable date) becomes `NSNull`, so it never hides the other
/// entitlements.
///
/// Returns `nil` for anything structurally malformed. Never reads out of bounds, whatever the input.
ISC_HIDDEN NSDictionary<NSString *, id> *_Nullable ISCDictionaryFromDEREntitlements(const uint8_t *_Nullable bytes, size_t length);

NS_ASSUME_NONNULL_END
