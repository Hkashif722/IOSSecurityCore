//
//  ISCObfuscation.h
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//
//  Compile-time string obfuscation.
//
//  Sensitive literals (jailbreak paths, hooking-framework names, `dlsym` symbol names, ...) must not
//  appear in plain text in the shipped binary, otherwise `strings` or a hex editor hands an attacker a
//  map of every check. These macros encode a literal with a per-call-site XOR key *while compiling*, so
//  the plain text never reaches the object file, even in -O0 builds. The bytes are decoded on demand.
//
//  This is obfuscation, not encryption: it defeats `strings`, grep and casual static analysis, not a
//  debugger. Decoded text lives in memory while in use; wipe C buffers with `ISC_OBF_WIPE`.
//
//  Usage (Objective-C):
//
//      NSString *path = ISC_OBF_NSSTRING("/Applications/Cydia.app");
//
//      ISC_OBF_CSTRING(symbolName, "ptrace");          // declares `char symbolName[...]`
//      void *fn = dlsym(RTLD_DEFAULT, symbolName);
//      ISC_OBF_WIPE(symbolName);
//
//  Limits: the argument must be a string literal of at most `ISC_OBF_MAX_LENGTH` characters (checked
//  at compile time), made of single-byte characters (use UTF-8 escapes for anything else).
//

#ifndef ISCObfuscation_h
#define ISCObfuscation_h

#import <Foundation/Foundation.h>
#include <stddef.h>
#include <stdint.h>

#import "ISCObfuscationConfig.h"

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

/// Longest literal (in bytes, excluding the terminator) the `ISC_OBF_*` macros accept.
#define ISC_OBF_MAX_LENGTH 64

// MARK: - Runtime support (used by the macros; also callable directly)

/// Decodes `length` bytes produced by the `ISC_OBF_*` macros into `output`.
///
/// - Parameters:
///   - encoded: The XOR-encoded bytes.
///   - length: Number of bytes in `encoded`.
///   - key: The key the bytes were encoded with.
///   - output: Buffer of at least `length + 1` bytes. A NUL terminator is always written.
void ISCDeobfuscateBytes(const uint8_t *encoded, size_t length, uint8_t key, char *output) ISC_SN_DEOBFUSCATE_BYTES;

/// Decodes `length` bytes produced by the `ISC_OBF_*` macros into an `NSString` (UTF-8).
NSString *ISCStringFromObfuscatedBytes(const uint8_t *encoded, size_t length, uint8_t key) ISC_SN_STRING_FROM_BYTES;

/// Overwrites `length` bytes at `buffer` with zeros in a way the optimizer cannot remove. Does nothing
/// for a `NULL` buffer or a zero length.
void ISCSecureZero(void *_Nullable buffer, size_t length) ISC_SN_SECURE_ZERO;

// MARK: - Macro machinery (implementation detail)

/// Per-character key stream. Must match `ISCDeobfuscateBytes`.
#define ISC_OBF_STEP(index, key) \
    ((uint8_t)((((unsigned)(key)) + ((unsigned)(index)) * 31u + 7u) & 0xFFu))

/// Encodes character `index` of `literal`, or yields 0 past the end of the literal.
/// Everything here is an integer constant expression, so the compiler folds it into a static array.
#define ISC_OBF_ENCODE_CHAR(literal, index, key) \
    ((uint8_t)(((size_t)(index)) < (sizeof(literal "") - 1)     \
        ? (uint8_t)((uint8_t)((literal "")[(index)]) ^ ISC_OBF_STEP((index), (key))) \
        : 0u))

#define ISC_OBF_ENCODE_8(literal, key, base)                                         \
    ISC_OBF_ENCODE_CHAR(literal, (base) + 0, key), ISC_OBF_ENCODE_CHAR(literal, (base) + 1, key), \
    ISC_OBF_ENCODE_CHAR(literal, (base) + 2, key), ISC_OBF_ENCODE_CHAR(literal, (base) + 3, key), \
    ISC_OBF_ENCODE_CHAR(literal, (base) + 4, key), ISC_OBF_ENCODE_CHAR(literal, (base) + 5, key), \
    ISC_OBF_ENCODE_CHAR(literal, (base) + 6, key), ISC_OBF_ENCODE_CHAR(literal, (base) + 7, key)

#define ISC_OBF_ENCODE_64(literal, key)                                              \
    ISC_OBF_ENCODE_8(literal, key, 0),  ISC_OBF_ENCODE_8(literal, key, 8),           \
    ISC_OBF_ENCODE_8(literal, key, 16), ISC_OBF_ENCODE_8(literal, key, 24),          \
    ISC_OBF_ENCODE_8(literal, key, 32), ISC_OBF_ENCODE_8(literal, key, 40),          \
    ISC_OBF_ENCODE_8(literal, key, 48), ISC_OBF_ENCODE_8(literal, key, 56)

/// A key unique to this expansion. `__COUNTER__` is substituted exactly once because macro arguments
/// are fully expanded before they are pasted into the replacement list.
#define ISC_OBF_MAKE_KEY(counter) \
    ((uint8_t)((ISC_OBFUSCATION_BASE_KEY + ((unsigned)(counter)) * 17u) & 0xFFu))

#define ISC_OBF_LENGTH_CHECK(literal) \
    _Static_assert(sizeof(literal "") - 1 <= ISC_OBF_MAX_LENGTH, \
                   "ISC_OBF_*: string literal is longer than ISC_OBF_MAX_LENGTH")

#define ISC_OBF_NSSTRING_IMPL(literal, counter)                                      \
    __extension__({                                                                  \
        ISC_OBF_LENGTH_CHECK(literal);                                               \
        static const uint8_t isc_obf_bytes[ISC_OBF_MAX_LENGTH] = {                   \
            ISC_OBF_ENCODE_64(literal, ISC_OBF_MAKE_KEY(counter))                    \
        };                                                                           \
        ISCStringFromObfuscatedBytes(isc_obf_bytes, sizeof(literal "") - 1,          \
                                     ISC_OBF_MAKE_KEY(counter));                     \
    })

#define ISC_OBF_CSTRING_IMPL(name, literal, counter)                                 \
    ISC_OBF_LENGTH_CHECK(literal);                                                   \
    static const uint8_t name##_isc_obf_bytes[ISC_OBF_MAX_LENGTH] = {                \
        ISC_OBF_ENCODE_64(literal, ISC_OBF_MAKE_KEY(counter))                        \
    };                                                                               \
    char name[sizeof(literal "")];                                                   \
    ISCDeobfuscateBytes(name##_isc_obf_bytes, sizeof(literal "") - 1,                \
                        ISC_OBF_MAKE_KEY(counter), name)

// MARK: - Public macros

/// Expression yielding an autoreleased `NSString *` with the decoded literal.
/// The plain text is never stored in the binary.
#define ISC_OBF_NSSTRING(literal) ISC_OBF_NSSTRING_IMPL(literal, __COUNTER__)

/// Statement declaring a local `char name[]` holding the decoded literal (NUL-terminated).
/// Call `ISC_OBF_WIPE(name)` when you are done with it.
#define ISC_OBF_CSTRING(name, literal) ISC_OBF_CSTRING_IMPL(name, literal, __COUNTER__)

/// Zeroes a buffer declared with `ISC_OBF_CSTRING`.
#define ISC_OBF_WIPE(name) ISCSecureZero((name), sizeof(name))

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END

#endif /* ISCObfuscation_h */
