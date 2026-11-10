import Foundation
import IOSSecurityCoreObjC

/// Keeps secrets out of `strings` output.
///
/// A string literal in Swift source ends up verbatim in the binary. Encode it once, paste the bytes
/// into your code, and decode them where you need the text:
///
/// ```swift
/// // At development time (a playground or a unit test):
/// let bytes = StringObfuscator.encode("https://internal.example.com", key: 0x2B)
///
/// // In the app:
/// let url = StringObfuscator.decode([0x4F, 0x1A, …], key: 0x2B)
/// ```
///
/// This is obfuscation, not encryption: it defeats `strings`, grep and casual static analysis, not a
/// debugger and not anyone who reads this source. Never put a real secret in an app binary; keep it on a
/// server. For Objective-C code, the `ISC_OBF_NSSTRING` and `ISC_OBF_CSTRING` macros do the same at
/// compile time, with no manual encoding step.
public enum StringObfuscator {

    /// Encodes `string` as UTF-8 and masks it with a key-dependent stream.
    ///
    /// - Parameters:
    ///   - string: The text to hide.
    ///   - key: Any value; the same key is needed to decode.
    /// - Returns: The masked bytes. They are not valid UTF-8 in general.
    public static func encode(_ string: String, key: UInt8) -> [UInt8] {
        mask(Array(string.utf8), key: key)
    }

    /// Reverses ``encode(_:key:)``.
    ///
    /// - Returns: The original text, or `nil` if the bytes were not produced by ``encode(_:key:)`` with
    ///   this key.
    public static func decode(_ bytes: [UInt8], key: UInt8) -> String? {
        String(bytes: mask(bytes, key: key), encoding: .utf8)
    }

    // The mask is its own inverse, and shares ISCDeobfuscateBytes with the Objective-C macros so both
    // layers always agree.
    private static func mask(_ bytes: [UInt8], key: UInt8) -> [UInt8] {
        guard !bytes.isEmpty else { return [] }
        var output = [CChar](repeating: 0, count: bytes.count + 1)
        bytes.withUnsafeBufferPointer { input in
            guard let base = input.baseAddress else { return }
            ISCDeobfuscateBytes(base, bytes.count, key, &output)
        }
        return output.prefix(bytes.count).map { UInt8(bitPattern: $0) }
    }
}
