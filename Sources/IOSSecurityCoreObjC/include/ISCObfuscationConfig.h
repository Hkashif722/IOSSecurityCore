//
//  ISCObfuscationConfig.h
//  IOSSecurityCoreObjC
//
//  Build-time obfuscation switches. Nothing in this header changes behaviour; it only changes how
//  the compiled binary names things.
//

#ifndef ISCObfuscationConfig_h
#define ISCObfuscationConfig_h

// MARK: - String obfuscation

/// Base value mixed into the key of every obfuscated string literal (see ISCObfuscation.h).
///
/// Every `ISC_OBF_*` use additionally gets its own key derived from `__COUNTER__`, so two equal
/// literals never encode to the same bytes. Define this before importing the umbrella header to give
/// your own build a different encoding. It is baked into each call site, so changing it never breaks
/// decoding.
#ifndef ISC_OBFUSCATION_BASE_KEY
#define ISC_OBFUSCATION_BASE_KEY 0x5Au
#endif

// MARK: - Runtime class-name obfuscation

/// Set to `1` to give every public Objective-C class an opaque runtime name.
///
/// - Source-level names do not change, so Swift and Objective-C callers are unaffected.
/// - `class-dump`, `NSStringFromClass` and tools like Frida's `ObjC.classes` then show the opaque
///   names listed below instead of `ISCJailbreakDetector` and friends.
/// - Symbolicated crash logs show the opaque names too, which is why this is OFF by default.
///
/// The value must be identical for the package build and for every file that imports these headers.
/// To enable it, add `.define("ISC_SYMBOL_OBFUSCATION", to: "1")` to the `cSettings` of the
/// `IOSSecurityCoreObjC` target in your fork of `Package.swift`.
#ifndef ISC_SYMBOL_OBFUSCATION
#define ISC_SYMBOL_OBFUSCATION 0
#endif

#if ISC_SYMBOL_OBFUSCATION
#define ISC_RUNTIME_NAME(name) __attribute__((objc_runtime_name(name)))
#else
#define ISC_RUNTIME_NAME(name)
#endif

// Opaque runtime names. Replace them with your own random identifiers per product; they only have
// to be unique and valid Objective-C class names.
#define ISC_RN_FINDING            ISC_RUNTIME_NAME("Qk7xN2")
#define ISC_RN_SCAN_RESULT        ISC_RUNTIME_NAME("Zr4mB9")
#define ISC_RN_SCAN_OPTIONS       ISC_RUNTIME_NAME("Wt8hC3")
#define ISC_RN_PROTECTED_METHOD   ISC_RUNTIME_NAME("Ya2pD6")
#define ISC_RN_ENVIRONMENT        ISC_RUNTIME_NAME("Vb5qE1")
#define ISC_RN_JAILBREAK_DETECTOR ISC_RUNTIME_NAME("Xc9rF4")
#define ISC_RN_DEBUGGER_DETECTOR  ISC_RUNTIME_NAME("Ud3sG8")
#define ISC_RN_HOOK_DETECTOR      ISC_RUNTIME_NAME("Te6tH2")
#define ISC_RN_INTEGRITY_CHECKER  ISC_RUNTIME_NAME("Sf1uJ5")
#define ISC_RN_SECURITY_SCANNER   ISC_RUNTIME_NAME("Rg7vK9")

#endif /* ISCObfuscationConfig_h */
