//
//  ISCObfuscationConfig.h
//  IOSSecurityCoreObjC
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
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

/// `1` (the default) gives every public Objective-C class an opaque runtime name.
///
/// - Source-level names do not change, so Swift and Objective-C callers are unaffected.
/// - `class-dump`, `strings`, `NSStringFromClass` and tools like Frida's `ObjC.classes` show the
///   opaque names listed below instead of `ISCJailbreakDetector` and friends, so a static scan of
///   the host app does not reveal which RASP checks it carries.
/// - Symbolicated crash logs show the opaque names too.
///
/// The value must be identical for the package build and for every file that imports these headers:
/// the class symbols themselves are renamed (`_OBJC_CLASS_$_Ud3sG8`), so a Swift or Objective-C
/// importer that sees a different value fails to link. That is why it is set here, in the one header
/// every importer reads, and not through `cSettings` (which the Swift target's importer never sees).
/// To turn it off, change the value below rather than defining it elsewhere.
#ifndef ISC_SYMBOL_OBFUSCATION
#define ISC_SYMBOL_OBFUSCATION 1
#endif

#if ISC_SYMBOL_OBFUSCATION
#define ISC_RUNTIME_NAME(name) __attribute__((objc_runtime_name(name)))
#else
#define ISC_RUNTIME_NAME(name)
#endif

// MARK: - C symbol names
//
// The same switch renames the public C functions at the linker level, so their symbols do not name the
// checks either. Every other C function in the package has hidden visibility and is never exported.

#if ISC_SYMBOL_OBFUSCATION
#define ISC_C_SYMBOL(name) __asm__("_" name)
#else
#define ISC_C_SYMBOL(name)
#endif

#define ISC_SN_PERFORM_SCAN       ISC_C_SYMBOL("Mx2nB8")
#define ISC_SN_DEOBFUSCATE_BYTES  ISC_C_SYMBOL("Hv7cQ4")
#define ISC_SN_STRING_FROM_BYTES  ISC_C_SYMBOL("Jd5kW1")
#define ISC_SN_SECURE_ZERO        ISC_C_SYMBOL("Nr8pZ6")

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
#define ISC_RN_NETWORK_DETECTOR   ISC_RUNTIME_NAME("Ph4wL7")

#endif /* ISCObfuscationConfig_h */
