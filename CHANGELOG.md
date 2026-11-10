# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Hybrid package: Objective-C runtime layer (`IOSSecurityCoreObjC`) and Swift facade (`IOSSecurityCore`).
- Jailbreak, debugger, hooking/instrumentation and integrity detectors, built on documented Apple APIs only.
- `SecurityEngine` with callback, async/await, `monitor` stream and Combine publisher; all work runs off the
  main thread.
- Stable numeric threat kinds and `Codable` reports for server-side decisions.
- Compile-time string obfuscation macros (`ISC_OBF_*`) and `StringObfuscator`.
- Empty privacy manifest; `Scripts/audit-symbols.sh` keeps it honest.
- `Scripts/text-digest.swift` to compute the expected `__TEXT,__text` digest of a release binary.
- Jailbreak indicators `/bin/sh`, `/usr/lib/libjailbreak.dylib`, `libsandy` and the Shadow bypass tweak.
- Opaque Objective-C class names (`ISC_SYMBOL_OBFUSCATION`) on by default, so `strings`/`class-dump`
  on a host app do not list the detector classes. Set in `ISCObfuscationConfig.h`, not `cSettings`,
  because every importer must see the same value or linking fails.
- System-function verification: the libc, dyld and Objective-C runtime functions the detectors call are
  checked for rebinding (fishhook, dyld interposing; `hookReboundSymbol`, 410) and inline patching
  (Substrate, ElleKit, Dobby, Frida; `hookInlinePatchedFunction`, 409). `+[ISCHookDetector
  isFunctionInlineHooked:]` checks any C function.
- Hardware breakpoint and watchpoint detection (`debuggerHardwareBreakpoint`, 301) and a parent-process
  heuristic (`debuggerUnexpectedParent`, 302, medium).
- Jailbreak-detection bypass tools by Objective-C class and by file (`jailbreakBypassTool`, 206;
  `additionalSuspiciousClasses`), and SSH/checkra1n shells on loopback (`jailbreakRemoteShellPort`, 207;
  `probesRemoteShellPorts`).
- `network` check family: HTTP, HTTPS, SOCKS and auto-config proxies, including per-interface (VPN)
  ones (`networkProxy`, 600, medium).
- `__TEXT,__text` digests for embedded frameworks (`expectedImageTextDigests`; `integrityImageModified`,
  508; `integrityImageUnavailable`, 509) and `SecurityEngine.textSegmentDigest(ofImageNamed:)`.
- More jailbreak indicators: Cephei, Substitute and libhbang preference bundles, `/usr/lib/substrate`,
  `/var/lib/dpkg`, `/var/log/apt`, and the PreferenceLoader, WeeLoader, Cephei and AppSyncUnified libraries.

### Changed
- `ISCChecksAll` and `SecurityCheck.allCases` include the new `network` family.
- The self-integrity check also covers `+[ISCDebuggerDetector scanWithOptions:]` and the network detector.
