# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Hybrid package: Objective-C runtime layer (`IOSSecurityCoreObjC`) and Swift facade (`IOSSecurityCore`).
- Jailbreak, debugger, hooking/instrumentation and integrity detectors, built on documented Apple APIs only.
- `SecurityEngine` with callback, async/await, a `monitor` stream and a `reports` async sequence; all work
  runs off the main thread.
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

- `+[ISCIntegrityChecker hasEmbeddedProvisioningProfile]`: whether the profile file exists, separate from
  whether it parses. The App Store expectation and `IntegritySignals` use it, so a present but unreadable
  profile no longer passes as "none".
- Author and license header in every source file.
- DER entitlements: `entitlementsFromCodeSignatureData:` falls back to the DER slot (7, `0xfade7172`)
  Apple has required since iOS 15 when the XML slot is absent or unreadable, so the Team ID check keeps
  working once the XML slot is dropped.
- `SecurityPolicy`: the rule that turns a report into a verdict (`minimumSeverity`, `ignoredKinds`,
  `escalatedKinds`), and `SecurityReport.isCompromised(under:)`. `isCompromised` is the default policy.
- `SecurityReport.skipReason` (`simulator`, `macRuntime`, `unsupportedPlatform`); `wasSkipped` is derived
  from it, so an evaluation that requested no check families is no longer reported as skipped.
- `SecurityEngine.reports`, a `Sendable` `AsyncSequence` of every report the engine produces.

### Changed
- **Breaking.** `SecurityConfiguration` is grouped by family: `jailbreak`, `hooking` and `integrity` nested
  values hold what used to be twenty flat properties (`configuration.integrity.expectedTeamIdentifier`).
  `checks` and the test hooks stay at the top level. The Objective-C `ISCScanOptions` is unchanged.
- **Breaking.** `SecurityEngine.reports` is an `AsyncSequence`, not a Combine publisher; the package no
  longer imports Combine. `SecurityEngine` is `Sendable` without `@unchecked`, and `configuration` is
  settable (`configure(_:)` remains).
- **Breaking.** Swift tools version 6.0 and Swift 6 language mode: the package needs Xcode 16 or later.
- `ISCHookDetector` is split into probes under `Internal/`: self-integrity, system functions,
  instrumentation, and the shared code-trust helpers. Behaviour is unchanged.
- The detector registry and the self-integrity target list live in `ISCDetectorRegistry.m`; no detector
  imports another detector or the scanner any more.
- `ISCChecksAll` and `SecurityCheck.allCases` include the new `network` family.
- The self-integrity check also covers `+[ISCDebuggerDetector scanWithOptions:]` and the network detector,
  and now also reports a detector whose implementation stayed in place but was inline-patched to branch
  out of the package.
- Detectors share a private `ISCDetector` contract; `ISCSecurityScanner` iterates that registry instead
  of naming each family. Every detector now honours `ISCScanOptions.checks` when called directly (before,
  only the debugger and network detectors did).
- `SecurityEngine` keeps its configuration in an `OSAllocatedUnfairLock` instead of an `NSLock`.
- `SecurityConfiguration.includesBuiltInIndicators` and `scansUnsupportedEnvironments` are test hooks and
  now require `@_spi(Testing) import IOSSecurityCore`. The Objective-C properties are unchanged.
