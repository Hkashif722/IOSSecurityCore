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
