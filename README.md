# IOSSecurityCore

Runtime application self-protection (RASP) for iOS apps. IOSSecurityCore tells your app when it is running
on a jailbroken device, under a debugger, with an instrumentation framework such as Frida injected, as a
re-signed or patched copy, or behind an intercepting proxy, so **your app** can decide what to do about it.

- **Detects, never hides.** It reports signals about the device your own app runs on. It does not touch other
  apps.
- **Documented APIs only.** `<objc/runtime.h>`, `<dlfcn.h>`, dyld, `sysctl`, Mach and CommonCrypto. No private
  API, so it is App Store safe.
- **Hybrid package.** An Objective-C runtime layer (`IOSSecurityCoreObjC`) and an idiomatic, `Sendable`,
  async-first Swift layer (`IOSSecurityCore`). Use either.
- **Never blocks launch.** Every evaluation runs on a private background queue.
- **Privacy manifest included, and empty.** It collects nothing and uses no "required reason" API
  (`Scripts/audit-symbols.sh` enforces that).

## Requirements

iOS 16.0+, Swift 6.0+, Xcode 16+.

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/<you>/IOSSecurityCore.git", from: "1.0.0")
],
targets: [
    .target(name: "YourApp", dependencies: [
        .product(name: "IOSSecurityCore", package: "IOSSecurityCore")        // Swift API
        // .product(name: "IOSSecurityCoreObjC", package: "IOSSecurityCore") // Objective-C only
    ])
]
```

## Quick start

```swift
import IOSSecurityCore

// 1. Tell the engine what your app should look like (every field is optional).
var configuration = SecurityConfiguration()
configuration.integrity.expectedBundleIdentifier = "com.example.app"
configuration.integrity.expectedTeamIdentifier = "ABCDE12345"
#if !DEBUG
configuration.integrity.expectedDistribution = .appStore   // release builds only
#endif
SecurityEngine.shared.configuration = configuration

// 2. Evaluate at launch. This does not block the main thread.
SecurityEngine.shared.evaluate { report in
    if report.isCompromised {
        // Degrade, log out, or tell your backend. See "Deciding what to do".
    }
}

// 3. Or with async/await, and keep watching: debuggers attach after launch.
let report = try await SecurityEngine.shared.evaluate()   // throws only CancellationError
for await report in SecurityEngine.shared.monitor(interval: 30) { … }

// 4. Or observe every report the engine produces, wherever it was requested.
for await report in SecurityEngine.shared.reports where report.isCompromised { … }
```

A `SecurityReport` holds `threats`, each with a stable numeric `kind`, a `category`, a `severity`
(`info` … `critical`) and a dotted `identifier` such as `jailbreak.artifact`. `isCompromised` is true when any
threat is `high` or `critical`. Heuristics (unknown libraries, odd threads) are deliberately `medium` or
lower, so many weak signals never add up to a lock-out. That rule is `SecurityPolicy.default`; a stricter or
looser one is a value you pass to `report.isCompromised(under:)` (see "Deciding what to do").

On the Simulator, on macOS and under Mac Catalyst the checks are **skipped**, not failed: the report contains
one `info` threat, `wasSkipped == true` and `skipReason` says why (`.simulator`, `.macRuntime`,
`.unsupportedPlatform`).

## What it checks

| Family | Signals |
|---|---|
| `jailbreak` | Known jailbreak files and directories, system directories replaced by symlinks, `DYLD_INSERT_LIBRARIES`, loaded tweak-injection libraries, a write outside the sandbox, a successful `fork()`, an SSH (22) or checkra1n (44) shell on loopback, jailbreak-detection **bypass tools** (Shadow, A-Bypass, FlyJB, Liberty) by their Objective-C classes and their files |
| `debugger` | The `P_TRACED` flag (Apple QA1361), armed hardware breakpoints or watchpoints, a parent process other than launchd (medium) |
| `hooking` | Swizzled detectors (self-integrity), **system functions the checks rely on** (`access`, `open`, `sysctl`, `getenv`, dyld, ...) rebound by fishhook/interposing or inline-patched by Substrate/ElleKit/Dobby/Frida, Frida/Cycript/SSL Kill Switch libraries, `frida-server` on disk or listening on loopback, Frida agent threads, images from unexpected locations, dylibs injected into the bundle, swizzled methods you register |
| `integrity` | Bundle ID, Team ID (read from the app's own code signature), App Store expectations (no provisioning profile, encrypted binary, no `get-task-allow`), SHA-256 of `__TEXT,__text` of the app and of embedded frameworks |
| `network` | An HTTP, HTTPS, SOCKS or auto-config (PAC/WPAD) proxy, including one a VPN sets (medium: managed networks use proxies legitimately). The finding names the kind of proxy, never its address |

Bypass tweaks do not patch this package; they hook the system calls its checks make, so files and libraries
"are not there". That is why the `hooking` family verifies those system functions first: a check that
found nothing is only meaningful when the calls it made were not intercepted.

### Protect your own methods

```swift
configuration.hooking.protectedMethods = [
    .init(className: "MyApp.AuthManager", selector: "isUserAuthenticated"),
]
```

If a tweak replaces that implementation, it moves out of your image and the engine reports
`.hookSwizzledMethod`.

For a C function, ask whether its first instructions were replaced by a hook's trampoline:

```objc
if ([ISCHookDetector isFunctionInlineHooked:(const void *)verifyLicense]) { … }
```

### Catch jailbreak-bypass tools

A bypass tweak can hide its files and its library, but not its Objective-C classes. Add the class names of
tools you care about (Shadow's are built in):

```swift
configuration.jailbreak.additionalSuspiciousClasses = ["SomeBypassTweakController"]
```

### Catch injected dylibs

List every dynamic library you embed. Any other image loaded from inside the app bundle is reported, which is
the effective defence against a repackaged app with an injected dylib:

```swift
configuration.hooking.allowedBundleLibraries = ["Auth.framework/Auth", "libFoo.dylib"]
```

### Verify the code itself

```
swift Scripts/text-digest.swift path/to/YourApp.app/YourApp
```

Put the printed digest in `configuration.integrity.expectedTextSegmentDigests`. Hashing reads the whole code section, so
use it in release builds only, and compute it from the binary your users run (for App Store builds, print
`IntegritySignals.textSegmentDigest` from a TestFlight build).

Embedded dynamic frameworks work the same way, keyed by their trailing path components:

```swift
configuration.integrity.expectedImageTextDigests = ["Auth.framework/Auth": ["3f1c…"]]
// From a TestFlight build: await SecurityEngine.shared.textSegmentDigest(ofImageNamed: "Auth.framework/Auth")
```

## Deciding what to do

**A check inside the app can be patched out by whoever controls the device.** Treat the report as a risk
signal and make the decision where it cannot be tampered with:

```swift
let signals = await SecurityEngine.shared.integritySignals(includingTextDigest: true)
// `IntegritySignals` and `SecurityReport` are Codable: send them, with an App Attest assertion, to your server.
```

When the decision has to be made on the device, make it with a `SecurityPolicy` rather than by reading
severities yourself. The policy is a value, so a payments screen can be stricter than the rest of the app:

```swift
var strict = SecurityPolicy()                 // high or critical, like `isCompromised`
strict.escalatedKinds = [.networkProxy]       // a proxy is disqualifying here, although it is only medium
strict.ignoredKinds = [.debuggerUnexpectedParent]
if report.isCompromised(under: strict) { … }
```

For Objective-C, `ISCSecurityScanner` offers the same through `ISCScanOptions`.

## Debugger denial (opt-in countermeasure)

`SecurityEngine.denyDebuggerAttachment()` asks the kernel to refuse debuggers (`PT_DENY_ATTACH`). If a debugger
is already attached the process is terminated, and Xcode/LLDB can no longer attach, so never call it in debug
or QA builds.

## Hiding indicator strings

A literal in your source ends up verbatim in the binary. Objective-C code can use
`ISC_OBF_NSSTRING("…")` / `ISC_OBF_CSTRING(name, "…")` (encoded at compile time, per-call-site keys); Swift can
use `StringObfuscator`. This defeats `strings` and grep, not a debugger. Never put a real secret in a binary.

This reaches only the **literals you wrap**. It cannot touch class and selector *names*: those are emitted by
the compiler into `__TEXT`, not written by you, so they are visible to `class-dump` no matter what this
library does at runtime. That is a build-time concern — see the next section.

## Build-time hardening (class names, reflection, symbols)

Class names, selectors and Swift type metadata are written into the binary when it is **compiled**. An auditor
runs `class-dump` or `strings` on the shipped file without ever launching the app, so **nothing a runtime
library does can change what they see** — the names are already in the IPA before IOSSecurityCore's code
runs. Closing that gap is a job for the build, not for a dependency. Two pieces, both compile-time:

**1. Strip what you don't need** (Build Settings, release configuration):

| Setting | Effect |
|---|---|
| `SWIFT_REFLECTION_METADATA_LEVEL = none` | Drops `__swift5_fieldmd` field names and `Mirror`. Breaks reflection-based code; `Codable` is unaffected. |
| `STRIP_SWIFT_SYMBOLS = YES` | Removes Swift symbol names. |
| `DEPLOYMENT_POSTPROCESSING = YES`, `STRIP_INSTALLED_PRODUCT = YES`, `STRIP_STYLE = all` | Strips the symbol table (defeats `nm`). |

These remove Swift field names and the symbol table. They do **not** rename Objective-C class names — the
runtime dereferences those from `__TEXT,__objc_classname`, so they stay. Renaming them is a separate,
heavier source-rewrite step (SwiftShield-class tooling); this package does not ship one.

**2. Gate the build** so a sensitive name can never leak unnoticed. `Scripts/build-phase-audit.sh` inspects
the linked binary exactly as an auditor would and **fails the build** when a name you declared off-limits is
visible. Add it to your app target as a Run Script phase (after *Compile Sources*):

```
"${SRCROOT}/Scripts/build-phase-audit.sh"
```

List the names to forbid in a `security-audit.denylist` file next to your project (see
`Scripts/security-audit.denylist.sample`). The script also warns, without failing, when the strip settings
above did not take effect. It is a gate, not an obfuscator: it tells you which names reached the binary so you
can rename those few at the source — only ever names that are **not** resolved by string (storyboard/XIB,
`Codable`, KVC, Core Data, `NSClassFromString`, `#selector`), since renaming those breaks the app. Run it in
CI or by hand too: `Scripts/build-phase-audit.sh path/to/YourApp.app/YourApp`.

## Limits you should know

- Client-side detection is not proof. A determined attacker on a jailbroken device can bypass any single
  check; the checks raise the cost and give your server data to judge.
- The jailbreak checks cannot see a jailbreak that hides well. Combine them with server-side verification.
- A scan runs through C functions, not Objective-C methods, so swizzling a method cannot redirect or empty it,
  and the Swift layer cross-checks each result against what it asked for. Patching the machine code itself
  is still possible on a device with code signing disabled. The package looks for that too, but code that
  checks itself can be patched to skip the check. Only a decision made on your server is out of reach.
- Results on the Simulator and macOS are not meaningful, so the checks are skipped there.
- **It cannot hide your class names.** Class/selector names and Swift type metadata are compiled into the
  binary before the app runs, so `class-dump`/`strings` read them off the shipped file no matter what runs at
  runtime. That is a build-time concern — see "Build-time hardening". This library detects tampering; it does
  not obfuscate the binary.

## Development

```
swift test                       # macOS host (needs Xcode selected, not only the Command Line Tools)
swift test -c release            # the same, optimised: self-integrity must verify clean in release code
swift test --sanitize=address    # memory safety of the parsers and probes
Scripts/audit-symbols.sh         # privacy, plain-text and exported-symbol audit of the release build
```

## License

MIT. See [LICENSE](LICENSE).
