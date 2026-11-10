//
//  ISCTypes.h
//  IOSSecurityCoreObjC
//
//  Shared enumerations for findings, checks and expectations.
//

#ifndef ISCTypes_h
#define ISCTypes_h

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// How seriously a finding should be taken.
///
/// `ISCSeverityHigh` and above mean "the runtime environment is not trustworthy"; lower values are
/// context or weak signals that only matter in combination.
typedef NS_CLOSED_ENUM(NSInteger, ISCSeverity) {
    /// Context only (for example "running on the Simulator"). Never a threat on its own.
    ISCSeverityInfo = 0,
    /// A weak signal, easily produced by legitimate software.
    ISCSeverityLow = 1,
    /// A suspicious signal that is not conclusive on its own.
    ISCSeverityMedium = 2,
    /// A strong indicator of a compromised environment.
    ISCSeverityHigh = 3,
    /// A conclusive indicator (tampered binary, active instrumentation, sandbox escape).
    ISCSeverityCritical = 4,
};

/// The detector family a finding belongs to.
typedef NS_ENUM(NSInteger, ISCCategory) {
    /// Where the process runs (Simulator, Mac, ...). Always informational.
    ISCCategoryEnvironment = 0,
    ISCCategoryJailbreak = 1,
    ISCCategoryDebugger = 2,
    ISCCategoryHooking = 3,
    ISCCategoryIntegrity = 4,
};

/// Bit set selecting which detector families a scan runs.
typedef NS_OPTIONS(NSUInteger, ISCChecks) {
    ISCChecksJailbreak = 1 << 0,
    ISCChecksDebugger = 1 << 1,
    ISCChecksHooking = 1 << 2,
    ISCChecksIntegrity = 1 << 3,
    ISCChecksAll = ISCChecksJailbreak | ISCChecksDebugger | ISCChecksHooking | ISCChecksIntegrity,
};

/// How the host app expects to be distributed. Drives the integrity checks that only make sense for
/// one channel.
typedef NS_ENUM(NSInteger, ISCDistribution) {
    /// Do not assume anything about the distribution channel.
    ISCDistributionAny = 0,
    /// App Store or TestFlight: no embedded provisioning profile, FairPlay-encrypted binary, and no
    /// `get-task-allow` entitlement. Anything else points at a re-signed or cracked copy.
    ISCDistributionAppStore = 1,
};

/// Whether the main executable's `__TEXT` segment is FairPlay-encrypted (`cryptid` in
/// `LC_ENCRYPTION_INFO_64`). App Store and TestFlight builds are encrypted; development builds and
/// dumped ("cracked") copies are not.
typedef NS_ENUM(NSInteger, ISCEncryptionState) {
    /// The binary carries no encryption load command, or it could not be read.
    ISCEncryptionStateUnknown = 0,
    ISCEncryptionStateDecrypted = 1,
    ISCEncryptionStateEncrypted = 2,
};

/// Stable numeric identifier of what a finding reports. Safe to log, store and send to a backend;
/// existing values never change meaning and new checks only add new values.
typedef NS_ENUM(NSInteger, ISCFindingCode) {
    // Environment (informational)
    ISCFindingCodeSimulator = 100,
    ISCFindingCodeUnsupportedPlatform = 101,
    ISCFindingCodeMacRuntime = 102,

    // Jailbreak
    ISCFindingCodeJailbreakArtifact = 200,
    ISCFindingCodeJailbreakSymlink = 201,
    ISCFindingCodeJailbreakSandboxEscape = 202,
    ISCFindingCodeJailbreakForkAllowed = 203,
    ISCFindingCodeJailbreakInjectedLibrary = 204,
    ISCFindingCodeJailbreakInjectionEnvironment = 205,

    // Debugger
    ISCFindingCodeDebuggerAttached = 300,

    // Hooking / instrumentation
    ISCFindingCodeHookInstrumentationLibrary = 400,
    ISCFindingCodeHookInstrumentationPort = 401,
    ISCFindingCodeHookInstrumentationThread = 402,
    ISCFindingCodeHookInstrumentationArtifact = 403,
    ISCFindingCodeHookUnknownLibrary = 404,
    ISCFindingCodeHookSwizzledMethod = 405,
    ISCFindingCodeHookProtectedMethodUnresolved = 406,
    ISCFindingCodeHookSelfIntegrity = 407,
    ISCFindingCodeHookUnexpectedBundleLibrary = 408,

    // Integrity
    ISCFindingCodeIntegrityBundleIdentifierMismatch = 500,
    ISCFindingCodeIntegrityTeamIdentifierMismatch = 501,
    ISCFindingCodeIntegrityBinaryDecrypted = 502,
    ISCFindingCodeIntegrityTextSegmentModified = 503,
    ISCFindingCodeIntegrityDebuggableBuild = 504,
    ISCFindingCodeIntegrityUnexpectedProvisioningProfile = 505,
    ISCFindingCodeIntegrityTeamIdentifierUnavailable = 506,
    ISCFindingCodeIntegrityTextSegmentUnavailable = 507,
};

NS_ASSUME_NONNULL_END

#endif /* ISCTypes_h */
