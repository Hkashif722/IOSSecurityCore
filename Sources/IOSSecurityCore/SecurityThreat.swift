//
//  SecurityThreat.swift
//  IOSSecurityCore
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import Foundation
import IOSSecurityCoreObjC

/// One thing the engine noticed about the runtime environment.
///
/// A threat is a *signal*, not a verdict. Decide what to do with it in your app, and prefer deciding on
/// a server (send the ``SecurityReport`` there): a decision made inside the app can be patched out.
public struct SecurityThreat: Hashable, Sendable, Codable, CustomStringConvertible {

    /// What was found. The raw values are stable across releases: log them, store them, send them to a
    /// backend. New checks add new kinds; existing kinds never change meaning.
    public struct Kind: RawRepresentable, Hashable, Sendable, Codable {
        public let rawValue: Int

        public init(rawValue: Int) {
            self.rawValue = rawValue
        }

        init(_ code: ISCFindingCode) {
            self.init(rawValue: code.rawValue)
        }

        // Environment (informational)

        /// Running on the iOS Simulator; the checks were skipped.
        public static let simulator = Kind(.simulator)
        /// Running on a platform the checks do not support (macOS, ...); they were skipped.
        public static let unsupportedPlatform = Kind(.unsupportedPlatform)
        /// Running on a Mac (Mac Catalyst or an iOS app on Apple silicon); the checks were skipped.
        public static let macRuntime = Kind(.macRuntime)

        // Jailbreak

        /// A file or directory that exists only on jailbroken devices.
        public static let jailbreakArtifact = Kind(.jailbreakArtifact)
        /// A system directory that is a symbolic link on jailbroken devices.
        public static let jailbreakSymlink = Kind(.jailbreakSymlink)
        /// A file could be created outside the app sandbox.
        public static let jailbreakSandboxEscape = Kind(.jailbreakSandboxEscape)
        /// `fork()` succeeded, which the stock sandbox forbids.
        public static let jailbreakForkAllowed = Kind(.jailbreakForkAllowed)
        /// A tweak-injection library (Substrate, Substitute, libhooker, ...) is loaded.
        public static let jailbreakInjectedLibrary = Kind(.jailbreakInjectedLibrary)
        /// `DYLD_INSERT_LIBRARIES` names a library that is not developer tooling.
        public static let jailbreakInjectionEnvironment = Kind(.jailbreakInjectionEnvironment)
        /// A jailbreak-detection bypass tool (Shadow, A-Bypass, FlyJB, ...) is installed or loaded.
        public static let jailbreakBypassTool = Kind(.jailbreakBypassTool)
        /// Something listens on a loopback port only a jailbreak opens (SSH 22, checkra1n 44).
        public static let jailbreakRemoteShellPort = Kind(.jailbreakRemoteShellPort)

        // Debugger

        /// A debugger is attached to the process.
        public static let debuggerAttached = Kind(.debuggerAttached)
        /// A thread has a hardware breakpoint or watchpoint armed.
        public static let debuggerHardwareBreakpoint = Kind(.debuggerHardwareBreakpoint)
        /// The app was not launched by launchd, usually because a debugger launched it.
        public static let debuggerUnexpectedParent = Kind(.debuggerUnexpectedParent)

        // Hooking

        /// An instrumentation framework (Frida, Cycript, SSL Kill Switch, ...) is loaded.
        public static let hookInstrumentationLibrary = Kind(.hookInstrumentationLibrary)
        /// Something listens on the loopback port `frida-server` uses.
        public static let hookInstrumentationPort = Kind(.hookInstrumentationPort)
        /// A thread that only an injected instrumentation agent starts.
        public static let hookInstrumentationThread = Kind(.hookInstrumentationThread)
        /// `frida-server` files exist on the device.
        public static let hookInstrumentationArtifact = Kind(.hookInstrumentationArtifact)
        /// A loaded image comes from neither the system nor the app bundle.
        public static let hookUnknownLibrary = Kind(.hookUnknownLibrary)
        /// A protected method's implementation moved out of its image.
        public static let hookSwizzledMethod = Kind(.hookSwizzledMethod)
        /// A protected method could not be found (a configuration problem, or it was removed).
        public static let hookProtectedMethodUnresolved = Kind(.hookProtectedMethodUnresolved)
        /// This package's own detectors were hooked.
        public static let hookSelfIntegrity = Kind(.hookSelfIntegrity)
        /// A dynamic library you did not ship is loaded from inside the app bundle.
        public static let hookUnexpectedBundleLibrary = Kind(.hookUnexpectedBundleLibrary)
        /// A system function the checks rely on was inline-patched to branch out of the OS.
        public static let hookInlinePatchedFunction = Kind(.hookInlinePatchedFunction)
        /// A system function the checks rely on is bound to code outside the OS (fishhook, interposing).
        public static let hookReboundSymbol = Kind(.hookReboundSymbol)

        // Integrity

        /// The bundle identifier is not the expected one.
        public static let integrityBundleIdentifierMismatch = Kind(.integrityBundleIdentifierMismatch)
        /// The app is signed by a different Team ID than expected.
        public static let integrityTeamIdentifierMismatch = Kind(.integrityTeamIdentifierMismatch)
        /// The binary is not FairPlay-encrypted although an App Store build must be.
        public static let integrityBinaryDecrypted = Kind(.integrityBinaryDecrypted)
        /// The code section's digest is not one of the expected digests.
        public static let integrityTextSegmentModified = Kind(.integrityTextSegmentModified)
        /// The build carries `get-task-allow`, so any debugger can attach.
        public static let integrityDebuggableBuild = Kind(.integrityDebuggableBuild)
        /// An App Store build must not contain an embedded provisioning profile.
        public static let integrityUnexpectedProvisioningProfile = Kind(.integrityUnexpectedProvisioningProfile)
        /// The Team ID could not be read from the code signature.
        public static let integrityTeamIdentifierUnavailable = Kind(.integrityTeamIdentifierUnavailable)
        /// The code section could not be read, so its digest could not be checked.
        public static let integrityTextSegmentUnavailable = Kind(.integrityTextSegmentUnavailable)
        /// An embedded library's code section digest is not one of the expected digests.
        public static let integrityImageModified = Kind(.integrityImageModified)
        /// An embedded library listed in the expected digests is not loaded or cannot be read.
        public static let integrityImageUnavailable = Kind(.integrityImageUnavailable)

        // Network

        /// An HTTP, HTTPS, SOCKS or auto-config (PAC) proxy is configured.
        public static let networkProxy = Kind(.networkProxy)
    }

    /// The detector family a threat belongs to.
    public enum Category: String, CaseIterable, Hashable, Sendable, Codable {
        /// Where the process runs. Always informational.
        case environment
        case jailbreak
        case debugger
        case hooking
        case integrity
        case network
    }

    /// How seriously to take a threat. ``high`` and ``critical`` mean the environment is not trustworthy.
    public enum Severity: Int, CaseIterable, Hashable, Sendable, Codable, Comparable {
        /// Context only. Never a threat on its own.
        case info
        /// A weak signal that legitimate software can also produce.
        case low
        /// Suspicious, but not conclusive on its own.
        case medium
        /// A strong indicator of a compromised environment.
        case high
        /// A conclusive indicator.
        case critical

        public static func < (lhs: Severity, rhs: Severity) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    /// What was found.
    public let kind: Kind

    /// The detector family.
    public let category: Category

    /// How seriously to take it.
    public let severity: Severity

    /// Dotted machine-readable name such as `jailbreak.artifact`, for analytics.
    public let identifier: String

    /// Specifics such as the matching path or library. For logs only: do not show it to end users and do
    /// not parse it.
    public let detail: String?

    public init(kind: Kind, category: Category, severity: Severity, identifier: String, detail: String? = nil) {
        self.kind = kind
        self.category = category
        self.severity = severity
        self.identifier = identifier
        self.detail = detail
    }

    public var description: String {
        guard let detail else { return "\(identifier) [\(severity)]" }
        return "\(identifier) [\(severity)]: \(detail)"
    }
}
