import Foundation
import IOSSecurityCoreObjC

/// Raw facts about the running app, for a server to judge.
///
/// A check performed inside the app can be patched out by whoever controls the device. The same facts
/// judged on a server cannot. Send this (it is `Codable`) together with an Apple App Attest assertion and
/// compare it with what you shipped.
public struct IntegritySignals: Hashable, Sendable, Codable {

    /// `CFBundleIdentifier` of the main bundle.
    public let bundleIdentifier: String?

    /// The Team ID in the app's own code signature, or `nil` when it cannot be read.
    public let teamIdentifier: String?

    /// Whether the main executable is FairPlay-encrypted, or `nil` when that is unknown. App Store and
    /// TestFlight builds are encrypted; development builds and dumped copies are not.
    public let isBinaryEncrypted: Bool?

    /// Whether the app carries an `embedded.mobileprovision`. App Store and TestFlight builds do not.
    public let hasEmbeddedProvisioningProfile: Bool

    /// The `get-task-allow` entitlement: `true` means any debugger can attach. `nil` when the entitlements
    /// cannot be read.
    public let isDebuggable: Bool?

    /// Lowercase hex SHA-256 of the `__TEXT,__text` section. Present only when requested.
    public let textSegmentDigest: String?

    static func collect(includingTextDigest: Bool) -> IntegritySignals {
        let entitlements = ISCIntegrityChecker.codeSigningEntitlements
        let encryption: Bool? = {
            switch ISCIntegrityChecker.binaryEncryptionState {
            case .encrypted: return true
            case .decrypted: return false
            case .unknown: return nil
            @unknown default: return nil
            }
        }()
        return IntegritySignals(
            bundleIdentifier: Bundle.main.bundleIdentifier,
            teamIdentifier: ISCIntegrityChecker.codeSigningTeamIdentifier,
            isBinaryEncrypted: encryption,
            hasEmbeddedProvisioningProfile: ISCIntegrityChecker.embeddedProvisioningProfile != nil,
            isDebuggable: entitlements.map { ($0["get-task-allow"] as? NSNumber)?.boolValue ?? false },
            textSegmentDigest: includingTextDigest ? ISCIntegrityChecker.textSegmentDigest : nil
        )
    }
}
