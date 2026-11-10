import Foundation

/// Everything that tunes the engine. The defaults are safe to ship unchanged; the `expected…` values
/// switch on checks that need to know something about *your* app.
///
/// ```swift
/// var configuration = SecurityConfiguration()
/// configuration.expectedBundleIdentifier = "com.example.app"
/// configuration.expectedTeamIdentifier = "ABCDE12345"
/// SecurityEngine.shared.configure(configuration)
/// ```
public struct SecurityConfiguration: Sendable {

    /// How the app is distributed. Drives the integrity checks that only make sense for one channel.
    public enum Distribution: Sendable {
        /// Make no assumption.
        case any
        /// App Store or TestFlight: no embedded provisioning profile, an encrypted binary and no
        /// `get-task-allow`. Set this **only for release builds**; an Xcode build violates all three.
        case appStore
    }

    /// An Objective-C method whose implementation must stay inside a known set of images.
    ///
    /// If a tweak or instrumentation framework swizzles it, the implementation moves into the attacker's
    /// image and the engine reports ``SecurityThreat/Kind/hookSwizzledMethod``.
    public struct ProtectedMethod: Hashable, Sendable {
        /// Whether the method is an instance (`-`) or class (`+`) method.
        public enum Scope: Hashable, Sendable {
            case instance
            case `class`
        }

        /// The class that declares the method, as accepted by `NSClassFromString`.
        public var className: String

        /// The selector, for example `isUserAuthenticated` or `validateToken:`.
        public var selector: String

        public var scope: Scope

        /// Path prefixes the implementation may live under. When empty, the app bundle is used. For
        /// system classes pass `["/System/", "/usr/lib/"]`.
        public var allowedImagePathPrefixes: [String]

        public init(
            className: String,
            selector: String,
            scope: Scope = .instance,
            allowedImagePathPrefixes: [String] = []
        ) {
            self.className = className
            self.selector = selector
            self.scope = scope
            self.allowedImagePathPrefixes = allowedImagePathPrefixes
        }
    }

    // MARK: General

    /// The check families to run. Default: all.
    public var checks: Set<SecurityCheck> = Set(SecurityCheck.allCases)

    /// When `false`, the built-in indicator lists and heuristics (including the parent-process check and
    /// the system-function verification) are skipped and only the custom entries are used. Intended for
    /// tests. Default: `true`.
    public var includesBuiltInIndicators = true

    /// Run the checks on the Simulator, on macOS and under Mac Catalyst too. Their results are not
    /// meaningful there (the Simulator exposes the Mac's file system, for example). Intended for tests and
    /// tooling. Default: `false`.
    public var scansUnsupportedEnvironments = false

    // MARK: Jailbreak

    /// Extra file-system paths whose presence indicates a compromised device.
    public var additionalSuspiciousPaths: [String] = []

    /// Try to create a file outside the sandbox. Only succeeds when the sandbox is broken, and the file is
    /// removed immediately. Default: `true`.
    public var performsSandboxWriteProbe = true

    /// Call `fork()`, which the stock sandbox forbids. A successful child exits immediately. Default: `true`.
    public var performsForkProbe = true

    /// Extra Objective-C class names that only a jailbreak-detection bypass tool or tweak registers. A
    /// tweak can hide its files and its library, but its classes stay registered with the runtime.
    /// Reported as ``SecurityThreat/Kind/jailbreakBypassTool``.
    public var additionalSuspiciousClasses: [String] = []

    /// Probe the loopback interface for an SSH server (port 22) or checkra1n's shell (port 44). Nothing
    /// listens there on a stock device. Never leaves the device. Default: `true`.
    public var probesRemoteShellPorts = true

    // MARK: Hooking

    /// Extra substrings; a loaded image whose path contains one (case-insensitive) is reported as an
    /// instrumentation library.
    public var additionalSuspiciousLibraries: [String] = []

    /// Extra path prefixes treated as trusted when looking for unknown images, on top of the system
    /// locations and the app bundle.
    public var allowedImagePathPrefixes: [String] = []

    /// Report images that come from neither the system nor the app bundle. Default: `true`.
    public var reportsUnknownLibraries = true

    /// File names of every dynamic library you embed in the app bundle, for example `Auth.framework/Auth`
    /// or `libFoo.dylib`. When non-empty, any other image loaded from inside the bundle is reported: the
    /// effective defence against a repackaged app with an injected dylib. Default: empty (off).
    public var allowedBundleLibraries: [String] = []

    /// Probe the loopback interface for a listening `frida-server`. Never leaves the device. Default: `true`.
    public var probesInstrumentationPorts = true

    /// Methods whose implementations must not move.
    public var protectedMethods: [ProtectedMethod] = []

    // MARK: Integrity

    /// The bundle identifier the app must ship with. A mismatch means the app was re-signed.
    public var expectedBundleIdentifier: String?

    /// The Apple developer Team ID the app must be signed with, read from the app's own code signature.
    public var expectedTeamIdentifier: String?

    /// Lowercase hex SHA-256 digests of the release binary's `__TEXT,__text` section (see
    /// `Scripts/text-digest.swift`). A running binary whose digest is not listed was modified. Computing
    /// the digest reads the whole code section, so use it for release builds only. Default: empty (off).
    public var expectedTextSegmentDigests: Set<String> = []

    /// Expected `__TEXT,__text` digests of embedded dynamic libraries, keyed by the library's trailing
    /// path components (for example `"Auth.framework/Auth"`). Libraries inside the app bundle are matched
    /// first. Compute the values with `Scripts/text-digest.swift` or
    /// ``SecurityEngine/textSegmentDigest(ofImageNamed:)``. Default: empty (off).
    public var expectedImageTextDigests: [String: Set<String>] = [:]

    /// How the app is distributed. Default: ``Distribution/any``.
    public var expectedDistribution: Distribution = .any

    // MARK: Presets

    /// The default configuration.
    public static let `default` = SecurityConfiguration()

    public init() {}
}
