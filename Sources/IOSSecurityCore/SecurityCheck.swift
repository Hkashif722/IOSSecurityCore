//
//  SecurityCheck.swift
//  IOSSecurityCore
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import Foundation
import IOSSecurityCoreObjC

/// A family of runtime checks the engine can run.
public enum SecurityCheck: String, CaseIterable, Hashable, Sendable, Codable {
    /// Jailbreak artifacts, tweak injection and a weakened sandbox.
    case jailbreak
    /// An attached debugger.
    case debugger
    /// Instrumentation frameworks (Frida, Cycript, ...), injected libraries and swizzled methods.
    case hooking
    /// A re-signed, repackaged, cracked or patched app.
    case integrity
    /// Traffic interception: a configured HTTP, HTTPS, SOCKS or auto-config proxy.
    case network
}

extension SecurityCheck {
    var objcValue: ISCChecks {
        switch self {
        case .jailbreak: return .jailbreak
        case .debugger: return .debugger
        case .hooking: return .hooking
        case .integrity: return .integrity
        case .network: return .network
        }
    }
}

extension Set where Element == SecurityCheck {
    /// The Objective-C option set equivalent.
    var objcValue: ISCChecks {
        reduce(into: ISCChecks()) { $0.formUnion($1.objcValue) }
    }

    /// The checks present in an Objective-C option set.
    init(objc checks: ISCChecks) {
        self.init(SecurityCheck.allCases.filter { checks.contains($0.objcValue) })
    }
}
