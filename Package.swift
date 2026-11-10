// swift-tools-version: 6.0

//
//  Package.swift
//  IOSSecurityCore
//
//  Created by Kashif Hussain on 2026-11-10.
//  Copyright © 2026 Kashif Hussain. MIT License.
//

import PackageDescription

let package = Package(
    name: "IOSSecurityCore",
    platforms: [
        .iOS(.v16),
        // macOS is declared so `swift build` / `swift test` work on a developer machine or CI runner.
        // On macOS every detector reports "unsupported platform" and performs no checks.
        .macOS(.v13)
    ],
    products: [
        // Swift-friendly API. Depends on (and therefore links) the Objective-C layer.
        .library(
            name: "IOSSecurityCore",
            targets: ["IOSSecurityCore"]),
        // The Objective-C runtime layer on its own, for Objective-C or mixed-language host apps.
        .library(
            name: "IOSSecurityCoreObjC",
            targets: ["IOSSecurityCoreObjC"]),
    ],
    targets: [
        // Objective-C layer: every detector, the obfuscation macros and the privacy manifest.
        // Public headers live in `include/`; everything under `Internal/` stays private.
        .target(
            name: "IOSSecurityCoreObjC",
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("Internal")
            ],
            linkerSettings: [
                // CFNetworkCopySystemProxySettings (network checks).
                .linkedFramework("CFNetwork")
            ]),
        // Swift layer: idiomatic, Sendable, async-first facade over the Objective-C layer. Swift 6 language
        // mode (the tools-version default), so data races are compile errors.
        .target(
            name: "IOSSecurityCore",
            dependencies: ["IOSSecurityCoreObjC"]),
        .testTarget(
            name: "IOSSecurityCoreTests",
            dependencies: ["IOSSecurityCore", "IOSSecurityCoreObjC"]),
        .testTarget(
            name: "IOSSecurityCoreObjCTests",
            dependencies: ["IOSSecurityCoreObjC"]),
    ]
)
