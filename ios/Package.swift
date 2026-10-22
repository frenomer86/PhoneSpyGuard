// swift-tools-version:5.9
//
// Phone Spy Guard — iPhone companion.
//
// The logic lives in two plain Swift libraries so it builds and tests on any
// machine with a Swift toolchain (macOS, Linux, Windows), not only in Xcode:
//
//  - PSGCore       the Swift twin of the Kotlin core:detection + core:evidence
//                  and the Rust psg-core: facts, signed rule bundles, the bounded
//                  interpreter, four-level scoring and the hash-chained evidence
//                  log. Pinned to the other two by desktop/conformance/.
//  - PSGCompanion  what the iPhone companion does (FR-IOS-01..04): device
//                  posture, accounts audit, scam check, phone-number guidance and
//                  the on-phone diagnostic-archive (sysdiagnose) analysis.
//
// The SwiftUI app in App/ is a thin shell over these; it needs Xcode on a Mac.

import PackageDescription

let package = Package(
    name: "PhoneSpyGuardIOS",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "PSGCore", targets: ["PSGCore"]),
        .library(name: "PSGCompanion", targets: ["PSGCompanion"]),
        .executable(name: "psg-ios-check", targets: ["psg-ios-check"]),
    ],
    dependencies: [
        // On Apple platforms this re-exports CryptoKit; elsewhere it is the same
        // API over BoringSSL, so the Ed25519 / SHA-256 code is identical.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"4.0.0"),
    ],
    targets: [
        .target(
            name: "PSGCore",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
        .target(
            name: "PSGCompanion",
            dependencies: ["PSGCore"],
            resources: [.copy("Resources")]
        ),
        .executableTarget(
            name: "psg-ios-check",
            dependencies: ["PSGCore", "PSGCompanion"]
        ),
        .testTarget(
            name: "PSGCoreTests",
            dependencies: ["PSGCore", .product(name: "Crypto", package: "swift-crypto")]
        ),
        .testTarget(
            name: "PSGCompanionTests",
            dependencies: ["PSGCompanion", "PSGCore", .product(name: "Crypto", package: "swift-crypto")],
            resources: [.copy("Fixtures")]
        ),
    ]
)
