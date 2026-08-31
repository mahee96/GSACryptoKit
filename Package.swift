// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "GSACryptoKit",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
        .tvOS(.v14),
        .watchOS(.v7),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "GSACryptoKit",
            targets: ["GSACryptoKit"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.3.1")
    ],
    targets: [
        .binaryTarget(
            name: "OpenSSL",
            url: "https://github.com/krzyzanowskim/OpenSSL/releases/download/3.6.2000/OpenSSL.xcframework.zip",
            checksum: "37846a8bd302cb2443eff47f1045ab844d0cd40bf82cc6159cfad9aa5c3eff9e"
        ),
        .target(
            name: "GSACryptoKit",
            dependencies: [
                .product(name: "Crypto",        package: "swift-crypto"),
                .product(name: "CryptoExtras",  package: "swift-crypto")
            ],
            path: "Sources"
        ),
        .testTarget(
            name: "GSACryptoKitTests",
            dependencies: [
                "GSACryptoKit",
                .product(name: "Crypto",        package: "swift-crypto"),
                .product(name: "CryptoExtras",  package: "swift-crypto"),
                .target(name: "OpenSSL")
            ],
            path: "Tests"
        )
    ]
)
