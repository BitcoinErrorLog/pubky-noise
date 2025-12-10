// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "PubkyNoise",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "PubkyNoise",
            targets: ["PubkyNoise", "PubkyNoiseFFI"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "PubkyNoiseFFI",
            path: "./PubkyNoise.xcframework"
        ),
        .target(
            name: "PubkyNoise",
            dependencies: ["PubkyNoiseFFI"],
            path: "Sources/PubkyNoise"
        ),
    ]
)

