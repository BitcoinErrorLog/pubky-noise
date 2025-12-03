# Platform Support

This directory contains platform-specific bindings and examples.

## Platforms

### iOS

Located in `ios/`:
- `Package.swift` - Swift Package Manager configuration
- `example/BasicExample.swift` - Usage example

Build: `./build-ios.sh`

### Android

Located in `android/`:
- `build.gradle.kts` - Gradle build configuration
- `settings.gradle.kts` - Project settings
- `example/MainActivity.kt` - Usage example

Build: `./build-android.sh`

## Build Requirements

### iOS
- macOS
- Xcode 14+
- Rust targets: `aarch64-apple-ios`, `x86_64-apple-ios`, `aarch64-apple-ios-sim`

### Android
- Android NDK (set `ANDROID_NDK_HOME`)
- Rust targets: `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`

## Output

After building:
- iOS: XCFramework in `platforms/ios/`
- Android: AAR with JNI libs in `platforms/android/`

## See Also

- [docs/IOS_INTEGRATION.md](../docs/IOS_INTEGRATION.md)
- [docs/ANDROID_INTEGRATION.md](../docs/ANDROID_INTEGRATION.md)
- [docs/MOBILE_INTEGRATION.md](../docs/MOBILE_INTEGRATION.md)

