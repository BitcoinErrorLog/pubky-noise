# FFI Bindings

This directory contains Foreign Function Interface (FFI) bindings for mobile platforms.

## Modules

| File | Description |
|------|-------------|
| `mod.rs` | Module root and re-exports |
| `manager.rs` | `FfiNoiseManager` - Thread-safe FFI wrapper |
| `types.rs` | FFI-safe type conversions |
| `errors.rs` | `FfiNoiseError` - FFI error type |
| `config.rs` | Configuration helpers and key derivation |

## Usage

Enable the `uniffi_macros` feature to build FFI bindings:

```bash
cargo build --release --features uniffi_macros
```

## Platform Scripts

- `../../build-ios.sh` - Build iOS XCFramework
- `../../build-android.sh` - Build Android AAR

## Architecture

```
FfiNoiseManager
    └── Arc<Mutex<NoiseManager<DummyRing>>>
        └── NoiseClient / NoiseServer
```

The FFI layer provides:
- Thread-safe access via `Arc<Mutex<>>`
- Type conversion (Rust ↔ FFI-safe types)
- Error mapping (`NoiseError` → `FfiNoiseError`)
- Hex encoding for session IDs

## See Also

- [FFI_CHANGELOG.md](../../FFI_CHANGELOG.md) - FFI-specific changelog
- [docs/FFI_GUIDE.md](../../docs/FFI_GUIDE.md) - FFI integration guide
- [docs/MOBILE_INTEGRATION.md](../../docs/MOBILE_INTEGRATION.md) - Mobile guide

