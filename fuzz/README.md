# Fuzz Testing for pubky-noise

This directory contains fuzz targets for testing `pubky-noise` against malformed and adversarial inputs.

## Prerequisites

Install `cargo-fuzz`:

```bash
cargo install cargo-fuzz
```

You'll need a nightly Rust toolchain:

```bash
rustup install nightly
```

## Available Fuzz Targets

| Target | Description |
|--------|-------------|
| `fuzz_identity_payload` | Tests `make_binding_message` with arbitrary inputs |
| `fuzz_kdf` | Tests key derivation functions (HKDF, X25519) |
| `fuzz_handshake` | Tests Noise_IK handshake with malformed messages |
| `fuzz_noise_link` | Tests encrypt/decrypt with malformed ciphertexts |

## Running Fuzz Tests

### Basic Usage

```bash
cd fuzz
cargo +nightly fuzz run fuzz_identity_payload
cargo +nightly fuzz run fuzz_kdf
cargo +nightly fuzz run fuzz_handshake
cargo +nightly fuzz run fuzz_noise_link
```

### Run All Targets

```bash
for target in fuzz_identity_payload fuzz_kdf fuzz_handshake fuzz_noise_link; do
    cargo +nightly fuzz run $target -- -max_total_time=60
done
```

### With Time Limit

```bash
# Run for 5 minutes
cargo +nightly fuzz run fuzz_handshake -- -max_total_time=300
```

### With Dictionary

For better coverage, you can provide a dictionary of interesting inputs:

```bash
cargo +nightly fuzz run fuzz_handshake -- -dict=dictionaries/noise.dict
```

## Corpus

Interesting inputs are stored in `fuzz/corpus/<target_name>/`. You can seed the corpus with known edge cases:

```bash
mkdir -p corpus/fuzz_handshake
echo -n "known_edge_case" > corpus/fuzz_handshake/edge1
```

## Crash Artifacts

When a crash is found, artifacts are saved to `fuzz/artifacts/<target_name>/`. To reproduce:

```bash
cargo +nightly fuzz run fuzz_handshake artifacts/fuzz_handshake/crash-xxxxx
```

## Coverage

Generate coverage reports:

```bash
cargo +nightly fuzz coverage fuzz_handshake
```

## Security Considerations

These fuzz targets verify:

1. **No Panics**: Functions should return errors, not panic
2. **Determinism**: Same inputs should produce same outputs
3. **Memory Safety**: No buffer overflows or use-after-free
4. **Cryptographic Properties**: 
   - X25519 key clamping
   - Encrypt/decrypt roundtrip
   - Authentication tag verification

## Adding New Targets

1. Create a new file in `fuzz_targets/`
2. Add the target to `Cargo.toml`
3. Follow the pattern:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct Input {
    // Define your input structure
}

fuzz_target!(|input: Input| {
    // Test code that should not panic
});
```

## Continuous Fuzzing

For CI integration, use OSS-Fuzz or run periodically:

```yaml
# GitHub Actions example
- name: Fuzz
  run: |
    cd fuzz
    cargo +nightly fuzz run fuzz_handshake -- -max_total_time=120
```

