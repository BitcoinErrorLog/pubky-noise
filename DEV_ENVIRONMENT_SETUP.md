# Development Environment Setup for pubky-noise

This guide will help you set up a complete development environment for testing `pubky-noise`.

## Prerequisites

### macOS (Your System)

#### 1. Install Homebrew (if not installed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

After installation, follow the instructions to add Homebrew to your PATH.

#### 2. Install Rust via rustup

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Select option 1 (default installation) when prompted.

After installation, restart your terminal or run:

```bash
source ~/.cargo/env
```

Verify installation:

```bash
rustc --version
cargo --version
```

#### 3. Install Additional Build Tools

```bash
# Install required system libraries
brew install openssl pkg-config

# For FFI/mobile builds (optional)
brew install protobuf
```

#### 4. Configure Rust Toolchain

```bash
# Ensure you have the latest stable toolchain
rustup update stable
rustup default stable

# Install useful components
rustup component add clippy rustfmt

# For iOS builds (optional)
rustup target add aarch64-apple-ios x86_64-apple-ios

# For Android builds (optional)
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
```

## Verification

Once setup is complete, run these commands from the `pubky-noise` directory:

```bash
cd ~/Library/Mobile\ Documents/com~apple~CloudDocs/vibes/synonymdev/pubky-noise

# Format code
cargo fmt

# Run linter
cargo clippy --all-targets --all-features

# Run tests
cargo test

# Build documentation
cargo doc --no-deps --open
```

## Quick Test Commands

```bash
# Run specific test file
cargo test --test cold_key_patterns

# Run specific test
cargo test test_ik_raw_handshake

# Run tests with output
cargo test -- --nocapture

# Run tests in release mode (faster)
cargo test --release

# Check compilation without building
cargo check --all-targets --all-features
```

## Troubleshooting

### "cargo: command not found"

Your shell doesn't have Cargo in the PATH. Run:

```bash
source ~/.cargo/env
```

Or add this to your `~/.zshrc`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

### OpenSSL Errors

If you see OpenSSL-related errors:

```bash
export OPENSSL_DIR=$(brew --prefix openssl)
export PKG_CONFIG_PATH="$OPENSSL_DIR/lib/pkgconfig"
```

### Permission Issues on iCloud Drive

The project is stored in iCloud Drive. If you experience sync issues:

1. Wait for files to download (cloud icon should disappear)
2. Or move the project to a local folder:

```bash
cp -r ~/Library/Mobile\ Documents/com~apple~CloudDocs/vibes/synonymdev/pubky-noise ~/dev/pubky-noise
cd ~/dev/pubky-noise
```

## IDE Setup (Optional)

### VS Code

Install the rust-analyzer extension:
- Extension ID: `rust-lang.rust-analyzer`

### Cursor

Cursor has built-in Rust support. Ensure you have:
- rust-analyzer installed (should be automatic)
- Format on save enabled for `.rs` files

## Environment Variables

For full functionality, you may want these in your `~/.zshrc`:

```bash
# Rust
export PATH="$HOME/.cargo/bin:$PATH"
source "$HOME/.cargo/env"

# Better compiler messages
export RUST_BACKTRACE=1

# Parallel compilation
export CARGO_BUILD_JOBS=$(sysctl -n hw.ncpu)
```

## Next Steps

After setup, you can:

1. Run the full test suite: `cargo test`
2. Run clippy for code quality: `cargo clippy`
3. Build the project: `cargo build`
4. Generate and view docs: `cargo doc --open`

For mobile builds, see `BUILD.md` for iOS/Android specific instructions.

