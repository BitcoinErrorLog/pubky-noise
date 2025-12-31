# tests

Test suite for `pubky-noise`.

This folder contains unit, integration, concurrency (Loom), and fuzz-adjacent regression tests covering:

- Handshake flows (XX/IK) and identity binding
- Replay protection and policy enforcement
- Storage-backed messaging (when enabled)
- UniFFI boundary behavior and error mapping

Run tests from the repository root using Cargo commands described in `BUILD.md`.


