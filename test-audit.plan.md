<!-- ce9550bd-7e69-44b5-bb94-b567d7472789 c9239871-fc82-4a92-b4ce-ed3738649acd -->
# Create Comprehensive Testing & Audit Plan

## Overview

Create a production-ready `TESTING_AND_AUDIT_PLAN.md` document that serves as a permanent reference for code auditing and review across all Paykit, Pubky, and related projects. This document will incorporate the 7-stage audit methodology while being tailored to the specific tech stack.

## Document Structure

### Section 1: Introduction & Purpose

- Document scope and applicability
- When to use this plan (between phases, before releases, during reviews)
- How to use this plan (checklist vs deep audit)

### Section 2: Quick Reference Checklist

- One-page quick checklist for rapid sweeps
- Pass/fail criteria for each category
- Essential commands to run

### Section 3: Stage 1 - Threat Model & Architecture Review

- How to assess threat models for each component type:
- Core libraries (paykit-lib, pubky-noise)
- FFI boundaries (mobile, WASM)
- Network protocols (Noise, PKARR)
- Storage layers
- Architecture simplicity assessment
- Rust "pit of success" patterns
- Document existing threat models and reference examples

### Section 4: Stage 2 - Cryptography Audit (Zero Tolerance)

- Constant-time execution verification
- Side-channel resistance checklist
- API misuse prevention review
- Key management audit (generation, rotation, storage, zeroization)
- Authenticated encryption verification
- Banned primitives detection
- Required justifications and citations
- Specific checks for:
- Snow/Noise Protocol usage
- Ed25519/X25519 operations
- BLAKE2, HKDF usage
- Nonce/IV management

### Section 5: Stage 3 - Rust Safety & Correctness Audit

- `unsafe` block justification requirements
- Send/Sync correctness for concurrent code
- Pin, lifetime, variance audits
- Interior mutability review (RefCell, Cell, Mutex, etc.)
- Panic safety assessment
- Drop order and leak freedom
- Async cancellation safety
- FFI boundary safety (UniFFI for mobile, wasm-bindgen for web)

### Section 6: Stage 4 - Testing Requirements (Non-Negotiable)

- Coverage requirements and measurement
- Property-based testing with proptest
- Fuzz testing targets (cargo-fuzz)
- Integration test requirements:
- Multi-node distributed scenarios
- Network partition simulation
- Concurrency testing (loom for async)
- Doctest completeness
- Test naming conventions
- Test result verification

### Section 7: Stage 5 - Documentation & Commenting (Audit-Ready)

- Public API documentation requirements
- Safety precondition documentation
- Threat model considerations in docs
- Example code requirements (must compile)
- Private function commenting standards
- Crate-level README requirements
- Fuzzing guide requirements

### Section 8: Stage 6 - Build & CI Verification

- Required Cargo.toml configurations
- Build commands that must pass
- Platform-specific builds (WASM, Android, iOS)
- Clippy configuration and enforcement
- Rustfmt configuration
- Cargo-audit integration
- Warning-free compilation requirements

### Section 9: Stage 7 - Final Structured Output Template

- Threat model summary template
- Critical issues reporting format
- Verification checklist template
- Sign-off format

### Section 10: Code Completeness Checks

- TODO/FIXME/PLACEHOLDER detection
- `#[ignore]` test detection
- `unwrap()`/`expect()`/`panic!()` in production code
- Incomplete implementations detection
- Lost functionality verification

### Section 11: Stack-Specific Considerations

#### Distributed Systems Checks

- Consensus safety
- Partition tolerance
- Eventual consistency verification
- DHT-specific tests (PKARR)

#### Mobile FFI Checks

- UniFFI binding correctness
- Memory management across FFI
- Error propagation
- Thread safety for callbacks
- Platform-specific testing (Android, iOS)

#### WebAssembly Checks

- wasm-pack build verification
- JS bindings type safety
- Memory limits
- No blocking operations
- panic=abort configuration

#### Pubky-Specific Checks

- Homeserver compliance
- Auth flow correctness
- Storage quota enforcement
- Path validation
- Session management

## Implementation Details

The document will include:

- **Concrete examples** from existing codebase (audit-full.sh, property_tests.rs)
- **Runnable commands** for each verification step
- **Pass/fail criteria** with specific thresholds
- **Remediation guidance** for common issues
- **References** to existing threat models and documentation
- **Templates** for creating new tests and documentation

## File Location

`TESTING_AND_AUDIT_PLAN.md` in the root of each major workspace (paykit-rs-master, pubky-noise-main, pubky-core-main)

## References

- Existing `audit-full.sh` script
- `THREAT_MODEL.md` in pubky-noise
- `AGENTS.md` repository guidelines
- Property test examples in pubky-noise
- Integration test patterns across projects