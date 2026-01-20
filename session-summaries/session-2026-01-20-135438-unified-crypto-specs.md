# Session Summary: Unified Crypto Specs (Launch-Ready)

**Date/Time**: 2026-01-20 13:54:38  
**Workspace/Repos**: `pubky-core`, `atomicity-research` (also touched via `/sync`: pubky-noise, pubky-ring, paykit-rs, bitkit-android, bitkit-ios, pubky-app-specs, vss-rust-client-ffi, bitkit-core, atomicity-core, atomicity-mobile, pubky-locks)  
**Primary Goal**: Reconcile `PUBKY_CRYPTO_SPEC` (root), `PUBKY_UNIFIED_KEY_DELEGATION_SPEC_v0.2` (proposal/extension), and `Atomicity Specification` (application) so crypto requirements are consistent, minimal, and launch-ready (no legacy/deprecation text), then sync to BitcoinErrorLog forks.

## Work Completed

### `pubky-core/docs/PUBKY_CRYPTO_SPEC.md` (modified)
- **Resolved InboxKey vs TransportKey role confusion**:
  - Made InboxKey/TransportKey separation **normative** in Section 4.7.
- **KeyBinding made app-scoped + canonical encoding**:
  - Updated Section 6.8.1 to include `app_id` and require Deterministic CBOR encoding.
- **Added AppKey discovery via KeyBinding**:
  - Added Section 6.8.5 defining `app_keys[]` and AppCert discovery flow.
- **Added signing hierarchy table**:
  - Added Section 7.6.1 “Signing Hierarchy” as the cross-spec authoritative policy.
- **Added Sealed Blob delegated signature support**:
  - Added header field `cert_id` (key 11) and Section 7.2.2 to allow AppKey signing of Sealed Blob header `sig`.
- **Ring typed signing policy**:
  - Added Section 5.3.5 “Typed Signing API” (no “sign arbitrary bytes”).
- **Launch-ready cleanup**:
  - Removed migration/deprecated/single-key compatibility content and adjusted wording to avoid “legacy/backward compat” framing.
- **Added cross-refs + implementation impact appendix**:
  - Added “Related Specifications” section and Appendix E “Implementation Impact (Non-Normative)”.

### `pubky-core/docs/PUBKY_UNIFIED_KEY_DELEGATION_SPEC_v0.2.md` (modified)
- **Aligned as a clean extension of the root spec**:
  - Added “How This Extends PUBKY_CRYPTO_SPEC” section.
- **Terminology alignment**:
  - Normalized to `transport_x25519_pub` and `inbox_x25519_pub`.
- **Single discovery root**:
  - Discovery phrasing updated to rely on KeyBinding `app_keys[]` as the primary mechanism.
- **Launch-ready cleanup**:
  - Removed “Migration Notes” and “fallback/backward compatibility” phrasing where it was purely legacy framing.

### `atomicity-research/Atomicity Specification.md` (modified)
- **Removed duplicated key discovery pattern**:
  - Replaced prior `noise_key_binding` discovery approach with KeyBinding-based discovery (Section 2.2.2).
- **Corrected encryption targets**:
  - Replaced “encrypt to Noise pubkey” language to “encrypt to InboxKey” (stored delivery).
- **Covenant authenticity model clarified**:
  - Live flow: authenticated by Noise session.
  - Offline/stored artifact: AppKey signature via AppCert.
- **Idempotency mapping**:
  - Added normative mapping so Sealed Blob header `msg_id` matches payload `request_id`.
- **Launch-ready cleanup**:
  - Removed deprecated/migration text and removed “legacy client” failure-mode language, replacing it with deterministic timeout/retry behavior.

## Commands Run
- `/Users/john/vibes-dev/scripts/sync-repos.sh` (requested via `/sync`)
  - **Result**: ✅ All push remotes verified to be `github.com/BitcoinErrorLog/*`
  - **Outcome**:
    - `pubky-core`: committed + pushed changes
    - `atomicity-research`: committed + pushed changes
    - all other audited repos: already up to date

## Current State
- **Specs updated and accepted by user**:
  - `pubky-core/docs/PUBKY_CRYPTO_SPEC.md`
  - `pubky-core/docs/PUBKY_UNIFIED_KEY_DELEGATION_SPEC_v0.2.md`
  - `atomicity-research/Atomicity Specification.md`
- **Sync status**: ✅ completed, 0 failures
- **Build/tests/lints**: Not run (spec-only markdown changes).
- **Last action**: `/sync` succeeded; commits were created by the sync script and pushed to BitcoinErrorLog forks.

## Pending Work
- None requested/left unfinished for this session.

## Key Decisions & Context
- **Single discovery root**: Key discovery is unified around **KeyBinding** (app-scoped).
- **Strict key role separation**: InboxKey (Sealed Blob stored delivery) vs TransportKey (Noise) separation is treated as current/normative.
- **RootKey semi-cold**: RootKey signs binding artifacts; AppKey used for typed/offline verifiable signatures; Noise session auth for live flows.
- **No legacy framing for launch**: Removed deprecated/compat sections so specs read as “current” for public launch.
- **Sync safety**: Only push to BitcoinErrorLog; script performed pre-flight checks.

## Relevant Code Locations
- `pubky-core/docs/PUBKY_CRYPTO_SPEC.md`
  - Key separation: Section 4.7
  - KeyBinding: Section 6.8.1
  - AppKey discovery: Section 6.8.5
  - Sealed Blob header: Section 7.2 (incl. `cert_id`)
  - Signing hierarchy: Section 7.6.1
  - Typed signing policy: Section 5.3.5
  - Implementation impact: Appendix E
- `pubky-core/docs/PUBKY_UNIFIED_KEY_DELEGATION_SPEC_v0.2.md`
  - Extension relationship section + AppCert discovery wording
- `atomicity-research/Atomicity Specification.md`
  - Key discovery: Section 2.2.2
  - Covenant authenticity + idempotency mapping updates

## Quick Start for Next Session
- Read:
  - `pubky-core/docs/PUBKY_CRYPTO_SPEC.md` (Sections 4.7, 6.8.1, 6.8.5, 7.2.2, 7.6.1)
  - `pubky-core/docs/PUBKY_UNIFIED_KEY_DELEGATION_SPEC_v0.2.md` (extension alignment + AppCert discovery)
  - `atomicity-research/Atomicity Specification.md` (KeyBinding usage + covenant model)
- Verify repo state:
  - Run `/Users/john/vibes-dev/scripts/sync-repos.sh --status`
- Next logical step:
  - If desired, implement the spec requirements in code (KeyBinding publishing/parsing, `cert_id` header field handling, typed signing surface in Ring, and Atomicity KeyBinding fetch helpers).

