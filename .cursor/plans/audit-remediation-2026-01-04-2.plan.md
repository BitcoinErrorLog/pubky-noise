# Remediation Plan: E2E harness consistency (Profiles/Contacts)

**Created**: 2026-01-04

**Source**: `/audit` of `.cursor/plans/audit-remediation-2026-01-04-profiles-contacts-e2e.plan.md`

**Priority**: Critical - current E2E scripts are inconsistent and some cannot run---

## Summary

The “profiles/contacts E2E” folder currently contains **two competing harnesses**:

- **Config-based harness**: `run-all.sh` + `lib/common.sh` + `config/*.json` + `flows/android/*.yaml`
- **Fixtures-based harness**: `tests/00-import-identities.sh`, `tests/01-paykit-connect.sh`, and `lib/ui-automation.sh` using `fixtures/config.json`

These harnesses disagree on:

- how apps are launched (`adb_launch_app` called with **app keys** like `ring`, but implemented as an alias to a function expecting **package IDs**)
- which helper functions exist (`adb_tap_element`, `adb_wait_for_app`, `adb_screenshot`, etc are referenced but not implemented anywhere)
- which config is authoritative (`config/devices.json` vs `fixtures/config.json`, and `fixtures` contains a typo for Ring activity)

Result: several tests are still broken even if “command not found” for a couple functions was addressed.---

## Tasks

### 🔴 P1: Make Android launch + UI helpers consistent

- [ ] **P1.1**: Make `adb_launch_app` handle *both* signatures
- **Requirement**: Support:
    - `adb_launch_app <serial> <package> [activity]` (package IDs)
    - `adb_launch_app <serial> <appKey>` where `appKey in {ring, bitkit}` and resolves via loaded config
- **Acceptance**: All scripts calling `adb_launch_app ... ring|bitkit` do not mis-launch due to treating `ring|bitkit` as a package name
- [ ] **P1.2**: Provide `launch_app` alias (or migrate callers)
- **Requirement**: Either:
    - add `launch_app()` alias to the canonical Android launcher, **or**
    - update all scripts in `tests/` to use `launch_android_app`
- **Acceptance**: `tests/00-setup-identities.sh` and `tests/02-profile-android-to-android.sh` do not reference undefined `launch_app`
- [ ] **P1.3**: Implement or remove the missing `adb_*` helpers referenced by fixtures scripts
- **Requirement**: Either:
    - implement `adb_tap_element`, `adb_tap_text`, `adb_wait_for_text`, `adb_wait_for_app`, `adb_screenshot`, `adb_stop_app`, `adb_open_url`, `get_device_serial`, etc using `config/devices.json` and coordinate files, **or**
    - migrate/delete the fixtures-based scripts (only after confirming they are truly unused)
- **Acceptance**: `tests/00-import-identities.sh` + `tests/01-paykit-connect.sh` can execute without “command not found” for helper functions

### 🟡 P2: Unify configuration and fix known fixture typos

- [ ] **P2.1**: Choose and enforce one source of truth
- **Requirement**: Prefer `config/devices.json` + `config/identities.json` as canonical; mark `fixtures/config.json` as legacy or remove after migration
- **Acceptance**: There is exactly one documented way to configure devices/identities for profile/contact E2E
- [ ] **P2.2**: Fix `fixtures/config.json` Ring activity typo (if fixtures harness remains)
- **Acceptance**: Ring activity matches the installed app’s activity (no `to.pubkyring.*` typos)

### 🟢 P3: Documentation + traceability

- [ ] **P3.1**: Update `e2e-tests/README.md` to explicitly document supported scripts and legacy ones
- **Acceptance**: README clearly states which scripts work with `run-all.sh` and which are legacy/migrating
- [ ] **P3.2**: Create a new session summary for this remediation work
- **Acceptance**: A new file exists under `session-summaries/` describing the remediation changes and current E2E status

---

## Success Criteria

- [ ] `run-all.sh` references only scripts that use existing helpers (or helpers are implemented)
- [ ] All profile/contact E2E scripts share a single config source (`config/*.json`) and a single launcher API