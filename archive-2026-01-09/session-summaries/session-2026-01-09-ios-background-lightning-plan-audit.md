# Audit Report: iOS Background Lightning Plans (merged master plan)

**Date**: 2026-01-09  
**Plan file audited**: `/Users/john/.cursor/plans/ios_background_lightning_plans_7f4d77e5.plan.md`  
**Repos audited for impact**:
- `bitkit-ios`
- `bitkit-android`
- `paykit-rs`
- `atomicity-mobile` (and references to `atomicity-core`)

## Executive summary (what will actually work)

The plan’s core diagnosis is correct: **an iOS Notification Service Extension is too memory-constrained to run LDK-node reliably** (Tokio + LDK-node runtime + caches tends to blow the extension’s memory ceiling).

The most production-safe path that meets the constraints “**no LDK modifications**” and “**don’t wait on Spiral infra**” is:

- **Phase 1 (≈2 weeks)**: **Stop doing Lightning ops in the Notification Service Extension.** Use it only to decrypt + display a high-urgency notification that tells the user to open the app to complete the receive. This avoids crashes/timeouts and preserves the usefulness of notifications.
- **Phase 1.5 (≈4–6 weeks)**: Add **silent push → wake the main app process** and do **best-effort** minimal node work (start → connect → wait briefly for receive → stop). This can materially improve success rates, but iOS still does not guarantee background execution.
- **Critical dependency for “as intended”**: If you want “receive while user doesn’t immediately open the app” to succeed more than “sometimes”, you will need an **LSP-side hold/parking behavior for inbound HTLCs on existing channels** long enough for the OS to wake the app and for the node to start (tens of seconds). Without it, senders will time out (~2s in the Slack context) before the wallet can come online.

The existing plan’s **Part 2 KMP-notification-extension Lightning claim** is **not currently grounded in the actual Lightning receive mechanics** and should be treated as **high-risk / likely pointless work** unless the protocol is redefined (which drifts into custody/trust or “rewrite a Lightning stack” territory).

## What is already true in the codebase (so we don’t do pointless work)

### bitkit-ios: background prerequisites already enabled

- **`UIBackgroundModes` already includes** `remote-notification`, `fetch`, `processing` in `Bitkit/Info.plist`.  
  This means the plan item “enable remote notifications background mode” is already satisfied at the plist level.

- **Keychain accessibility is already `AfterFirstUnlock`** for stored secrets in `Bitkit/Utilities/Keychain.swift`, and the entitlements include:
  - App Group: `group.bitkit`
  - Keychain access group: `$(AppIdentifierPrefix)to.bitkit`
  
  So the plan item “ensure AfterFirstUnlock” is already satisfied; keep it as a verification step, not an implementation step.

### bitkit-ios: deep-link plumbing exists for Paykit “payment-request”

`Bitkit/MainNavView.swift` already routes:
- `paykit:` scheme, and
- `bitkit://payment-request`

to `handlePaymentRequestDeepLink(...)`.

So “open the relevant Paykit request screen from a notification” is feasible without inventing new routing, **but only for `payment-request`**.

### bitkit-android: Paykit ProGuard rules already exist

`bitkit-android/app/proguard-rules.pro` already contains keep rules for:
- `uniffi.paykit_mobile.**`
- `uniffi.pubkycore.**`
- `com.pubky.noise.**`
- JNA (`com.sun.jna.**`)

So “add ProGuard rules” is already done for Android.

## High-signal issues / loose ends found (risk of production problems)

### 1) Plan pseudocode does not match the real `LightningService` API (bitkit-ios)

The master plan references methods that do not exist:
- `connectToBlocktankPeer()`
- `processEvents()`
- `persistState()`

In `bitkit-ios/Bitkit/Services/LightningService.swift`, the actual relevant primitives are:
- `start(onEvent:)`
- `connectToTrustedPeers()`
- `sync()`
- `stop()`

**Impact**: If this plan is implemented as-written, it will stall mid-flight (or introduce rushed “new APIs” to match the plan). The remediation plan below rewrites the background flow in terms of **existing methods**.

### 2) “Critical alert sound” is a likely App Store / entitlement trap

The plan mentions using `UNNotificationSound.defaultCritical(...)`.

**Reality**: Critical alerts require the entitlement `com.apple.developer.usernotifications.critical-alerts` and Apple approval. Absent that, this is either a no-op or a rejection risk.

**Recommendation**: Use `.timeSensitive` interruption level + default sound as the production-safe baseline. Treat critical alerts as “only if entitlement is obtained”.

### 3) iOS silent-push background handling is not wired in the real AppDelegate (today)

There is an `AppDelegate_integration.swift` file showing:
`application(_:didReceiveRemoteNotification:fetchCompletionHandler:)` delegating to `PipBackgroundHandler.shared`.

However, the live app uses SwiftUI `@main` with `@UIApplicationDelegateAdaptor` in `BitkitApp.swift`. The live `AppDelegate` currently implements:
- token registration
- `userNotificationCenter(...didReceive...)` for user taps
- URL handling

It does **not** implement `didReceiveRemoteNotification:fetchCompletionHandler`, so **silent-push wake work cannot run** until this is added to the real AppDelegate.

**Recommendation**: Implement the background remote notification handler in `Bitkit/BitkitApp.swift` (not in `AppDelegate_integration.swift`).

### 4) Paykit iOS background tasks likely can’t auto-pay when the node is stopped (today)

`PaykitPollingService` / `SubscriptionBackgroundService` wait for “node ready”, but the app’s scene-phase policy stops the node when entering background.

Additionally, the Paykit executors (`BitkitLightningExecutor`, `BitkitBitcoinExecutor`) call into `LightningService` but do **not** start the node.

**Impact**: Background Paykit tasks can be scheduled correctly yet **still fail to execute Lightning-dependent work** if the node is not running.

**Recommendation**: Unify the Lightning background-start capability so both:
- the **Lightning wake** path (incoming HTLC/payment) and
- the **Paykit BGTaskScheduler** paths (autopay / subscription checks)

can start → connect → perform minimal work → stop, within iOS constraints.

### 5) Atomicity has an explicit stub in shipping FFI surface area

In `atomicity-mobile/rust/src/lib.rs`:

- `get_payment_list(...)` returns `Ok(vec![])` with a comment “This would need a runtime context in a real implementation”.

This is a real “loose end” and violates “no stubs/loose ends” as a production posture.

**Recommendation**: Either implement it fully (with an explicit non-extension runtime strategy) or remove/feature-gate it so it cannot be called in production builds.

### 6) Paykit and Atomicity mobile crates embed Tokio (extension memory risk)

- `paykit-rs/paykit-mobile/Cargo.toml` depends on `tokio` with multi-thread runtime.
- `atomicity-mobile/rust/Cargo.toml` depends on `tokio` with multi-thread runtime.

**Impact**: If these bindings are ever invoked inside an iOS Notification Service Extension (or other constrained extension), you will hit the same class of memory/runtime issues as LDK-node.

**Recommendation**: Put explicit guardrails in docs + architecture so “extension code paths” never initialize Tokio.

## “Optimal” remediation plan (tightened, production-safe, minimal new surface area)

This is the corrected plan (keeping all useful intent, removing/flagging likely-pointless work, and aligning to real APIs).

### Phase 1 (≈2 weeks): make notifications reliable, require user open to complete

**Goal**: Notifications remain useful; no extension crashes; user experience makes the constraint explicit and actionable.

1) **Simplify Notification Service Extension**
   - File: `bitkit-ios/BitkitNotification/NotificationService.swift`
   - Remove:
     - all `LDKNode` import/usage
     - all `LightningService.shared.*` calls
     - event handling / node start/stop
   - Keep:
     - payload decryption
     - mapping notification type → user-facing text
   - Add:
     - clear messaging: “Open Bitkit to complete receiving”
     - store minimal “incoming” metadata into App Group if available (e.g., sats) using `ReceivedTxSheetDetails(type:sats).save()`

   **Acceptance**:
   - Notification extension never times out.
   - No memory termination attributed to the extension.
   - Visible push always shows a sensible message even if decryption fails.

2) **Time-sensitive categories (no critical alerts)**
   - Register categories at app startup.
   - Use `.interruptionLevel = .timeSensitive` where appropriate.
   - Avoid `defaultCritical` unless you have the entitlement.

   **Acceptance**:
   - Notification shows time-sensitive UX behavior on supported iOS versions.
   - No entitlement requirement introduced.

3) **Tap-to-complete UX**
   - When user taps the notification, prioritize:
     - start node
     - connect to trusted peers
     - wait for receive event (short window)
     - then show existing “received tx” sheet when available

   **Implementation notes**:
   - Route via existing `UNUserNotificationCenterDelegate` tap handler in `BitkitApp.swift` → `PushNotificationManager.shared.handleNotification`.
   - Add a new handler branch for the relevant LN notification types (e.g., `incomingHtlc`, `cjitPaymentArrived`, etc.), posting a dedicated NotificationCenter event or driving a shared state in the app.

   **Acceptance**:
   - Cold-start from a push tap results in node start/connect as first priority.
   - User sees a deterministic UI state (“Completing receive…”) rather than nothing.

4) **Blocktank coordination (non-custodial)**
   - Agree on a **two-push** scheme (silent + alert) even in Phase 1:
     - If silent is not yet implemented in app, alert still drives user open.
   - Agree on a server-side “hold/parking” option (see Phase 1.5) but you can ship Phase 1 without it.

5) **Testing**
   - Test on production-signed builds (TestFlight) because push + extension behavior differs from debug.
   - Test scenarios:
     - app killed
     - app backgrounded
     - low power mode
     - background app refresh disabled
     - notification permission disabled

   **Acceptance**:
   - For each scenario, expected UX text is shown and no extension crash occurs.

### Phase 1.5 (≈4–6 weeks): best-effort background receive using the main app process

**Goal**: When iOS allows it, complete the receive without immediate user open; otherwise fall back to Phase 1 UX.

1) **Implement silent push handler in the real AppDelegate**
   - File: `bitkit-ios/Bitkit/BitkitApp.swift` (the `AppDelegate` used by SwiftUI)
   - Add `application(_:didReceiveRemoteNotification:fetchCompletionHandler:)`.
   - Route to a dedicated handler object (recommended) similar in shape to `PipBackgroundHandler`, but for Lightning.

   **Acceptance**:
   - Silent pushes wake the app (when OS allows).
   - Completion handler is always called within budget.

2) **Lightning background handler: minimal, bounded work**
   - Use existing `LightningService` primitives:
     - `setup` if needed
     - `start(onEvent:)`
     - `connectToTrustedPeers()`
     - optionally `sync()` only if empirically required
     - wait for `.paymentReceived` (short bounded window)
     - `stop()`
   - Wrap in:
     - `beginBackgroundTask` / `endBackgroundTask`
     - a strict timeout
     - `StateLocker` to avoid concurrent node manipulation

   **Acceptance**:
   - Handler completes quickly and deterministically.
   - No deadlocks on the `StateLocker` path.

3) **Blocktank/LSP hold (“parking”) becomes a dependency for meaningful success**
   - If the sender/LSP times out ~2s, background wake cannot save the payment.
   - To make Phase 1.5 materially useful, Blocktank should:
     - hold an incoming HTLC on the existing channel (hodl-like behavior)
     - send silent push immediately
     - only fail/return to sender after a window that matches realistic iOS wake + node start (e.g., 20–60s)

   **Non-custodial note**:
   - “Holding the HTLC” is not custody; it’s deferring settlement while waiting for the recipient to come online.

4) **Unify with Paykit iOS background execution**
   - Update Paykit BG tasks (polling/subscriptions) to use the same “start node for bounded work” helper.
   - Otherwise background autopay remains unreliable whenever the node is stopped by scene-phase policy.

5) **Metrics**
   - Add observable counters (even if only local logs in the first iteration):
     - silent push received
     - background handler started
     - node start latency
     - connected-to-peer latency
     - receive success vs fallback-to-alert

### Phase 2 (re-evaluate): KMP notification-extension Lightning “claim”

**Status after audit**: **Not recommended as currently described.**

Reason: Lightning receive isn’t a simple “sign a claim” operation you can isolate into a tiny module. To settle an incoming HTLC you generally need:
- the node to be online, handle onion messages, update channel state, and reveal preimages

Doing this inside a Notification Service Extension implies either:
- fitting a real Lightning implementation inside ~24MB, or
- redefining the protocol so a server can settle on your behalf (custody/trust)

If you still want a “KMP investment”, the **highest ROI** use is:
- **shared crypto + protocol plumbing for Paykit/Atomicity** (where you control the protocol surface and can keep it small),
not “run Lightning receive in an iOS extension”.

## Cross-repo impact checklist

### bitkit-ios

- Notification extension: remove LDK linkage and all LN ops.
- AppDelegate: add silent push background handling in the real SwiftUI AppDelegate.
- Notification tap handling: extend `PushNotificationManager` to route LN push types to UX.
- Deep links:
  - `bitkit://payment-request` already handled.
  - Consider adding parity for `bitkit://subscriptions` (Android uses it).
- Paykit BG tasks: align node lifecycle expectations with background reality.

### bitkit-android

- Confirm PaykitPollingWorker’s node-ready wait matches real node lifecycle in production (it waits up to 30s for `NodeLifecycleState.Running`).
- No new ProGuard work needed (rules already present).
- Optional parity: if iOS degrades to “tap to complete”, Android can remain better (WorkManager can do more), but ensure the backend payloads don’t become iOS-specific.

### paykit-rs

- Add/extend docs warning: **Do not run paykit-mobile (Tokio) in iOS extensions**.
- Ensure push-relay docs explicitly distinguish:
  - extension-safe “decrypt and show”
  - main-process background handling (silent push) vs extension handling

### atomicity

- Remove/implement `get_payment_list` stub; feature-gate if necessary.
- Add docs warning: atomicity-ffi embeds Tokio; treat iOS extensions as off-limits.

## Test & verification matrix (avoid production surprises)

### bitkit-ios

- **Build**: Xcode build both the app and Notification Service Extension (Release config).
- **Manual push tests** (TestFlight):
  - app foreground/background/killed
  - low power mode
  - background app refresh disabled
  - notifications disabled
  - device locked vs unlocked (Keychain AfterFirstUnlock behavior)
- **Success criteria**:
  - Phase 1: notification always renders; user open can complete receive.
  - Phase 1.5: silent push path sometimes completes without user open; if not, user gets the alert push and can complete after opening.

### bitkit-android

- Run `./gradlew compileDevDebugKotlin`
- Run targeted unit tests around Paykit polling/autopay flows if present.
- Validate WorkManager constraints and notification deep links.

### paykit-rs / atomicity

- Run `cargo test` in `paykit-rs` after doc/guardrail changes.
- Add a small CI check (docs/lint level) that flags “Tokio in iOS extension targets” as a policy violation (even if just documented initially).

## Concrete todo adjustments (plan hygiene)

- Mark as **already satisfied / verify only**:
  - iOS `UIBackgroundModes.remote-notification`
  - Keychain `AfterFirstUnlock`
  - Android ProGuard keep rules for UniFFI/JNA

- Mark as **high-risk / do not implement by default**:
  - iOS critical alerts
  - “KMP Lightning receive inside notification extension” (unless the protocol is redefined with explicit acceptance of the trade-offs)

- Add **missing but required** tasks:
  - Implement silent push handler in the real SwiftUI AppDelegate (`BitkitApp.swift`)
  - Add iOS deep link parity for `bitkit://subscriptions` if you want Android parity
  - Unify Paykit BG tasks with Lightning node lifecycle, or explicitly document “autopay requires app foreground”

