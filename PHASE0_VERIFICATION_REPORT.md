# Phase 0 Verification Report — Web Crypto Compatibility & Benchmark

**Branch:** `feature/security-hardening` (based on `audit/authentication` at `8f29dfd`)
**Date:** 2026-11-25
**Environment:** Node.js v24.22.1 (x86_64 Linux)

---

## 1. Files Created / Modified in This Phase

| File | Status | Purpose |
|------|--------|---------|
| `phase0_crypto_check.js` | Created | Node.js Web Crypto functional verification script (getRandomValues, subtle, PBKDF2 600k, localStorage envelope) |
| `crypto_test.html` | Created | Browser/WebView test harness for on-device verification (getRandomValues, subtle, PBKDF2 600k ×3 runs with benchmark, localStorage envelope read/write) |
| `test_crypto.js` | Created | Simple JS module for crypto checks (unused; kept for reference) |

---

## 2. Functional Verification Results (Node.js WebCrypto)

| Component | Result | Details |
|-----------|--------|---------|
| `crypto.getRandomValues` | ✅ PASS | 16 bytes generated; entropy visually random |
| `crypto.subtle` | ✅ PASS | All standard methods present (deriveBits, importKey, etc.) |
| PBKDF2-HMAC-SHA-256 600k | ✅ PASS | 3 runs: 290.4ms, 215.9ms, 239.8ms; output 256-bit correct |
| localStorage envelope | ✅ PASS | Write+read integrity verified; salt base64 round-trip correct (simulated in Node via Map) |
| Insecure fallback | ✅ PASS | None used; fail-closed policy enforced |

**Overall Functional Status:** ✅ PASS (Node environment)

---

## 3. Benchmark: PBKDF2-HMAC-SHA-256, 600,000 iterations, 256-bit output

| Environment | Run 1 | Run 2 | Run 3 | Average | Notes |
|-------------|-------|-------|-------|---------|-------|
| Node.js v24 (x86_64 server) | 290.4 ms | 215.9 ms | 239.8 ms | **248.7 ms** | Reference only — NOT Android WebView |

> ⚠ **Important:** This is a server-class x86_64 benchmark. **Actual Android WebView performance will be slower** (ARM SoC, JIT differences, thermal throttling). Expect **300–1,200 ms** on mid-range Android devices. **On-device measurement is mandatory** before Phase 1.

---

## 4. Android APK / WebView Analysis

| Attribute | Value |
|-----------|-------|
| APK Package | `com.kopi.app` |
| Entry HTML | `assets/index.html` (identical to `Kasir Kopi (1).html` — `diff -q` confirms) |
| Min SDK | 14 (from manifest) |
| WebView | System WebView (package `com.android.webview` or `com.google.android.webview`) — typical for WebIntoApp wrappers |
| WebCrypto Availability | **Must be verified on device** — Android 5+ (API 21) has basic `crypto.subtle`, but PBKDF2-HMAC-SHA-256 with high iterations can fail on older WebView versions (< 69) or custom ROMs. |

---

## 5. On-Device Test Procedure (Phase 0 Mandatory for Android)

Since no Android emulator/device is available in this environment, the following procedure must be executed on a physical Android device or emulator running the **actual production APK** (`KasirKopi.apk`):

### 5.1 Test Harness
Open `crypto_test.html` in the same WebView that loads the Kasrr app. Options:
- **Method A (recommended):** Temporarily rename `assets/index.html` in the APK to `index.html.bak`, copy `crypto_test.html` as `assets/index.html`, rebuild APK, install, and run.
- **Method B:** Host `crypto_test.html` on a local HTTPS server, edit `assets/index.html` to redirect to it via `<meta http-equiv="refresh" content="0; url=https://local-ip/crypto_test.html">`, rebuild APK.
- **Method C:** Use ADB port forwarding + Chrome DevTools to inject the test page into the running WebView.

### 5.2 Required Checks
Run **all four tests** in `crypto_test.html`:
1. `crypto.getRandomValues` — must pass
2. `crypto.subtle` — must be available with `deriveBits`
3. PBKDF2 600k ×3 runs — record all three durations; **average must be ≤ 1,000 ms** (per SPEC gate)
4. localStorage envelope write+read — must pass with base64 salt round-trip

### 5.3 Pass Criteria
- All four tests show ✅ (green)
- PBKDF2 average duration ≤ 1,000 ms (if > 1,000 ms → **escalate to owner with exact numbers**; do NOT downgrade iterations)
- `window.isSecureContext` = true (WebView must be secure context for `crypto.subtle`)

### 5.4 Failure Modes & Actions
| Symptom | Likely Cause | Action |
|---------|--------------|--------|
| `crypto.subtle` undefined | WebView < API 21 or stripped | Fail-closed; owner decision required |
| PBKDF2 throws `OperationError` / `NotSupportedError` | WebView doesn't support PBKDF2 or iterations too high | Fail-closed; escalate |
| PBKDF2 > 1,000 ms avg | Slow device / thermal throttling | Record exact avg; **do not downgrade**; owner must approve |
| `isSecureContext` = false | `file://` origin blocked | Try `http://localhost` via ADB reverse proxy; if impossible → escalate |
| localStorage quota exceeded | Corrupt storage / full | Clear app storage and retry; if persistent → escalate |

---

## 6. Phase 0 Recommendation & Next Steps

### 6.1 Functional Baseline ✅
Node.js WebCrypto confirms the algorithm, parameters, and envelope format are correct and implementable.

### 6.2 Android Gate 🔄 PENDING
**Phase 0 is not complete until on-device verification passes.** The Node benchmark is a reference only. Do **not** proceed to Phase 1 without:
1. On-device PBKDF2 600k average ≤ 1,000 ms
2. `crypto.subtle` confirmed in actual WebIntoApp WebView
3. localStorage envelope round-trip confirmed

### 6.3 Next Phase (Phase 1) — Conditional
Upon successful on-device Phase 0 pass, Phase 1 will implement:
- Schema v2 state (`pinEnabled`, PBKDF2 envelope fields, `recovery` wizard state)
- Migration layer (legacy `S.pin`/`S.master` → envelope)
- `save()` returning boolean + candidate snapshot rollback
- `Security Settings` panel in `vAtur()` with PIN enable/change, Master Code create/change
- Guard on `LOCKED` tabs (`rekap`, `stok`, `atur`) requiring `pinEnabled && unlock`

---

## 7. Summary for Owner

| Item | Status | Action |
|------|--------|--------|
| Functional WebCrypto API | ✅ Verified (Node) | Proceed |
| PBKDF2 600k benchmark | 🔄 Reference: 249 ms (Node) | **Must re-measure on Android** |
| localStorage envelope | ✅ Verified (Node sim) | **Must re-verify on Android** |
| Android WebIntoApp test | 🔄 NOT DONE (no device) | **Run `crypto_test.html` in actual APK WebView** |
| Phase 1 gate | 🔄 BLOCKED | Await on-device results + owner approval |

**Branch:** `feature/security-hardening` (commit `8f29dfd`)  
**Parent branch:** `audit/authentication` (unchanged)  
**Main branch:** untouched  
**PR #4:** untouched