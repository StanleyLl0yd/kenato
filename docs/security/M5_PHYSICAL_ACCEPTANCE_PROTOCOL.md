# M5 voice: physical acceptance evidence protocol

Status: **PLAN ONLY - NOT EXECUTED, NOT APPROVED FOR RELEASE**.
Trackers: #87 (security/physical exit), #116 (Android effect runner), #88 (WebRTC AAR), #118 (draft M3 AEAD migration), #123 (draft shared M3 owner), #91 (deployed Go runtime).
Baseline published test APK: **0.0.4**. M6 out of scope.

## Execution gate and rules

Do not run live M5 audio scenarios against the current application: the Android
effect runner, approved media dependency and microphone path are not active.
This document specifies a future controlled **local test build** gate and does
not authorize an APK publication, new service, STUN/TURN infrastructure, or
microphone enablement. A reviewed test harness may fault-inject Android
Keystore/AtomicFile behavior; it must never export private keys, ratchet
plaintext, SDP/ICE, microphone frames, contact identifiers, or ciphertext to
CI artifacts, logcat, crash reporters or issue comments.

**Do not silently reset app storage or regenerate contact identities** to make
a failing case pass. A failed migration or inaccessible key is a security
finding. Destructive recovery needs an explicit user action, its own evidence
and a reviewed rollback decision.

For each run, record the tested exact Git commit, local build identifier and
APK SHA-256, intended signer fingerprint, Android application version,
device model, Android release/API level and security patch, both network
topologies and a UTC run interval. Redact or hash device serial numbers;
never attach full bugreports without a privacy review.

Read-only environment inventory (no permission changes):

```sh
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.product.model
adb shell dumpsys package com.sl.kenato
```

Collect **only** case ID, pass/fail, approved fixed diagnostic codes,
timestamps, separately counted encrypted WSS sends and redacted local
call-key correlation from a reviewed test-only harness. Avoid `logcat`
exports containing sensitive payloads. The M4.5 user-initiated diagnostics
viewer is not evidence that M5 effects or native audio actually ran.

## Device and topology matrix

- At least two **physical phones per end-to-end call**. Cover Android 10,
  Android 13 and Android 14 or newer across the campaign. Android 14+ must
  verify the relevant foreground-service and microphone permission rules at
  the actual target SDK. Report hardware Keystore properties as *observed*,
  never assume hardware-backed keys based only on API level.
- Test direct connectivity on the same Wi-Fi, different networks and
  mobile/CGNAT as applicable. Without approved TURN, some NAT paths must
  fail with bounded cleanup; no connectivity workaround may forward audio
  through a new server.
- Test in-place upgrades from the installed 0.0.4 baseline with existing
  identity, contact trust, M3 ratchet and pending messages. Preserve the
  original state. Android device-to-device restore and process-restart
  cases are separate; neither is equivalent to fresh installation.

## Acceptance scenarios (record every case independently)

| ID | Test | Required evidence / invariant |
| --- | --- | --- |
| P01 | Pair using explicit user-visible identity and QR challenge/proof on both devices | Two independent approvals, pinned M2 identity, single-use signed voice-v2 capability; no implicit text-peer upgrade |
| P02 | Legacy M4 text-only contact | No unsolicited unsupported v2 probe, text messaging unchanged |
| P03 | Ordinary outgoing and incoming audio | Exact peer/call-key effect execution, user microphone consent and keyed local media lifecycle; no raw IP/SDP/ICE logging |
| P04 | One device denies or revokes RECORD_AUDIO | No microphone capture or orphaned media; clear local failure |
| P05 | Simultaneous offers / active busy | Deterministic glare/busy outcome, no second active media instance |
| P06 | Ring timeout, rejected, missed, local hangup | Correct bounded control signaling only while still approved; no leaked audio |
| P07 | Media failure or connect timeout | Keyed STOP_MEDIA, no stale ACTIVE transition and no resource leak |
| P08 | Revoke M2 pin/voice consent in OUTGOING_RINGING | No SEND_HANGUP after revoke, retire call |
| P09 | Revoke in INCOMING_RINGING | No SEND_REJECT after revoke, retire call |
| P10 | Revoke in CONNECTING or ACTIVE | Only exact-key local STOP_MEDIA; zero new encrypted peer sends |
| P11 | Revoke between reducer proposal and effect runner | Revalidate at execution boundary, fail closed |
| P12 | Stale callback after teardown or a new call | Cannot stop unrelated media or resurrect a retired call |
| P13 | Duplicate, reordered, expired, tampered and replayed voice events | No second ratchet advance/effect, no ACK before durable encrypted semantic import |
| P14 | Restart/process death during accepted/pending ACK and staged outbound v2 | Durable recovery with single-use claims, no plaintext replay or duplicated media |
| P15 | Offline expiry and reconnect | No post-expiry side effect, deterministic cleanup and bounded retries |
| P16 | Direct P2P blocked by CGNAT/no TURN | Document controlled failure, no server fallback or silent privacy expansion |
| P17 | Android activity recreation and overlapping send/bootstrap | Shared M3 owner and ratchet state, no duplicate session creation or lost outbound handoff |
| P18 | Low storage, interrupted AtomicFile write and process kill | Old or committed state is coherent, never partially accepted |
| P19 | Keystore alias loss before decrypt and between decrypt/re-encrypt | No replacement alias, no silent consent/state overwrite and no ACK |
| P20 | Reinstall/upgrade/old APK after candidate KNS3 to KSAE migration | One-way policy, explicit recovery/downgrade outcome; old APK cannot silently recover plaintext |
| P21 | Restore previously valid KSAE or canonical KNS3 after newer authenticated state | Detect or explicitly classify full-file rollback as blocking; never claim AES-GCM prevents replay |
| P22 | Recovery with key deletion failure, then with file deletion failure | Confirm key-first destructive order; restored old ciphertext remains unreadable **after key invalidation** |
| P23 | Restore an older valid positive capability consent after revoke | Classify any re-grant as rollback finding; never interpret valid AEAD tag as fresh approval |
| P24 | Foreground/background, audio route, Bluetooth and permission transitions | Explicit Android 14+/target-SDK compliance, no silent background microphone or lingering capture |

P18-P23 require a **separately reviewed test-only injection or controlled
device harness** before execution. The current draft #118 is not wired into
production, so synthetic JVM results cannot be substituted for these physical
test outcomes. Cases involving destructive identity recovery are not to be
performed on the only copy of a real user account.

## Additional release and supply-chain prerequisites

- #88: independently acquire the *actual* candidate AAR, pin its SHA-256 from
  a trusted source, run the offline structural auditor, review published source
  lineage and binary reproducibility, all transitive Gradle metadata, license
  notices, native CVEs and ABI completeness. Verify D8/AGP and real Android
  10/13/14+ JNI loader before audio approval. Structural audit PASS alone
  never approves a dependency.
- #91: verify the *deployed* OCI ARM64 server binary's Go toolchain and binary
  hash against the release artifact, then explicitly capture health/rollback
  evidence. CI compiler version is not deployment proof.
- #87: conduct a literal repository-wide final security review, including
  Android, Go, native Rust/JNI, crypto/storage, network, build/release scripts,
  dependencies and CI policies. Keep findings linked until disposition.
- Re-run exact-head and exact-main Android, Go, protocol, `make test`,
  CodeQL, Gitleaks, Security/Quality and Dependency Review on all integrated
  changes. No voice APK/release until the owner has reviewed the completed
  physical evidence and blockers.

## Evidence record and disposition

For each Pxx case, add a short issue #87 record with:

```text
Pxx / date UTC:
Git commit / local build SHA-256:
Device A and B: Android version/API/security patch (no serials):
Network topology:
Prerequisites and injected fault (if applicable):
Observed app state and redacted fixed-code diagnostics:
Expected invariant PASS / FAIL / BLOCKED:
Artifacts: privacy-reviewed references only:
Finding issue or reviewer decision:
```

Never label a case PASS if the component is not implemented, the scenario
was not physically executed or the evidence only comes from a JVM test.
Unexecuted scenarios are **BLOCKED**, not silently passed. Maintain
#87/#116/#88 open until their respective exit requirements are met.
