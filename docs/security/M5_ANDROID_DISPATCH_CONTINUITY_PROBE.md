# KDL1 Android Keystore / AtomicFile physical-probe backend

Status: **STACKED DRAFT ON #174; NOT DEVICE-EXECUTED / NOT PRODUCTION APPROVED**.
Tracks #87 P13/P14, #116, #171, #174.

The separate Android adapter supplies real AndroidKeyStore AES-256-GCM
epoch aliases and a bounded no-backup AtomicFile for the isolated KDL1
JVM proposal. It requires a random 128-bit test-only alias prefix
`com.sl.kenato.dispatch.epoch-acceptance.v1.<hex32>.` and a disposable
`kenato_m5_dispatch_probe_<hex32>.bin` file. The acceptance caller must
use the **same random token** for its alias namespace and local file.
It must later delete **only** its own test keys and disposable file.

The adapter cannot use the production journal, M1 identity, M3 session,
M5 consent, semantic-event aliases, or any legacy data file. It has no
production factory/call site. Android source compilation in CI does not
execute Android Keystore or an AtomicFile physical transaction.

## Strict gates before any physical test

- Build a separate application ID / instrumented diagnostic package. It must
  have no INTERNET, RECORD_AUDIO or camera permissions in **either** the probe
  or its AndroidTest APK, and must never install
  as `com.sl.kenato`. Verify signer, package, exact APK SHA and device API
  before installation. No test on an irreplaceable real identity.
- Add five or more isolated AndroidX tests: actual key persistence after
  reopening, non-exportability observed (do not assume hardware), old
  ciphertext restoration rejection after a second commit, extra/missing
  aliases, and a separately labelled simulated uncertain AtomicFile result.
- Real process-death/reboot/failure-window tests are distinct from synthetic
  fault returns and require Android 10/13/14+ physical evidence; study
  100+ writes and key generation/retirement latency.
- Review disk/Keystore cross-process locking, crash recovery, key namespace
  retirement and explicit destructive recovery with user UX before any
  runtime change. KDL1 research can permanently refuse to restore state.
- Verify updated exact-head CI, CodeQL, security and native library policy;
  later integrate through one durable M2/M3/WSS/effect owner, not separate
  stores operating as if they were an atomic transaction.

The code does not activate voice, WebRTC, microphone, WSS, media or network.
It does not approve M5 P13/P14, producer JNI/CVE/license, or a new release.
Protected main and published v0.0.4 must remain unchanged. M6 forbidden.
