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

## Trusted temporary APK artifact and Windows operator helper

When exact-head Android CI passes, the pipeline produces one short-lived
14-day `kenato-m5-dispatch-research-apks` GitHub Actions ZIP with only the
separate diagnostic APK, the matching test APK, `SHA256SUMS` and `SCOPE.txt`.
This is **NOT a release, not an approved APK for ordinary installation, and
not physical evidence**. The workflow runs no Android instrumented tests.

An operator using PowerShell 7 and ADB may, **only after acceptance of the
native-free disposable diagnostic scope**, download the original ZIP and
independently obtain its SHA-256 digest from the authenticated GitHub Actions
artifact API for the exact reviewed PR HEAD. The helper verifies the original
ZIP *before* extraction, matches exact HEAD/SCOPE and both APK SHA-256 values,
requires a real Android API 29+ physical device, installs only
`com.sl.kenato.m5dispatchprobe` and its test package, then runs five
isolated methods. It never uninstalls or clears `com.sl.kenato`, prints no
identifiers, stores sanitized JSON only, and rejects emulators. The harness
will not diagnose real power-loss or process-death/reboot durability.

```powershell
$head = 'REPLACE_WITH_REVIEWED_PR_HEAD_SHA_40_LOWERCASE_HEX'
$zipSha = 'REPLACE_WITH_INDEPENDENT_GITHUB_ACTIONS_ZIP_SHA256'
pwsh -File scripts/Run-KenatoM5DispatchProbe.ps1 -ArtifactZip C:\\KenatoDispatchProbe.zip -ExpectedArtifactZipSha256 $zipSha -ExpectedHeadSha $head -EvidenceDirectory C:\\KenatoDispatchEvidence
```

`scripts/test_run_kenato_m5_dispatch_probe.py` uses a **synthetic ADB binary**
and synthetic non-APK ZIP in CI; its passing tests verify operator helper
policy and evidence sanitization, not actual physical Keystore/AtomicFile.
Android 10/13/14+ real hardware P13/P14 and independent security review remain
required, and none has yet passed.
