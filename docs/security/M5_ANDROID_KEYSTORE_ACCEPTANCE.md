# M5 Android Keystore continuity physical acceptance

Status: **NOT EXECUTED / NOT APPROVED**. Tracking: #118, #87, #116.

This is an **isolated synthetic probe**. It cannot authorize M3 migration, voice
runtime, microphone permission or a release. No original contact/Olm/voice state
is read. The Android Keystore aliases use a random 128-bit test-only namespace
`com.sl.kenato.session.epoch-acceptance.v1.<random>.` and the AtomicFile
uses a unique `kenato_epoch_probe_<random>.bin` name. The test destroys only
its own aliases and file after each method. Do not run on an irreplaceable
production device without a backup/consent to diagnostic testing.

## Preparation and execution

1. On Android 10, 13, and 14+ *real devices*, record model, build fingerprint,
   security patch, API level, target SDK, Android Keystore implementation and
   whether keys are hardware-backed. An emulator result is additional evidence
   only; it is not a physical-device pass.
2. Build with JDK 25, the pinned SDK/NDK and native M3 prerequisites (same as CI).
   Run `./gradlew :android:app:assembleDebug :android:app:assembleDebugAndroidTest`.
   Hosted CI builds only: it does **not** execute instrumented tests.
3. Install the two debug artifacts using `adb install -r`. Test APK is normally
   at `android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk`;
   confirm the actual Gradle output path before use.
4. Execute:
   `adb shell am instrument -w -r -e class com.sl.kenato.session.EpochKeystoreInstrumentedTest com.sl.kenato.test/androidx.test.runner.AndroidJUnitRunner`
5. Capture redacted output and `adb logcat -d -s KenatoM5Acceptance:I`. The log
   contains timing, API and key security classification only; it must never
   contain aliases, encrypted material, identifiers, SDP/ICE or private keys.
6. Confirm **3 executed / 3 PASS** for the exact artifact SHA and the exact
   physical device. Test-APK compilation is only a CI build result, not a pass.

## What these tests establish

- AES-GCM alias material is not exportable through Android Keystore's key API;
  authenticated ciphertext survives new backend instance construction.
- Real AtomicFile replacement and per-commit alias retirement reject restoration
  of a previously valid, older encrypted snapshot *when the Keystore namespace
  is not rolled back*.
- Extra unexpected aliases block reads, including after backend recreation.
- Latency for two synthetic commits is logged, **not automatically approved**.
  Measure warm, cold, repeated and post-reboot distributions separately before
  choosing any production latency threshold.

## Still mandatory, not demonstrated by this suite

Reboot and process-death windows (before/after `startWrite`, `finishWrite`,
and alias retirement), Android low-storage and key corruption scenarios,
multi-process serialization, post-update/downgrade behavior, Android 10/13/14+
device diversity, 100+ sustained writes, 95th/99th percentile latency,
hardware-versus-software KeyMint/Keystore capabilities, secret-dependent memory,
explicit destructive-recovery UX, KNS3/KSAE migration, and P01-P24 two-phone
voice acceptance. An interrupted epoch switch can permanently disable old
identity access by design; users must not be silently reset.

Record a matrix with device/OS/build, HEAD, test counts, timings, security
level, fail/skip reason, log location and reviewer before deciding whether
this approach is viable. `main` and release v0.0.4 are unchanged.
