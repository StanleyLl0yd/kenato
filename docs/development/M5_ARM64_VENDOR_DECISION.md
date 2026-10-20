# M5 ARM64 + prebuilt WebRTC vendor decision

Status: OWNER APPROVED TARGET ABI / VENDOR RESEARCH, NOT BINARY APPROVAL.
Parent #88, #116, #87. Effective 2026-10-20.

## Scope

- Android voice M5 target: **arm64-v8a** only.
- Defer **armeabi-v7a** pending future demand and a supported vendor binary.
- **x86** and **x86_64** are removed from target device scope.
- Use third-party, publisher-produced prebuilt WebRTC AAR. Do **not** fork,
  compile, patch or maintain a custom WebRTC build under this decision.
- M5 media target is direct P2P, audio-only, no new Kenato server/TURN.
- Preserve current published Android v0.0.4 and M4/M4.5 acceptance while
  researching. Update production Gradle ABI filters, native Rust packaging,
  and Android release/CI gate together in a separately reviewed PR **only
  after native vendor verification and release scope acceptance**.
- M6, new APK/release and microphone/runtime activation remain prohibited.

## Shiguredo m157 selected for investigation

- Publisher: shiguredo-webrtc-build/webrtc-build.
- Fixed tag: m157.8103.0.0, published 2026-10-14.
- Producer tag Git SHA: c575fdf836d1185d8cefda37197a2a489e95ffd9.
- Exact release file: [libwebrtc.aar](https://github.com/shiguredo-webrtc-build/webrtc-build/releases/tag/m157.8103.0.0).
- GitHub Releases API asset SHA-256 is pinned and checked inside
  `scripts/probe_shiguredo_m157.py` (not copied into release docs).
- Metadata byte count: 15,036,224 bytes.
- Publisher VERSION claims upstream WebRTC revision:
  b321f634929af0af61a8964487fbd7894a008f12.
- Publisher README lists Android ARM64 as supported; 32-bit ARM deprecated
  since September 2025.
- Research-only workflow: m5-shiguredo-m157-probe.yml. Its checks run on
  a temporary snapshot and upload sanitized JSON, never the vendor binary.
- Exact release AAR contains Java **classfile major 69 (Java 25)**, which
  JDK 17 alone cannot compile against. It is accepted in the **research-only
  pinned vendor probe** with an explicit max of 69; production still has no
  WebRTC dependency. Since PR #145/#146, regular Android CI, repository-wide
  tests and Java/Kotlin CodeQL use **JDK 25**; Kenato-owned Java/Kotlin
  **source and target bytecode remain Java 17 (major 61)**. The guard scans
  only Kenato-owned compiled classes, not vendor classfiles. Release signing
  remains JDK 17 until separately approved. No classfile rewriting.
- Disposable JDK25 + AGP 9.4 + Gradle 9.7.1 + SDK37 + ARM64 D8 build PASS.
  This proves compilation and APK packaging, not a successful JNI load.
- A release-page digest is a publisher-hosted **integrity pin**, not an
  independent attestation or reproducible-source-build proof.
- Existing generic strict three-ABI AAR audit remains the default for
  historical candidates. Only the pinned m157 research entrypoint selects
  ARM64-only. Neither can enable production WebRTC.

## Verified research evidence (2026-10-20)

- Published m157 AAR: **15,036,224 bytes**, SHA-256
  `b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a`.
- [Producer CI run 38522776327](https://github.com/shiguredo-webrtc-build/webrtc-build/actions/runs/38522776327)
  completed successfully at tag Git SHA `c575fdf836d1185d8cefda37197a2a489e95ffd9`.
  Its GitHub Actions archive artifact ID `11876415141` is exactly 105,467,424
  bytes, SHA-256 `8b6dd31f83b78b40d1239d588f50d93fe84008b021a720c89ddc3e11081d8e53`.
  The nested CI-built `webrtc/aar/libwebrtc.aar` has **the exact same
  bytes/hash** as the released AAR. The same tar declares WebRTC upstream
  commit `b321f634929af0af61a8964487fbd7894a008f12`. This establishes
  published-AAR-to-publisher-CI **identity**, not independent source rebuild
  reproducibility or complete GN flag attestation.
- The original publisher CI log shows all **21 declared Android SDK patches**
  being invoked sequentially. Pinned upstream source probes confirm repair
  signatures for **CVE-2026-78891, CVE-2026-9962, CVE-2026-106268**.
  These are **source-level fingerprints only**: we have not independently
  proven compiled native CVE remediation or complete code reachability.
- ARM64 ELF `libjingle_peerconnection_so.so` is **13,521,752 bytes**,
  SHA-256 `3f3a1299fa5e3a9570d2ea5b251856e5788616b2db05f7b22f025d1a4ce36aaa`.
  Static research confirms RELRO/BIND_NOW, non-executable GNU_STACK,
  JNI_OnLoad export and all three PT_LOAD `p_align=16384`.
- The producer `webrtc/NOTICE` matches the nested AAR `META-INF/NOTICE`
  **byte-for-byte** (214,353 bytes, SHA-256
  `e5e1a734e1f1e73a0526a4f6ab857f26c4657eb5a70c4f4bc05c20c5444e1ec9`).
  The 34 top-level named NOTICE sections are **not a binary SBOM** or
  complete license clearance.
- Isolated permissionless ARM64 physical-JNI *smoke APK build* PASS, with
  host JDK25 and application Java17 target. The disposable debug APK was
  **14,687,546 bytes** (SHA-256
  `6df2fd4d7e505653ace16d72d82397b7cc05cf414b8565a74159e672f8c16a89`).
  Android SDK37 `zipalign -c -P 16 -v 4` PASS; this is **test APK**
  packaging, **not** the production Kenato AAB size or runtime RSS.
  **No physical phone JNI was executed.**

## Unclosed engineering/security gates

1. Independently assess machine-code vulnerability remediation, complete
   publisher patches/NDK/GN flags and native/transitive third-party SPDX
   obligations. Source fingerprints, GitHub Actions provenance and NOTICE
   matching are necessary evidence but not a blanket vendor approval.
2. Execute isolated JNI smoke on real **ARM64 Android 10/13/14+** devices
   only after reviewed native-risk clearance. Verify later production
   APK/AAB packaging and runtime behavior separately.
3. Implement the securely keyed #116 Android effect runner, M3 lifecycle,
   explicit microphone/foreground permission handling and actual encrypted
   audio-only peer-to-peer transport without new TURN servers.
4. Keep #118/#123 pending until physical Keystore, rollback and ownership
   evidence; execute #87 P01-P24 and confirm #91 patched OCI Go deployment.
   Preserve signed v0.0.4 and prohibit M6 until M5 exit is approved.

## Resource and maintenance comparison (planning ranges, not measurements)

| Work component | Shiguredo published AAR | Own fork/build of upstream WebRTC |
|---|---|---|
| Initial vendor/binary audit, Android adapter, AGP/D8 integration | 40-100 engineer-hours **plus audited JDK25 build/tool compatibility** | 120-300 engineer-hours **before** Android adapter/QA |
| Source and patch maintenance for each upstream security update | 4-16 engineer-hours for vendor review/integration | 20-60 engineer-hours for patch, GN/NDK compatibility, multi-platform CI |
| Recurring binary build infrastructure | none in Kenato CI; download 15 MB candidate | substantial multi-GB source checkout, native toolchains, CI/cache/storage |
| Native security incident response | dependent on vendor publication; can suspend releases | own emergency patch/build/signing verification responsibility |
| Supply-chain risk | publisher trust, digest/source transparency | own build environment, transitive source, signing and release custody |
| ABI support | released ARM64 only | configurable but requires ongoing build/test resources |
| Feature customization | API adapter only | high flexibility with fork and patch drift |
| Two-device physical acceptance, M3 and media lifecycle | required | required |

For **Kenato's single-arm64, audio-only first release**, the vendor
artifact removes source-build and native toolchain ownership. It does not
remove app integration, CVE evaluation or device acceptance. Estimates above
are coarse engineering budgets for discussion, **not observed benchmarks,
vendor quotations, or evidence of security**. Writing a brand-new VoIP/media
protocol rather than building upstream WebRTC would be substantially more
complex and is not authorized.

Revisit the self-build alternative **only as a cost/risk comparison** until
the owner explicitly changes the no-self-build decision.

## JDK25 build-runtime status

The isolated candidate D8 probe and exact-head/exact-main Android CI have
passed with JDK25. Kenato application bytecode remains Java17; the published
third-party m157 AAR uses classfile major69. No production WebRTC, microphone
or release-signing dependency is activated. Physical JNI and the full M5
security/voice acceptance remain **BLOCKED** until separately executed.
