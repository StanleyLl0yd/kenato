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
- Exact release AAR has Java **classfile major 69 (Java 25)**, observed in
  the 2026-10-20 research workflow. Current Kenato/JDK17 accepts major 61.
  The strict production audit correctly rejects this binary. The vendor-only
  research probe now observes up to major 69 explicitly, and still marks
  vendor approval false. An isolated AGP/D8/JDK25 compatibility test and
  independent security review are mandatory before integration; no
  bytecode-header rewriting is allowed.
- A release-page digest is a publisher-hosted **integrity pin**, not an
  independent attestation or reproducible-source-build proof.
- Existing generic strict three-ABI AAR audit remains the default for
  historical candidates. Only the pinned m157 research entrypoint selects
  ARM64-only. Neither can enable production WebRTC.

## Unclosed engineering/security gates

1. Independently review the exact upstream CVE-2026-78891 / other native
   patches at the claimed source revision, the producer GN flags, source
   provenance and relevant binary symbols; version alone is insufficient.
2. Verify structural AAR integrity, ELF ARM64 PT_LOAD, PeerConnection
   classfile major <=61, optional LoggingJni presence and licenses/NOTICE.
3. Run temporary AGP 9.4/JDK17/Android API37 compile/D8 with arm64 only.
   Verify native library loading on Android 10/13/14+ devices. A CI
   structural PASS does not imply this runtime gate passed.
4. Address #118/#123 protected M3 persistence, #116 call effect runner,
   permission/foreground lifecycle, #87 P01-P24 physical acceptance and
   #91 separate deployed server Go patch.

## Resource and maintenance comparison (planning ranges, not measurements)

| Work component | Shiguredo published AAR | Own fork/build of upstream WebRTC |
|---|---|---|
| Initial vendor/binary audit, Android adapter, AGP/D8 integration | 40-100 engineer-hours **plus extra work for Java 25 toolchain incompatibility** | 120-300 engineer-hours **before** Android adapter/QA |
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

## Disposable JDK25 compatibility probe

A separate *research-only* workflow job sets up JDK 25, pinned Gradle 9.7.1,
AGP 9.4.0 and Android SDK 37, compiles a temporary ARM64-only app against
the publisher's exact AAR and inspects compiled DEX plus packaged JNI
libraries. This never changes the production Java 17 toolchain or app ABI
filters. A D8/AGP PASS does not prove runtime JNI load or security.
