# M5 Shiguredo m158.8127.1.0 — exact Android ARM64 candidate research

Status: **NEW PROVISIONAL CANDIDATE — NOT NATIVE / SPDX / DEVICE APPROVED**.
Research observation: 2026-11-05. This report compares a new immutable
candidate to the previously audited `m157.8103.4.0` in Draft #172 / issue #88.
**No production AAR import, JNI execution, microphone, video, TURN, server,
release or M6 changes.**

## Exact publisher and source identifiers

| Evidence | Exact value |
|---|---|
| [Published release](https://github.com/shiguredo-webrtc-build/webrtc-build/releases/tag/m158.8127.1.0) | 2026-11-05 04:22:53 UTC |
| Producer tag commit | `e60fe55f9c9c4dd6b02a12479107602a36b0951f` |
| `VERSION` declared WebRTC upstream source | `fb1c41a93d92d4188f068f437d80ef2c4b50c3a9` |
| [Original successful producer run](https://github.com/shiguredo-webrtc-build/webrtc-build/actions/runs/41959194651) | `41959194651` (`android_sdk` job `127021233268` SUCCESS) |
| Original Actions artifact | `13386994126`, `webrtc.android_sdk.tar.gz` |
| Original Actions artifact **outer ZIP** SHA-256 | `28d13acda02e63c8e420f5e19a6f7d3bdde9f396a93a045fb444a3ba64fe665c` |
| Nested `webrtc.android_sdk.tar.gz` | 105,812,669 B; SHA-256 `acabbccbdb51eb7492ad76d210c720143c2c09c6ecd69002f9b510b3ccca4b93` |
| Nested `webrtc/aar/libwebrtc.aar` | 14,889,470 B; SHA-256 `8a2f4da8e9546d9242d67b9bbb5b9ef0e4fa0e75a4bd86b431209f67a65176cf` |

**Independent evidence chain completed:** downloaded and SHA-verified the
*original producer Actions ZIP*, streamed its nested tar.gz without unsafe
extraction, recomputed the nested tar.gz hash and extracted exactly the
allowlisted AAR member. The nested tar.gz and nested AAR both match **byte for
byte** the separate public GitHub **release asset** size/SHA-256 metadata.
The embedded `webrtc/NOTICE` matches the AAR `META-INF/NOTICE` and also
the earlier m157 generated notice byte-for-byte. This proves
**original producer artifact → publisher release binary identity**, **not**
source-to-compiled-native reproducibility or a signed supply-chain attestation.

## Exact shipped AAR and ARM64 ELF — read-only structural inspection

- AAR ZIP has 4 entries, no duplicate/unsafe ZIP paths, only native
  `jni/arm64-v8a/libjingle_peerconnection_so.so`.
- Native ELF: **13,374,944 bytes**, SHA-256
  `010e394de8d114133fca568abec3efbacd05865da5b75f662f0d17863b06bf81`.
- ELF64 little-endian, `ET_DYN`, `AArch64`, `JNI_OnLoad` exported.
- **Three PT_LOAD segments, all `p_align=0x4000` (16 KiB)**; `GNU_RELRO`,
  `BIND_NOW`/`NOW` present, `GNU_STACK` is non-executable.
- Nested `classes.jar`: **520 Java class files**, classfile major **69**
  (Java 25). Static entries include `PeerConnection`, `VideoTrack`,
  `VideoCapturer`, `SurfaceViewRenderer`, software/hardware video
  encoder factories and `LoggingJni`. **Classes do not establish functional
  JNI, codec negotiation, camera capture/render or video interoperability.**
- `META-INF/NOTICE`: **214,353 bytes**, SHA-256
  `e5e1a734e1f1e73a0526a4f6ab857f26c4657eb5a70c4f4bc05c20c5444e1ec9`;
  byte-identical to the previously audited m157 NOTICE. This alone is
  neither complete SPDX component/linkage closure nor proof of legal text
  accessibility in the eventual signed Android APK/AAB/splits.

All inspections were performed without loading JNI, connecting a socket,
executing Java vendor code, requesting a microphone or running a device.

## Publisher patch delta vs exact m157.8103.4.0

Both producer versions select exactly **21 ordered Android SDK patches**.
The active lists have 20 names in common: 16 are blob-identical, 4 are
modified. One old patch is removed and one new patch added.

| Status | Publisher patch |
|---|---|
| Modified | `revive_proxy.patch` |
| Modified | `turn_tls_client_certificate.patch` |
| Modified | `unsafe_buffers_optout_list.patch` |
| Modified | `android_jni_zero_generated_java.patch` |
| Removed | `logging_sink_min_severity.patch` |
| Added | `android_toi420_failure_handling.patch` |

The new `android_toi420_failure_handling.patch` modifies
`YuvConverter.java` (catching `RuntimeException`, returning `null`
for a failed conversion and releasing conversion buffers) and
`android_video_track_source.cc` (drop the frame after a null `ToI420()`
when rotation is applied). This is a **new Java/native memory-ownership and
video lifecycle review surface**, not proven either safe or vulnerable.
The old TURN TLS custom certificate path, proxy customization and unsafe
buffer opt-outs remain relevant to native security review. The producer
still declares `rtc_use_h264=false`, so H.264 encode/decode/SDP support is
**not** assumed.

## What remains before choosing m158 over m157

1. Re-run the **six pinned upstream WebRTC CVE source-fix fingerprints** against
   the new upstream SHA, analyze each changed producer patch and whether the
   fixes genuinely reach the exact compiled ELF. Do not reuse m157 native-CVE
   approval for this new binary. The eight previously noted Firefox/Gecko
   security advisories still lack component-level applicability/VEX evidence.
2. Independent precise source→native provenance / signed attestation or
   comparably reviewed evidence, along with any new Android/JNI/video risks
   introduced by the m158 patch delta.
3. Complete linked-component inventory, 35 upstream NOTICE candidate license
   paths, SPDX expressions/exceptions, actual source texts, redistribution
   obligations and independent legal signoff.
4. Isolated AGP/D8/APK/AAB/splits compilation and **subsequent controlled**
   physical ARM64 JNI tests after preliminary native clearance, audio and
   future video VP8/H.264 negotiation/camera/media lifecycle tests.
5. #116 single durable voice owner/effect/consent gate, #87 two-phone
   acceptance, and separately authorized #91 OCI rollout.

**Disposition:** `m158.8127.1.0` is a credible **new provisional research
candidate**, not an automatically selected production SDK. The original m157
source audit and candidate remain intact pending comparable m158 security,
license and physical evidence. PR #172 stays Draft, #88 OPEN, M5 OPEN, M6
prohibited, protected main and published `v0.0.4` unchanged.
