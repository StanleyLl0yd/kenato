# M5 Shiguredo m157.8103.4.0 — exact producer, CVE source and vendor patch audit

Research opened 2026-11-03, issue #88 and Draft PR #172. **Do not import vendor WebRTC into production or interpret positive source signatures as native clearance.**

## Release binary identity — independently reproduced from original producer archive

- Published [Shiguredo m157.8103.4.0](https://github.com/shiguredo-webrtc-build/webrtc-build/releases/tag/m157.8103.4.0) full Android `libwebrtc.aar`: **15,037,143 bytes**, SHA256 `4ce14722c9c8f633cc9390f0547ee3195ad95cf1eeab18928ced733218d88cd1`.
- Publisher [exact GitHub Actions run 40991854569](https://github.com/shiguredo-webrtc-build/webrtc-build/actions/runs/40991854569), tag commit `c8c2c3ff87d6443192f9f42c3c12f005ee4f6d4c`, `android_sdk` build job **123855892690** PASS, saved producer artifact **12951911807** (`webrtc.android_sdk.tar.gz`) obtained independently via GitHub connector. Its nested `webrtc/aar/libwebrtc.aar` is **byte-identical to published release** by full SHA256 and size. This proves producer-artifact-to-released-AAR identity, not an independently deterministic source recompilation.
- Producer tag `VERSION` declares upstream WebRTC source `95554e4a0c5c343fdc989387d9d0ce18e2a2294b`, and its job fetched this exact commit, as recorded in original job logs. The direct `android` and Android SDK builds both completed.
- Producer archive `webrtc/NOTICE` and AAR `META-INF/NOTICE` are byte-for-byte the **same 214,353-byte notice**, SHA256 `e5e1a734e1f1e73a0526a4f6ab857f26c4657eb5a70c4f4bc05c20c5444e1ec9`. The generated AAR notice has **34 component headers**, including WebRTC, BoringSSL, libsrtp, libvpx, libaom, dav1d, opus, rnnoise, sframe and zlib. The publisher repository's separate source `NOTICE` is shorter than the generated archive/AAR notice; its SHA is inventoried separately. This proves the actual generated notice is bundled, **not** that its dependency and legal obligation inventory is complete or approved.
- Producer `run.py` includes **21 ordered Android/Android SDK patches** affecting proxy, TURN/TLS certificate, JNI, audio and video APIs, packaging and GN. All 21 patch files were inspected at the pinned tag. **None alters the exact CVE-checked RTP/FEC/SDP source paths**; this does not prove unrelated patched transport code safe. Default Android GN flag `rtc_use_h264=false` remains. Separate upstream Android `android_simulcast.patch` does modify Java/JNI simulcast paths, unlike the unpatched generic m157 AAR claim; check actual runtime capabilities later and avoid blanket assertions.

## Confirmed live research result — exact producer source (2026-11-03)

[Exact-head pinned-source workflow 41628840395](https://github.com/StanleyLl0yd/kenato/actions/runs/41628840395) **PASS**. Report artifact **13227695090**, name `m5-shiguredo-m157-4-source-cve-and-patch-digests`; extracted `kenato-shiguredo-m157-patch-security.json` records **`PINNED_PATCH_SOURCE_FIXES_PASS_NOT_NATIVE_APPROVAL`**.

The job fetched twelve exact Gitiles source files at WebRTC commit
`95554e4a0c5c343fdc989387d9d0ce18e2a2294b`, separately SHA-256
inventoried them, inspected the producer's exact `VERSION`, `run.py`,
and **all 21 applied Android patch files**. Producer patch target paths:
**74 distinct file paths**; none directly changed the twelve
CVE-checked upstream source paths. Both Android `PATCHES` lists match,
`rtc_use_h264=false` is present, and the CI source contract was verified.

The actual source checks PASS for **CVE-2026-78891, CVE-2026-9962,
CVE-2026-106268, CVE-2026-103631, CVE-2026-106357 and CVE-2026-118328**.
The seventh tracked issue, CVE-2026-110137, remains a *Chromium Blink renderer
component* exclusion, not an independent WebRTC source-fix claim.

The actual embedded generated 214,353-byte NOTICE and publisher archive
NOTICE were independently byte-identical; the shorter publisher *repository*
NOTICE is not the generated one. The report stores their digest evidence
separately. Source and archive provenance is **strong but not equivalent to
independently reproducible native compilation, CVE exploitability review,
third-party license clearance or real ARM64 JNI execution**.

## Generated binary NOTICE audit

The full **34-section** actual AAR `META-INF/NOTICE` records attribution
for WebRTC, its codec/security libraries and bundled third parties. A new
exact-digest, no-native-code test inventories every top-level component,
rejects duplicates/omissions and verifies a nontrivial copyright/permission
text exists for each. It uses the independently verified 214,353-byte
SHA256 `e5e1a734e1f1e73a0526a4f6ab857f26c4657eb5a70c4f4bc05c20c5444e1ec9`
from the producer archive and published AAR. The source repository's
different short NOTICE must not be substituted for this generated text.

This is an **attribution inventory, not an SPDX legal signoff**. Still map
all actually linked/transitive third-party dependencies to the relevant
redistribution notices, restrictions and eventual Kenato app packaging.

## Security gates

The dedicated offline tests and pinned Gitiles source workflow validate the *actual* WebRTC producer-declared commit (above), rather than merely the version number. Expected source fingerprints:

| CVE | Exact upstream source path | Expected proof or disposition |
|---|---|---|
| CVE-2026-78891 | `modules/rtp_rtcp/source/rtp_format.cc` | bounded `size_t` payload split + overflow guard |
| CVE-2026-9962 | `pc/sctp_data_channel.cc` | refcounted receiver captured through async task |
| CVE-2026-106268 | `pc/sdp_offer_answer.cc` | network/worker ordered transceiver teardown |
| CVE-2026-103631 | RTP/H264/H265 packetizers and sender | sanitized payload-size limits and reductions |
| CVE-2026-106357 | `pc/peer_connection.cc`, `pc/sdp_offer_answer.cc`, `pc/transceiver_list.cc` | repaired MID association and unassociated lookup |
| CVE-2026-118328 | `forward_error_correction.cc` / `forward_error_correction_internal.{cc,h}` | spanified masks plus fail-closed overflow/out-of-order guards |
| CVE-2026-110137 | Chromium Blink EncodedTransform | source component is Chromium Blink renderer/worker, outside standalone `sdk/android` AAR; component-specific exclusion, not blanket CVE approval |

`CVE-2026-118328` was disclosed 2026-10-27 by Chrome and its upstream WebRTC two-part patch chain identifies Chromium bug 570927027: spanification `3efe1a3a90c14ce339e22c451d48f4f7e831c75b`, and fail-closed sequence-guard `d86ac8ab5e04c7efb8f474985e1bec1f82443a34`. A release date newer than a fix is **not** sufficient evidence; exact producer-declared Gitiles source fingerprints are mandatory.

The independent native ARM64 ELF structural audit and video Java/D8 builds of exact AAR passed earlier, but they **did not** execute JNI, prove patched instructions, obtain native security attestation or clear every transitive third-party dependency. Receipt of the source job PASS would be **positive exact source evidence**, not vendor approval. Publisher source-to-binary *independent* reproducibility, complete license compliance and native exploitation/reachability remain unproven. Physical Android 10/13/14+ JNI/microphone/video and #87 P01–P24 tests are still NOT RUN.

**Decision boundary:** Shiguredo m157 is provisionally preferable to **security-rejected full webrtc-sdk m150.04**, but keep #88 OPEN and the prototype behind existing security gates; M5 OPEN, M6 prohibited, no production media runtime, permissions, deployment or release activation.
