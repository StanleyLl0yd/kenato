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

## Exact upstream vs publisher root license evidence (new research checkpoint)

The pinned source-only #88 workflow now fetches and SHA-256 inventories two
**separate root license texts** at immutable revisions: upstream WebRTC
`95554e4a0c5c343fdc989387d9d0ce18e2a2294b/LICENSE` via Gitiles
and the Shiguredo build-project `c8c2c3ff87d6443192f9f42c3c12f005ee4f6d4c/LICENSE`
via GitHub. It checks characteristic BSD three-clause vs Apache 2.0 text
clauses respectively, recording source bytes/digests and only **candidate**
SPDX expressions. **Never infer a third-party component's license from the
root WebRTC or publisher build-repository LICENSE.** The resulting report
explicitly sets source root license evidence apart from actual native linked
components, the 34-section generated NOTICE and independent legal signoff.

The first new exact-head attempt and a retry failed **before the license
fetch** because Gitiles returned HTTP 503 while serving different existing
CVE source paths; both had passed offline tests. A bounded, exact-URL-only
503/502/504/429 retry with negative no-fallback tests is now being evaluated.
No live root-license result is claimed until this updated exact-head job passes. Even when green,
this is at most two independently retrieved root LICENSE files, not a
complete SPDX/third-party redistribution review. No production asset changes.

### GN-derived generated NOTICE: precise source-license path inventory

The Shiguredo publisher `run.py` packages `android_sdk` by calling WebRTC's
`tools_webrtc/libs/generate_licenses.py` over GN-described build targets,
renaming `LICENSE.md` to `NOTICE`, and embedding it in the AAR. The new
source-only evidence probe fetches that generator at **the exact declared
WebRTC revision** `95554e4a0c5c343fdc989387d9d0ce18e2a2294b`, SHA-256
inventories its bytes, parses only the two bounded static AST license maps
(without executing the generator), and pairs direct candidate license source
paths with the 34 publisher NOTICE headings. Unmapped names remain explicit.

**Boundary:** a mapped path is only a suggested original source license
location. It does not prove that file's exact bytes, its SPDX expression,
compiler/GN linkage, exceptions, source-offer duties or completeness of
binary SBOM. The probe never invokes GN, performs native compilation, executes
untrusted generator Python or marks a component's legal obligation cleared.
**Exact-source result verified:** [pinned-source job #41645510654](https://github.com/StanleyLl0yd/kenato/actions/runs/41645510654) at `c70f910efe15223083abecdaac0b898b8b0146fa` **PASS**. Its archived JSON proves the exact SHA-pinned WebRTC generator `tools_webrtc/libs/generate_licenses.py` is **11,892 bytes**, SHA-256 `cfc24442429f83e5e7e73380a731c8950952646783b5db533dd41010dcfc6f88`. The generator's bounded static maps have **49 direct** and **3 regular-expression** entries. All **34/34** exact generated-NOTICE headings map to at least one *candidate* source-license path, producing **35 unique original license file paths** (the Rust standard library entry lists two). **0/34 names remain without a generator path**. The later exact-head change now fails closed if any of these known mappings becomes absent and must pass its own CI independently.

The *license file content* at those 35 paths is **not independently fetched and verified** here, and their GN-to-ELF binary linkage is not reproduced. 34/34 mapping is not 34/34 license approval, and cannot establish that every compiled or redistributed dependency is represented in NOTICE. Component SPDX obligations and independent legal signoff remain open.

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

## CI closure and component-by-component legal evidence register (2026-11-03)

The exact research HEAD `fb2db1347cd489737990bc22f4ec6ba19f7c783a`
completed [standard CI #41634239599](https://github.com/StanleyLl0yd/kenato/actions/runs/41634239599)
successfully. Its exact-HEAD required matrix was **10/10 PASS, 0 FAIL**;
this is **research CI**, not a native-vendor approval or M5 acceptance.
Any subsequent research commit requires fresh exact-HEAD verification.

The existing exact-digest `probe_shiguredo_m157_notice.py` now writes a
**34-entry unresolved license gap register** to the *sanitized research JSON*
for the SHA-pinned AAR notice. Every NOTICE section has a deterministic per-section
SHA-256 evidence anchor; every attributed component explicitly remains
`license_declared_spdx=NOASSERTION`,
`license_concluded_spdx=NOASSERTION`, with no verified upstream license,
linked native dependency, redistribution obligation or independent signoff.
This is deliberately **NOT an SPDX SBOM** or legal classification. NOTICE
sections are attribution headings, **not necessarily the exact native
dependency closure**. The register cannot be promoted to a completed legal
review simply because the 34 NOTICE headers are present.

Independent release clearance still requires: (1) source/package identity
and precise versions for each actual linked or otherwise redistributed
component, including dependencies missing from NOTICE; (2) component-level
SPDX license expressions from authoritative texts, exceptions and applicable
copyleft/source-offer duties; (3) separate complete third-party
redistribution conditions, approved text and user-visible legal access;
(4) verification against the exact production AAB/split APK and signed vendor
provenance or equivalent native-risk assessment. Zero of those 34 section
records is independently cleared by the current evidence. No vendor,
native JNI, legal or release acceptance is granted.

## Security-sensitive vendor patch review and scope restrictions

The 21 applied publisher patches were inspected at exact tag SHA. Notable
security-bearing behavior that is **not activated by Kenato M5**:

- `ssl_verify_callback_with_native_handle.patch` exposes a **borrowed raw
  `SSL*` pointer** through `BoringSSLCertificate`. Its lifetime is tied to
  the transport handshake; a certificate object retained after its `SSL`
  owner is destroyed could make that pointer stale. This is a *review
  hypothesis*, **not** a proven UAF or evidence of reachability in Kenato.
  Do not expose or dereference this handle from application callbacks.
- `android_ssl_certificate_verifier_chain.patch` adds
  `SSLCertificateVerifier.verifyChain`, whose default implementation delegates
  to existing **leaf-only** `verify(chain[0])`. It must **not** be mistaken for
  strict chain-of-trust verification when a custom application verifier is
  installed; such integrations need explicit trust-anchor/path validation.
- `android_turn_tls_client_certificate.patch` adds optional Java
  `String` fields carrying TURN-TLS client private key/certificate PEM. Those
  strings and JNI copies are not an acceptable Kenato secret-storage design.
  **No TURN integration/credentials** are authorized in M5.
- `unsafe_buffers_optout_list.patch` opts certain HTTP/proxy and H.265
  parser files out of stricter unsafe-buffer diagnostics; this is a
  **static-analysis coverage limitation**, not proof of a memory bug.
- `android_simulcast.patch` **does add** standard Android
  `SimulcastVideoEncoder` and Java/JNI factory paths to the publisher build.
  Presence of these paths is not proof of interoperable multi-codec
  simulcast, actual video encoding, or device performance.

These producer-specific changes warrant focused runtime/ownership checks if
the corresponding features are later enabled. No exploitability conclusion
is made solely from the patch diff.

## New Chrome-only MediaStream issue: CVE-2026-76024

The [Chromium fix `29268f92bbf3b2a2c5566bab2eb4d16b0e5bee49`](https://github.com/chromium/chromium/commit/29268f92bbf3b2a2c5566bab2eb4d16b0e5bee49)
explicitly references Chromium issue **576215540** and changes six files
**exclusively under `third_party/blink/renderer/`** for
`MediaStreamAudioTrack::StopAndNotify` and
`MediaStreamVideoTrack::StopAndNotify` during Oilpan/JS garbage collection.
This specific Chrome MediaStream vulnerability (published 2026-10-29;
CVE-2026-76024) is in **Blink renderer**, not Shiguredo's standalone Android
WebRTC Java/JNI AAR component. The scoped *component non-applicability*
finding does **not** imply all other native WebRTC vulnerabilities are absent.
No patch or runtime changes to Kenato.

## Reproducible remediation in isolated research APK

The disposable JDK25/AGP9.4/ARM64 test now performs two stages for pinned
`m157.8103.4.0`: (1) verify the original APK **does not** contain the
publisher-generated NOTICE; (2) copy the same SHA256-verified notice from
the pinned AAR to the disposable `app/src/main/assets/legal/NOTICE`,
reassemble, and verify `assets/legal/NOTICE` has the **exact same digest**
while native ABI/DEX inventories remain unchanged. A follow-on exact-head
research extension also builds the same disposable app as an **AAB** and
checks `base/assets/legal/NOTICE` against that precise SHA-256 and length,
with only ARM64 JNI and matching DEX counts. This AAB extension was validated in the exact-head [pinned AAR/D8/AAB workflow #41634239623](https://github.com/StanleyLl0yd/kenato/actions/runs/41634239623) at `fb2db1347cd489737990bc22f4ec6ba19f7c783a`.
An additional SHA-256-and-byte-pinned official bundletool 1.18.3 research
step produces **device-targeted split APK sets** for representative ARM64
Android API 29 and 34 profiles, verifies the exact notice survives into
`assets/legal/NOTICE`, checks ARM64-only packaged JNI and DEX presence, and
deletes every generated binary at the end of the job. This stage passed the [exact-head CI #41633259411](https://github.com/StanleyLl0yd/kenato/actions/runs/41633259411)
but remains an offline, never-installed device-profile package test. No APK, AAB, .apks or publisher
binary is uploaded: sanitized JSON only. The newest follow-up probe also
calculates the ARM64 JNI ELF SHA-256 from the SHA-pinned original publisher AAR
and requires **byte-identical ELF payloads** in both disposable APK builds,
the AAB and both generated device-profile APK sets. This ELF-preservation proof passed the same exact-head workflow at `fb2db1347cd489737990bc22f4ec6ba19f7c783a`; native instruction provenance and device safety remain **unapproved**. A positive split
check cannot establish native CVE remediation, upstream C++-to-binary
reproducibility, end-user legal-UI accessibility, full license obligations
or runtime safety.
The eventual production APK/AAB will require separate acceptance checks after
vendor approval.

## Android license packaging gate

A license text being present in `libwebrtc.aar/META-INF/NOTICE` does **not**
prove that Gradle automatically places it in the distributed Kenato APK/AAB.
The disposable m157 JDK25/AGP9.4 ARM64 package probe now inventories
all bounded NOTICE candidates in the resulting APK and records whether the
**exact generated NOTICE SHA** survives packaging automatically. A separate
explicitly included NOTICE test now requires the corresponding disposable
AAB to contain the exact publisher notice, exclusively ARM64 native JNI and
matching APK/AAB DEX inventory. This is ZIP-level bundle evidence only.

If the generated NOTICE is **absent** (as Gradle may discard AAR top-level
metadata), application release packaging must deliberately include the
same reviewed notice bytes as a user-visible legal resource and enforce
their SHA-256 and accessibility in release acceptance. The proprietary
vendor binary is not yet approved, so no production notice asset or
license redistribution is added now. This check does not settle
legal compliance or prove completeness of the 34 component sections.

## Newer browser WebRTC security advisories: exact component scope (2026-11-03)

Review of the [Chrome 156.0.8078.47 security bulletin](https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_02018666648.html)
identified two omitted **October 20** WebRTC-labelled CVEs. The exact
Chromium source fixes were retrieved and their complete touched-path lists
checked, not inferred from Chrome version numbers:

- **CVE-2026-113303, Critical, Chromium bug 574041825:** [fix
  `e193ceb7de134efa938172d45c38daec31658357`](https://github.com/chromium/chromium/commit/e193ceb7de134efa938172d45c38daec31658357)
  changes **4/4 files exclusively in `third_party/blink/renderer/modules/`**
  for `blink::WebRtcAudioDeviceImpl` / `WebRtcAudioRenderer` lifecycle.
- **CVE-2026-113161, High, Chromium bug 568945639:** [fix
  `6c38d4ec50ea5a153e2e616a39c06d6a4777b7c8`](https://github.com/chromium/chromium/commit/6c38d4ec50ea5a153e2e616a39c06d6a4777b7c8)
  changes **12/12 files exclusively in `third_party/blink/renderer/modules/`**
  for JS execution-context destruction and RTC encoded-stream optimizers.

For these **exact Chrome bugs and exact fixes**, the impacted code is
Chromium's Blink browser adapter, **outside the standalone WebRTC Android
SDK source and AAR target**. The finding is `BLINK_RENDERER_COMPONENT_EXCLUDED`,
not proof of unrelated native audio, encoder, RTP, STUN or SDP safety. Existing
six WebRTC-upstream CVE source-fix checks and previous Blink-only mappings
remain unchanged.

A second vendor bulletin, [Mozilla Firefox 159 MFSA 2026-118](https://www.mozilla.org/en-US/security/advisories/mfsa2026-118/)
(published October 27), disclosed **six additional WebRTC-labelled CVEs**:

| CVE | Mozilla component | Bug | Kenato exact AAR disposition |
|---|---|---|---|
| CVE-2026-118005 | Signaling UAF | 2073653 | applicability unverified |
| CVE-2026-118006 | Signaling privilege escalation/UAF | 2074202 | applicability unverified |
| CVE-2026-117892 | Networking UAF | 2078902 | applicability unverified |
| CVE-2026-117894 | Signaling boundary conditions | 2078983 | applicability unverified |
| CVE-2026-117957 | Networking cryptographic issue | 2061508 | applicability unverified |
| CVE-2026-117996 | WebRTC boundary conditions | 2081535 | applicability unverified |

Mozilla Bugzilla currently requires authorization for the referenced fixes,
so this audit has **no exact changed-file lists**, no safe source-fix
fingerprints and no proof of either affected or unaffected Shiguredo native
components. Mozilla's Firefox/Gecko WebRTC integration can differ from the
standalone SDK; a browser CVE title cannot settle AAR applicability.
Before independent native approval, obtain authoritative patch scope or
vendor component-level VEX/attestation for these issues, or a comparably
reviewed analysis. **Do not claim all publicly labelled WebRTC CVEs are
cleared merely because six upstream fingerprints PASS.**

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
