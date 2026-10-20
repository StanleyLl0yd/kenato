# M5 Shiguredo m157: pinned source, CVE and NOTICE research

Status: **SOURCE RESEARCH ONLY** — **NO VENDOR/BINARY APPROVAL** (2026-10-20).
Parent #88; keep #87/#116 open.

## Exact identities

- Shiguredo tag: m157.8103.0.0; producer tag Git SHA:
  c575fdf836d1185d8cefda37197a2a489e95ffd9.
- Publisher VERSION claims WebRTC source:
  b321f634929af0af61a8964487fbd7894a008f12.
- Published AAR SHA-256 independently pinned by the existing offline probe:
  b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a.
- Producer VERSION/LICENSE/NOTICE come only from pinned GitHub SHA.
- Source inspection uses the exact, declared WebRTC SHA from Gitiles, not HEAD.

## Source research and explicitly unproven claims

- CVE-2026-78891 (VP9 payload-size conversion): Chromium issue
  https://issues.chromium.org/issues/503013378 identifies upstream change
  https://webrtc.googlesource.com/src/+/190a7606321b53c861142f97fc39f679b295f31c
  (2026-07-23). The probe checks the pinned upstream source for an equivalent
  size_t SplitAboutEqually signature and bounded SafeGt payload-size guard.
  Even a PASS proves a **source fingerprint only**, not that the published
  ARM64 libjingle_peerconnection_so.so contains the fix. Shiguredo applies
  publisher patches before compilation.
- CVE-2026-9962: advisory https://github.com/advisories/GHSA-xf76-hmq4-v7qj
  maps to Chromium issue https://issues.chromium.org/issues/504716948;
  upstream fix https://webrtc.googlesource.com/src/+/9b4ffb3281c02327968ed07389082fcb2dd77baa
  (2026-05-06) ref-counts SctpDataChannel in SendAsync posted tasks instead of
  using the network_safety_ flag with a raw this capture. A pinned-source
  fingerprint probe checks these forms in exact WebRTC revision b321f634.
  It does NOT validate reachability on Kenato's audio-only path or prove
  the fix in the built ARM64 .so. Those remain OPEN.
- CVE-2026-106268: [Chrome's issue 565742177](https://issues.chromium.org/issues/565742177)
  maps to [upstream WebRTC commit 82df4ce](https://webrtc.googlesource.com/src/+/82df4ce4226de25e1682351d7ba2e9bf9a198790)
  (2026-09-25). Three pinned-source fingerprints independently demand that
  stopped transceivers receive no transport, gain no channel, and execute
  ordered network/worker channel teardown before removal. **Even PASS does
  NOT prove compiled AAR remediation or completeness of all related fixes.**
  Physical JNI, binary and patch-chain mapping are still required.
- Publisher LICENSE is Apache-2.0; tag NOTICE includes BSD-style WebRTC and
  WebKit attributions. **Third-party/transitive binary license completeness is
  NOT verified**, and eventual redistribution must reproduce applicable
  notices/licenses. Do not substitute publisher NOTICE for a binary SBOM.

The independent research job downloads bounded, pinned UTF-8 publisher text
and Gitiles base64 source. Every network/parse/pattern error **fails closed**.
Offline regressions cover mutated revision, invalid license/NOTICE, vulnerable
source pattern, redirection and oversized source. It uploads **JSON only**;
no WebRTC native code is compiled, patched, linked or loaded.

## Before #88 can be approved

1. Assess applicability of all CVEs and independent source-to-built-binary
   patch-chain/remediation proof for ALL applicable native fixes; source-only
   fingerprints are insufficient for production. Closed-source or absent lineage is a blocker.
2. Review exact applied Android publisher patch set, native link flags,
   transitive SPDX/NOTICE and release/source attestation; approved audit of
   the **actual** SHA-pinned ELF—not just source signatures.
3. JNI load on physical ARM64 Android 10/13/14+, D8/JDK25/full Kenato app,
   #116 safe effect runner, #87 P01-P24 device and security acceptance.
4. Preserve current production Java17 target, no vendor Gradle dependency,
   no microphone/STUN/TURN/OCI change, signed 0.0.4 untouched, M6 prohibited.
