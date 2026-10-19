# M5 WebRTC native ELF and vulnerability approval blocker

Status: SECURITY RESEARCH ONLY. Parent #88. No vendor or runtime approval.

## What is established

Exact upstream WebRTC m150 original AAR:
SHA-256 `8ad5e5fd02f0177743ddb566bea329006bef7689b944f6351717cd1d018958c0`.
This is byte-identical to the standard retained upstream producer CI AAR.
Upstream's reviewed 433-header post-processing produces Maven m150:
`0a1627b1a48c2bc17d9a40d62fc47bd45166f44a311e95917f147c402de379b0`.

Upstream source fork at `73cb8180f7258ee292878d6edd05177f41883962`
contains the exact pre-fix blobs for Chromium/WebRTC CVE-2026-78891
(upstream fix `190a7606321b53c861142f97fc39f679b295f31c`).
It still declares `SplitAboutEqually(int payload_len, ...)`; the upstream
fix replaces it with guarded `size_t` input and a safe comparison.
The upstream producer's executed GN flags do not explicitly disable VP9.
All four actual m150 ELF binaries include VP9 packetizer/SCTP type
markers and exported DataChannel JNI entry points. Marker presence
alone does **not** prove the exact vulnerable machine code is reachable
or exploitable; conversely audio-only UI does not prove exclusion.

The source fork and actual Maven AAR must not be approved until a patched,
independently verified replacement/equivalent fix and associated
exploit-precondition assessment are obtained. m149 also remains unapproved.
See issue #88 comment `6266052075` for exact pre-fix source blob IDs.

## Static probe scope

`scripts/probe_webrtc_native_elf.py` downloads only two fixed Maven
snapshots in an isolated temporary directory, checks historic CI
SHA-256 observations and the existing AAR structural policy,
then uses `readelf` as a non-executing analyzer on temporary ELF bytes.
Reports ABI-specific SHA-256, DT_NEEDED, SONAME, RELRO/BIND_NOW,
stack executable flag, exported JNI counts and diagnostic string
markers; output is a sanitized JSON-only, seven-day artifact.
No vendor AAR, binary or temporary APK is committed or uploaded.

A successful workflow is **not** an Android JNI loader test,
CVE-safety result, source reproducibility proof, license clearance
or explicit permission to ship WebRTC. Remaining blockers are native
patch/GN/link proof, license/NOTICE compliance, physical Android
10/13/14+ loader and all #87 P01-P24, #116 effect runner, and #91
separately approved rollout. Do not change production Gradle,
microphone permission, STUN/TURN, APK/release, OCI or M6.
