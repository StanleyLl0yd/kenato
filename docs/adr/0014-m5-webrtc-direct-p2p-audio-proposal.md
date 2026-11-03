# ADR 0014 (proposed): Android client-only P2P voice media

Status: **PROPOSED, NOT ACCEPTED OR ENABLED**
Milestone: M5/#84, implementation tracker #88; acceptance/security tracker #87.
Date: 2026-10-14
Updated scope note: 2026-11-02; later owner-approved decision takes precedence.


## Later binding media-scope decision (20 October 2026)

The owner's 2026-10-20 decision in
`docs/development/M5_ARM64_VENDOR_DECISION.md` supersedes the original
14 October candidate and ABI research below. **M5 client-only WebRTC media
research is pinned to Shiguredo m157.8103.0.0 on ARM64 only.** ARM32 is
deferred and x86/x86_64 are out of M5 media device scope; the historical
generic AAR auditor and the current M3 JNI build remain three-ABI until a
coordinated, separately reviewed production change. CI uses JDK25 while
Kenato-owned bytecode remains Java17. A pinned vendor digest, producer CI
matching, source patch fingerprints, JNI smoke APK compilation and 16KiB
alignment are *not* evidence of executed physical JNI, full native CVE
clearance, license approval, or production WebRTC integration.

This ADR remains a **proposal**, not a release approval. #88 native/vendor
acceptance, #116 durable lifecycle/effect runner, #87 P01–P24 physical,
#118 M3 Keystore, #170 consent rollback and #171 replay-claim rollback gates
remain open. No production microphone, TURN, new infrastructure or M6.

## Decision context

Kenato's supported 1.0 voice scope is exactly one-to-one **audio-only**
communication. M5 v2 OFFER, ANSWER and ICE_CANDIDATE signaling is
defined as a domain-separated, authenticated M3 E2EE application payload
staged for delivery through the ordinary M4 opaque messaging envelope.
The production Android app does not yet activate this voice transport. No media
component may infer peer identity, capability or permission from relay
metadata. The app's current production WSS/Android path is **not yet**
a functioning phone-to-phone audio call; a green unit test is not a
physical-acceptance claim.

The owner has prohibited new Kenato server components and TURN/coturn
deployment for this development scope. The prior general repository
architecture mentions TURN but does **not** override that instruction.
This ADR therefore proposes a client-side **direct-ICE only** first
implementation, with an honest connectivity limitation. No additional
signaling endpoint, third-party control plane or media server is needed.

## Proposed implementation and trust boundaries

1. Review and pin one publisher-prebuilt Android WebRTC native AAR before
   adding a runtime dependency. The **current research target** under the
   later 2026-10-20 owner decision is Shiguredo `m157.8103.0.0`, ARM64
   (`arm64-v8a`) only, not the historical Maven candidates below.
   The target's published AAR and publisher CI archive SHA-256, NOTICE byte
   matching, ARM64 PT_LOAD and isolated D8/ZIP alignment are recorded in
   `docs/development/M5_ARM64_VENDOR_DECISION.md`. These are *research*
   checks, not JNI, native CVE, license, or production-runtime approval.
   Review compiled native vulnerability exposure, transitive license
   obligations, exact artifact lineage and real loader/device tests before
   approval. No custom WebRTC fork/build is authorized.
2. **M5 media device target is ARM64 only**. Defer ARM32 and omit x86/x86_64
   from M5 media acceptance. The existing `main` Android/M3 JNI ABI filters
   still include `armeabi-v7a`, `arm64-v8a`, `x86_64`: they must NOT be
   silently changed by this documentation clarification. A coordinated
   Android Gradle/Rust/CI/release packaging change requires a separate
   reviewed PR after vendor acceptance. Verify the standalone ARM64 WebRTC
   JNI sentinel on physical Android 10/13/14+ before any audio activation.
3. Keep a single audio-only `PeerConnection` per claimed, validated
   `VoiceCallKey`. A media-adapter boundary owns the WebRTC factory,
   microphone audio module, audio track, remote description, ICE,
   lifecycle and teardown; Compose and the pure `VoiceCallReducer`
   never own a `PeerConnection`.
4. All incoming SDP and ICE are accepted only **after** successful M3
   ciphertext authentication, canonical M5 inner/outer binding, pinned
   contact+approved capability checks and the durable at-most-once
   effect claim. Never use untrusted relay metadata as evidence of
   caller identity. Preserve exact call ID and peer identity through
   callbacks; stale, wrong-key or post-hangup candidates and media
   callbacks must be ignored.
5. Force **audio-only**, Opus where supported. No video track, camera,
   DataChannel, screen capture or file transfer. Use WebRTC's DTLS-SRTP
   transport with authenticated SDP fingerprint; never replace it with
   home-grown media crypto. No SDP, ICE, local IP addresses, raw media,
   device IDs or identity secrets in logs/telemetry.
6. Begin with empty ICE server configuration: host candidates only,
   no TURN, no unapproved external STUN service. Adding a STUN service
   can disclose network address information to that provider, so is an
   explicit later privacy choice. Without TURN, some CGNAT/symmetric
   NAT/firewall combinations will simply not establish a call.
   Communicate this as a connection failure, not as a downgrade to
   plaintext or an implicit server fallback.
7. Acquire mic permission in visible user context **before** audio
   capture. Android `RECORD_AUDIO` is a runtime, while-in-use permission.
   If a call must persist after leaving the foreground, review the
   foreground-service `microphone` type, `FOREGROUND_SERVICE` and
   `FOREGROUND_SERVICE_MICROPHONE` declarations, Android 14+ restrictions,
   notifications and audio-focus/routing. Do **not** enable a microphone
   service or add those permissions in a protocol-only PR.
8. On reject, timeout, permission denial, network/ICE failure,
   identity recovery, activity/process teardown and user hangup, close
   tracks, sources, observers, PeerConnection, audio module and factory
   deterministically. Make callbacks idempotent, bound to the active
   call key and unable to ring or restart a finished call.
9. SDP/ICE and outbound M3 handoff data currently have an unencrypted
   Android no-backup temporary storage exposure documented in ADR 0013.
   Review the threat model before live voice activation; do not claim
   that server-side E2EE implies all plaintext is encrypted at rest.

## Implementation slices, independent gates

- **#88-A:** pinned dependency and reproducible ABI/license/size scan,
  isolated audio factory/PeerConnection wrapper without activation.
  Green exact-head Android + complete `make test` + security gates.
- **#88-B:** validated v2 OFFER/ANSWER/ICE mapping to WebRTC callbacks
  with bounded candidate queues, call-key isolation, deterministic
  media lifecycle, no microphone capture by default. Fault-injection
  tests for candidate reorder/duplicates, hangup, stale callback,
  reconnection and conflicting SDP/fingerprints.
- **#88-C:** explicit user-visible microphone consent, Android lifecycle
  and audio routing, microphone foreground constraints if required.
  Runtime call-admission must require signed peer-v2 capability and
  the exact durable M5 effect claim. No in-band probe to text-only peers.
- **#87 physical acceptance:** on *two actual phones* check
  Wi-Fi same-LAN call, cross-Wi-Fi failure handling, 4G/5G vs Wi-Fi
  connectivity/failures, inbound/outbound/missed/busy/glare, device
  rotation, background restrictions, permission denial, headset/audio
  route, process death, restart and reconnection, malicious/replayed
  signaling, duration and cleanup. Do not publish a voice test APK
  before the appropriate physical acceptance gate is ready.

## Sources and change triggers

- WebRTC peer connections / ICE: https://webrtc.org/getting-started/peer-connections
- Android microphone foreground service rules:
  https://developer.android.com/develop/background-work/services/fgs/service-types
- Android background-start restriction:
  https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start
- Existing repo rules: `AGENTS.md`, ADR 0012/0013,
  `docs/security/THREAT_MODEL.md`.

This document is a **proposal for focused review**, not permission to
add TURN/coturn, new server code, call activation, permissions or release
artifacts. It must be approved against the owner's explicit constraints
and physical test requirements before dependency/runtime implementation.

## Pre-dependency verification checkpoint (14 October 2026)

**Historical 2026-10-14 candidate comparison only; superseded as the
current M5 vendor choice by the 2026-10-20 ARM64/Shiguredo research decision.**
The published Maven Central POMs at that checkpoint advertised both candidates:
`io.github.webrtc-sdk:android:150.7871.01` under BSD-3-Clause,
and `im.conversations.webrtc:webrtc-android:149.0.0` under
Apache-2.0 plus MIT. This confirms **publication metadata only**.
The exact AAR SHA-256, embedded `.so` ABIs, third-party notices,
binary source lineage, transitive dependencies, Android 10/13 loader
behavior and compatibility with the locked Android build toolchain
are **not yet independently verified**. Neither is approved.

PR #117 now adds a local-only, user-approved pinned-contact capability
exchange interface, but it does **not** enable v2 WSS signaling, media,
microphone permission or native WebRTC. A signed proof is never a
substitute for a separately claimed inbound call effect.

Direct-host-only ICE should work in favorable local network topologies;
with no STUN/TURN, connectivity across distinct networks, CGNAT or
restrictive firewalls is intentionally not guaranteed. No automatic
external STUN service may be contacted without a separate privacy
decision. An honest failed connection is required instead of a
plaintext fallback.

This document remains **PROPOSED** after merging. Approval of a
specific, reproducibly audited AAR and explicit Android media/security
acceptance are independent future decisions under #88/#87/#116.


## Offline AAR acceptance inspection (tooling only)

`scripts/audit_webrtc_aar.py` performs a bounded **offline** structural
review of an explicitly supplied AAR: SHA-256, canonical ZIP paths,
duplicate/symlink/compression abuse, CRC, mandatory Android layout,
ELF machine/class, and native-library parity for its **historical generic
three-ABI policy** (`armeabi-v7a`, `arm64-v8a`, `x86_64`). That default
auditor is not the ARM64-only release policy: the dedicated pinned Shiguredo
m157 research entrypoint uses an ARM64-only target. Neither is permission
to add WebRTC to production.
No binary is downloaded, installed or executed by this tool.

For discovery only (never an approval):
`python3 scripts/audit_webrtc_aar.py candidate.aar --report-only`.
For independently verified input:
`python3 scripts/audit_webrtc_aar.py candidate.aar --expected-sha256 <64-hex-digest>`.
The expected digest must be obtained and reviewed **independently**
of the downloaded file. Offline synthetic regression fixtures are
included in repository security verification.

The offline audit also opens the nested `classes.jar` as a bounded ZIP,
rejects traversal, duplicate/case-aliased paths, symlinks, malformed Java
class headers, preview classes and classfile majors above Java 17 (61),
and reports observed classfile major versions. Kenato's current Android CI build runs on **JDK 25**, with Kenato-owned
Java/Kotlin source and target bytecode **Java 17 (classfile major 61)**.
The pinned m157 candidate contains Java 25 classfile major 69. Earlier
JDK17-only wording is historical; JDK25 host compilation does not approve
the vendor AAR or raise app bytecode target. Rewriting a Java 25 vendor
classfile header from major 69 to 61 without recompiling and auditing its
instructions and runtime dependencies is invalid as a compatibility strategy;
**passing a classfile-header check cannot establish binary compatibility**. Independently compare upstream and Maven AAR
provenance, then run real D8/AGP and device loader checks. This nested
ZIP scan is offline only and does not imply binary approval.

**Passing this structural tool is insufficient to accept a dependency.**
Publisher/source lineage, exact dependency closure, embedded notices and
third-party licenses, native vulnerability evaluation and physical
Android loader/ABI tests remain separate release gates. The historical Maven candidate hashes in this section were not accepted.
The selected Shiguredo m157 candidate **has** a pinned publisher digest and
publisher-CI archive byte-identity evidence, recorded in
`docs/development/M5_ARM64_VENDOR_DECISION.md`, but native security,
third-party licenses and device JNI are **NOT accepted**. No production
WebRTC library was added to Gradle.


## Isolated call-control admission coordinator (not activated)

A non-UI `VoiceCallAdmissionCoordinator` now proposes, but does **not
execute**, reducer effects for explicitly user-approved outgoing/local
acceptance and one-time durably claimed authenticated incoming OFFER,
ANSWER, REJECT, BUSY and HANGUP. A production adapter delegates pinned M2,
M3 session and signed consumed consent checks to
`VoiceOutboundCapabilityGuard`. The incoming adapter reads only fully
matched encrypted semantic and replay records, and durably claims one
control event before passing it to the reducer. ICE_CANDIDATE and
END_OF_CANDIDATES remain unclaimed for a future reviewed media owner.

The call-key, exact owner/peer/message identity, TTL and positive consent
are checked before reducer state changes. Stale media callbacks/timeouts
and network events passed through the wrong channel cannot mutate an
unrelated call. Simultaneous offers use the pre-existing deterministic
pinned-identity glare resolution. No proposed effect itself authorizes
network send, ringing or a microphone: production execution additionally
requires a synchronized lifecycle, E2EE outbound stage, fresh permission
and exact call-key check at effect-commit time.

This adapter is **volatile only and not wired** into M4 WSS, Compose,
WebRTC, audio or foreground services. No Android permissions or Gradle
dependencies were added. #116, #88 and #87 remain open.

Call identifiers for explicit local dial proposals come from an internal
cryptographically secure 128-bit generator, never from the UI, relay or
wall-clock. Invalid or all-zero generator output fails closed. This is
not a substitute for durable anti-replay and one-time M3 outbound staging.

### Additional 2026-11-03 upstream CVE fingerprint research (no media approval)

The isolated pinned-source probe checks the three-file WebRTC change associated
with CVE-2026-106357 (Chromium 567160162), upstream commit
`7a25e1c85a0af15cae8a2d55bf02e5610bf1af53`: transport lookup by the
channel's original MID, unassociated-only SDP m-line lookup, and the list's
no-prior-MID guard. Source is fetched only from the exact declared Shiguredo
WebRTC SHA, with bounded HTTPS allowlisted paths and offline tamper tests.
A positive result is a **source fingerprint only**, not independent binary
reproducibility, reachability, complete patch-set coverage or permission to
load ARM64 JNI. CVE-2026-103631 and CVE-2026-110137 also require separate
mapping (see #88). The existing AAR and Android runtime remain untouched.
