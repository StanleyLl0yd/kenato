# ADR 0014 (proposed): Android client-only P2P voice media

Status: **PROPOSED, NOT ACCEPTED OR ENABLED**
Milestone: M5/#84, implementation tracker #88; acceptance/security tracker #87.
Date: 2026-10-14

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

1. Review and pin one reproducible Android WebRTC native AAR before adding
   a dependency. Candidate: `io.github.webrtc-sdk:android:150.7871.01`
   (BSD-3-Clause; Maven Central,
   https://central.sonatype.com/artifact/io.github.webrtc-sdk/android).
   Compare `im.conversations.webrtc:webrtc-android:149.0.0`
   (https://central.sonatype.com/artifact/im.conversations.webrtc/webrtc-android).
   The selected AAR's source lineage, bundled third-party notices,
   vulnerability posture, SHA-256, Gradle resolution, byte growth, and
   compatibility with the app's exact pinned Gradle/AGP/NDK must be
   recorded, not assumed from artifact availability.
2. Preserve currently targeted native ABIs: `armeabi-v7a`,
   `arm64-v8a` and `x86_64`; no unreviewed ABI drop. The M3 JNI library
   build/verification remains unmodified. Verify library symbol loading
   on physical Android 10 and Android 13, at least.
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

The published Maven Central POMs currently advertise both candidates:
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
