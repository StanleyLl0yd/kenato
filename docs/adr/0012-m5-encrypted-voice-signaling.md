# ADR 0012: M5 encrypted voice signaling over existing M3/M4

- Status: Proposed for #86; **not** an approved wire contract or a working call
- Date: 2026-10-09
- Scope: client-only audio-call signaling design; no backend or transport endpoint changes

## Context

M4's `MessagingPlaintext` is a **text-only** record inside authenticated M3 ciphertext. The Android inbound path strictly decodes it, imports it into durable chat history, and only then ACKs. A call offer cannot be impersonated as user-visible chat text or passed directly to the existing conversation pipeline. The Go relay must see only the existing bounded M4 routing envelope and ciphertext.

The first M5 slice (#85) supplies a pure single-call state reducer and no transport. The existing M4 mailbox has a maximum 72-hour TTL; it does not imply a ringing or call-event replay policy. The in-memory 64-call retired cache is not durable replay defense.

## Provisional codec proof in the draft PR

A standalone, unconnected `VoiceSignalingPlaintext` schema and Android strict codec use encrypted **application protocol version 2**, while the external M4 Envelope stays at version 1. Version 2 is deliberate domain separation: an M4-only Android receiver rejects it rather than interpreting the call id as chat text. Fields 1-6 keep M4 identity, message and time bindings; field 7 is the call id, field 8 the signal kind, and field 9 the kind-specific body. The codec accepts only fields 1-9 exactly once and in canonical field order, including an empty field 9 for bodyless signals. Tests are local codec tests, not transport security evidence.

This provisional schema is not sent over the network and does not implement application capability discovery, state journal, glare switching, SDP semantic validation, DTLS verification, or WebRTC. Do not connect it to the M4 inbound handler until the entire atomic handoff/classification/replay/ACK design is reviewed.

## Proposed decisions to resolve before implementation

1. **No new server component.** Reuse the established M3 identity-bound Olm encryption and authenticated M4 WSS envelope, ACK, retry and bounded mailbox routing. Do not add HTTP APIs, Go message-type metadata, TURN/coturn, plaintext SDP, or an unauthenticated voice channel. Keep M4 wire protocol v1 and existing text behavior intact.
2. **Distinct encrypted application type.** Define a versioned `VoiceSignalingPlaintext` (never reinterpret `MessagingPlaintext.text`) with an explicit signal kind: OFFER, ANSWER, REJECT, BUSY, HANGUP, ICE_CANDIDATE, END_OF_CANDIDATES. The encrypted record includes sender/recipient identity ids (32 bytes), envelope message id (16 bytes), independent call id (16 nonzero bytes), sent timestamp, absolute expiry and a kind-specific bounded body. Both identity ids, message id and expiry must match the authenticated outer envelope exactly after M3 decryption. Signal contents and type are invisible to the relay.
3. **Compatibility is explicit, never guessed.** Older Android builds cannot decode this application type. Do not generate an M5 offer to a peer until a separately authenticated encrypted capability exchange proves it supports the exact call-signal protocol. Define this exchange and its fail-closed downgrade behavior before enabling a Call UI. Unknown versions and unsupported kinds must not fall back to chat display.
4. **Canonical parsing and limits.** Reject missing/duplicate/unknown fields, nonminimal encodings, contradictory kinds and noncanonical round trips. Keep encrypted M4 ciphertext under its existing 64 KiB maximum. Proposed stricter inner bounds: SDP up to 16 KiB; a single ICE candidate up to 4 KiB; at most 64 remote candidates per call; no arbitrary unbounded lists. Enforce UTF-8 and SDP/ICE structural limits before handing values to WebRTC. Authentication alone does not make SDP or ICE safe.
5. **Short-lived signaling.** Proposed maximum authenticated event lifetime: 90 seconds from send to expiry; receiver also rejects expired events, impossible timestamps and excessive future skew before any UI or media effect. The outer envelope expiry must exactly match the inner expiry. A stale offline mailbox delivery must never ring a phone. Do not silently extend expiry on retry.
6. **Durable replay and ACK ordering.** Inbound (owner identity, sender identity, envelope message id, call id, kind, expiry) deduplication must survive process restart, be bounded/expired, and be committed consistently with M3 ratchet advancement before sending an ACK. Conflicting replay under an existing message id fails closed. Event validation and persistence must occur before reducer side effects. Retrying the exact encrypted envelope must never restart media or duplicate an offer. Recovery must not render call events as chat-history entries. Implementation must explicitly handle failure between ratchet commit, app classification, replay journal commit and ACK; no standalone volatile replay cache suffices.
7. **Call/key identity.** The signaling dispatcher verifies the already pinned contact and M3 session, not a claimed peer id in an untrusted frame. The receiver constructs `VoiceCallKey` from validated identities/call id only after authentication, time and replay checks. Media may start only after local acceptance and verified authenticated answer semantics.
8. **SDP/fingerprint binding.** Offer/answer SDP and the DTLS fingerprint must be authenticated inside the same E2EE record. WebRTC must validate the negotiated peer fingerprint against the authenticated offer/answer; no unauthenticated or silently substituted fingerprint, unprotected candidate or opportunistic fallback.
9. **Glare policy to implement and test.** When both identities call each other simultaneously, compare canonical raw pinned identity ids deterministically to elect one winning outgoing call; retire the losing local offer before processing its incoming counterpart. Neither side may start two media sessions. The #85 reducer does not currently implement this swap; it must be extended and tested separately before enabling signaling.
10. **Connectivity limitation.** Without a new relay, direct ICE/STUN P2P may fail behind symmetric NAT/CGNAT. Do not claim universal reachability or mark M5 complete without documented physical test results and an explicit product decision about the no-TURN limitation.

## Isolated durable replay journal in M5/#86

The standalone Android replay journal now has a bounded (512 records; 64 KiB) checksum-protected no-backup AtomicFile store for **metadata only**: owner and peer identities, authenticated message/call identifiers, signal kind, expiry and SHA-256 of the exact encrypted M4 envelope. It does not retain SDP, ICE, plaintext, ciphertext or chat history. A reused peer/message id with changed ciphertext is a conflict. A fresh offer id reusing an existing live peer/call id is durably suppressed, even after process restart. Expired records are pruned; a full live journal rejects new admissions rather than evicting active replay evidence.

The journal requires the already **M3-committed** `SessionMessageHandoff` and validates exact encrypted inner/outer identity, ids, version and expiry before persisting metadata. It must run **after atomic ratchet+handoff commit** and **before ACK or reducer effects**. It does not yet own the M3 handoff completion or restart reconciliation: existing `MessagingRecoveryCoordinator` still assumes all handoffs are chat messages. Connecting this component without typed recovery and ACK changes is prohibited. Local SHA-256 detects accidental corruption, **not** hostile tampering by an attacker controlling app storage.

## Safe implementation order

- First review this contract, compatibility and capability negotiation, with canonical golden vectors shared where possible.
- Add a bounded strict codec and malformed/version/identity/time/replay regression tests **without** changing M4 text transport behavior.
- Design the atomic encrypted-message classification, durable replay journal, handoff and ACK boundary together; only then dispatch to the call-state reducer.
- Implement and review WebRTC audio/ICE separately under #88, then two-phone NAT/security acceptance under #87.
- Keep this ADR Proposed until the implementation and security review establish exact bytes, immutable version semantics and recovery behavior.

## Non-goals

No backend endpoints, server type dispatch, coturn, audio recording, video, group calls, push/background calling, M6, app version bump or user-visible claim that voice calling currently works.


## Crash recovery of voice M3 handoffs (isolated building block)

An inbound voice signal may be retired only after the atomic M3 decrypt/ratchet/handoff
commit. The isolated `VoiceInboundHandoffRecovery` performs canonical inner/outer
validation, durably imports **live** events into the bounded voice replay metadata
journal, then makes them eligible for an idempotent M4 ACK. A duplicate event has
no second replay import. A fully validated event that has expired while the app was
down can instead have its already-committed M3 handoff retired **without any ACK
or reducer/media effects**. The journal never makes expired entries ACK-eligible.
Failed or corrupt imports must retain the M3 handoff and must never authorize ACK.

This component is not yet connected to the M4 WSS handler or M3 handoff lifecycle.
The caller must durably complete the handoff in a correct crash-safe order, then
coordinate authenticated ACK dispatch. The current `MessagingRecoveryCoordinator`
still treats all handoffs as chat; **do not wire voice to live receiving** until
typed history/replay separation, outbound staging/recovery and explicit capability
negotiation are in place.
