# ADR 0013: Outbound voice-v2 pinned-contact admission

Status: proposed (isolated M5 #97 foundation; no production opt-in)

Before any future encrypted outbound v2 signaling is staged, the caller must
independently confirm that its local M2 directory contains the selected peer's
**pinned P-256 identity key**, that the M3 established Olm session has the
**same local contact binding**, and that an **explicit, consumed, signed voice
capability proof** was durably approved under the currently pinned key.
Legacy/unverified clients are not probed via M4 and never receive a v2 offer
until all three checks succeed.

`VoiceOutboundCapabilityGuard` provides a strict fail-closed preflight with
read-only adapters to `ContactLocalState`, `LocalSessionRepository`, and
`DurableVoiceCapabilityConsentRepository`. It validates owner/peer identity
and cryptographic key provenance instead of trusting network metadata.
Tests cover unsigned/unknown peers, real signed challenge confirmation,
M2/M3 binding divergence, identity/key substitution, revocation and corrupt
AES-GCM consent storage.

This guard is **not** a call authorization or an outbound send operation.
`VoiceOutboundHandoffStager` now provides an isolated, non-wired first
outbound crypto-coupled stage. It validates v2 signal/body/TTL and requires
signed capability both before encryption and inside the M3 synchronized
encrypt-and-commit builder. The serialized builder also rechecks pending
message IDs and earlier uncompleted voice handoffs before it can commit the
advanced ratchet and exact M4 envelope together with the encrypted v2
application plaintext. This assumes the actual production session and
handoff adapters use the **same** `LocalSessionRepository` instance/lock;
separate instances and mutations of contact/consent are not yet covered by
one shared transaction/lifecycle boundary. This class must remain **unwired**
until that ordering is proven and outbound voice SendAccepted/expiry/restart
recovery is independently implemented. The M4 text recovery intentionally
fails closed if it sees an outbound v2 record.

Signed consent is not inferred from relay behavior and no plaintext SDP/ICE
leaves M3/M4 ciphertext. The current M3 handoff retains a temporary
plaintext copy of the exact application record in an Android no-backup
AtomicFile. This file is isolated by the app sandbox but **is not itself
AES-GCM encrypted at rest** (unlike the separate durable M5 semantic event
store). This inherited M3 trust boundary needs explicit threat-model/owner
review before live voice staging is enabled, especially because SDP can
contain private local-network addresses. The ciphertext sent to the server
never includes this plaintext outside M3 encryption. Only one pending voice
event is allowed during this foundation phase.

The optional `VoiceOutboundHandoffRecovery` and `MessagingRecoveryCoordinator.outboundVoice`
adapter now recognize the committed v2 record without re-encrypting it,
validate canonical inner voice + outer M4 + session ciphertext binding,
and offer the exact immutable envelope for ordinary M4 transport retry.
Expired records can be removed only under the transport's synchronized
non-in-flight expiry boundary. An authenticated SendAccepted removes the
M3 handoff atomically; no M4 chat history entry is created. With the
adapter absent, pre-existing M4 recovery rejects outbound v2 records.
This recovery is still **not production wired** and is not call/media
integration or proof of user consent at the runtime call-admission point.

A separate, not-yet-wired `VoiceCapabilityQrWire` carries the existing
single-use challenge and signed proof as bounded canonical base64url QR/text
records. Its `kenato-voice-v2:challenge:` and `kenato-voice-v2:proof:`
prefixes are explicitly out-of-band data strings, not Android deep links or
an authenticated network protocol. The binary challenge record contains
`KVQ2`, version 2, intended verifier identity, intended signer identity,
16-byte nonce, and absolute expiry; the proof QR carries the existing
canonical `VoiceCapabilityProofWire` bytes unchanged. The challenge is
**not signed**: before producing a proof, the signer must verify the
requesting contact's pinned M2 identity and explicitly approve signing.
After import, the verifier must validate the P-256 signature and consume
its previously durably stored one-time challenge with explicit local user
approval. Importing a QR record alone NEVER grants voice permission.

The isolated `VoiceCapabilityOutOfBandService` now connects the
three offline operations without enabling transport: an existing M2 pinned
contact issues the persisted one-time challenge, a responder with the
selected pinned verifier key explicitly approves signing it with their
non-exportable Android M1 identity, and the verifier explicitly approves
the imported signed proof before consuming its stored challenge and
persisting capability consent. A replacement key or a mismatched verifier,
nonce or expired record fails closed. The QR alone never grants permission;
caller UI must independently show and confirm the pinned contact identity.
JVM tests use real P-256 signatures and encrypted consent state.

No app runtime uses this guard/stager, QR codec or offline coordinator yet; no backend endpoints, server
components, TURN/coturn, UI, WebRTC, release or M6 additions are permitted
by this ADR.
