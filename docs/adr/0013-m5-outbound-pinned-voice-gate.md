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
leaves M3/M4 ciphertext. The M3 handoff temporarily contains authenticated
plaintext protected by device-local session storage: that is a restorable
local persistence boundary, not a new server-visible field. Only one pending
voice event is allowed during this foundation phase.

No app runtime uses this guard/stager yet; no backend endpoints, server
components, TURN/coturn, UI, WebRTC, release or M6 additions are permitted
by this ADR.
