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
Future staged encryption must recheck the binding and capability inside the
same serialized ratchet/transport admission boundary to prevent TOCTOU races.
No app runtime uses this guard yet; no backend endpoints, server components,
TURN/coturn, UI, WebRTC, release or M6 additions are permitted by this ADR.
