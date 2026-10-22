# M5 process-local voice effect proposal claim gate

Scope: #116 / #87. **ISOLATED JVM-ONLY PROPOSAL, NOT A LIVE EFFECT RUNNER.**

A pure `VoiceCallReducer` returns `VoiceCallTransition.effects` but these
are only proposed SEND_* and START/STOP_MEDIA actions. The new
`VoiceEffectClaimGate` offers ephemeral one-use reference-identical tickets,
invalidated by the next registered transition or owner close. It checks the
exact latest transition snapshot and revalidates the peer for all outgoing
send/media-start proposals; a failed approval consumes the ticket. The
exception is `STOP_MEDIA`, which remains available for exact local teardown
even when trust is revoked. The future media adapter must own a separate
exact-keyed media handle and reject callbacks from other calls.

These JVM checks cannot prove the eventual Android runtime's correctness:
the gate currently has **no production call site** and never opens a socket,
stages M3 E2EE signaling, claims a durable effect, accesses audio hardware,
or schedules a timeout. The future owner must share one serialized lifecycle
lock covering: reducer commit, M2 signed consent and Keystore admission,
M3 ratchet state and durable single-use send claim, WSS accepted/expiry,
actual media state and closing actions. A snapshot supplied outside that
owner may become stale between the gate check and a real side effect.
In-memory ticket identity never replaces persisted replay defense.

Test cases cover one-shot use, revoked consent, stale snapshot, replacement,
local stop after revocation, concurrent-call key isolation, busy-peer
revalidation, and oversized effect-list refusal. Physical effect execution,
microphone lifecycle, WebRTC and #87 P01-P24 remain required. No release,
production migration, new infrastructure, TURN or M6 is authorized.
