# M5: monotonic call timeout fence (JVM-only)

Pure in-process, non-Android, non-runtime timer acceptance gate for #116.
`VoiceCallMonotonicTimeoutFence` issues bounded deadline tickets only for
outgoing/incoming ringing or connecting, using caller-supplied monotonic
elapsed milliseconds. Tickets are bound to exact call ID, peer ID, phase
and a monotonically increasing local generation. Early, duplicate,
cancelled, replaced, wrong-call/peer/phase and overflow callbacks fail
closed. The only output is a `VoiceCallEvent`; no scheduler, side effect,
signaling, WebRTC, microphone, background work or release is enabled.

**Critical runtime integration requirement:** the future owner must
serialize issuing, consuming, consent revalidation and reducer admission
under the same authenticated M3/WSS lifecycle. The class is process-local;
it gives no persistence, replay protection after process restart or
cross-process ordering. Keystore failure/consent revocation must cancel
the relevant ticket and locally stop already active media. #116/#87
remain OPEN and physical P01–P24 tests are still mandatory.

## Owner-identity invariant

Ticket fields are values for diagnostics, **not credentials for admission**.
The fence now requires the identical issued object (`===`), not data-class
structural equality. A copied/reconstructed ticket or a ticket from a
different fence instance is refused even if key, phase, generation and
deadline happen to match. The legitimate pending ticket stays usable.
Offline JVM regressions cover both cases. No runtime activation.

## Coordinator timeout entrypoint

`VoiceCallAdmissionCoordinator.callback` now accepts only media callbacks.
`RING_TIMEOUT` and `CONNECT_TIMEOUT` require a ticket issued by the
coordinator's `issueTimeout()` and passed to `timeoutCallback(ticket,
nowElapsedMillis)`. That call consumes the exact unfired timeout token
against the CURRENT call snapshot under the coordinator lock and immediately
revalidates pinned consent before generating reducer proposals. Wrong phase,
wrong owner, early, forged or duplicated tickets cannot bypass admission.

This remains **in-process pure policy**, not Android scheduling. The future
voice owner must serialize issuance and invalidation with M3/WSS ownership,
and recheck trust before executing any effect.

## Coordinator-owned fence and phase retirement

The coordinator, not its caller, owns the single process-local timeout
fence. `issueTimeout` and `timeoutCallback` are synchronized on the same
coordinator monitor; callers cannot substitute arbitrary external fences.
Every state transition changing the active key or phase cancels any pending
ticket, as does explicit `cancelTimeout()`. The admission remains an event
proposal, not permission to transmit or start media.
