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
