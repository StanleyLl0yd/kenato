# M5: WSS outbound dispatch-time expiry fence

This change hardens the **shared existing M4 WSS dispatch loop** in preparation
for typed M5 outbound voice recovery. It does not enable the M5 sender or media.

The prior loop captured a timestamp while building a durable recovery plan.
Recovering or checking other queued records could delay dispatch past an
envelope's expiry. Reusing that timestamp to validate the envelope could enqueue
an already-expired M4 or M5 message into the socket.

Before queueing each unsent recovered envelope, the coordinator now:

1. Decodes and validates the exact durable, canonical envelope at the earlier
   recovery-preflight timestamp, and serializes the outgoing frame.
2. Reads the clock again **after frame serialization** and fails closed if that
   clock regressed relative to the prior timestamp.
3. If the frame is expired at dispatch-time, requests *durable* expiry using the
   same outbound message key, and skips the send. A failed/unconfirmed durable
   expiry fails closed rather than risking an expired network dispatch.
4. Otherwise enqueues the already serialized exact frame and starts the normal
   existing acceptance watchdog.

JVM tests cover expiry during recovery, a still-valid delayed send, backwards
wall-clock movement and refused durable terminalization.

**Boundary:** The check is immediately before the transport API call, not a
guarantee of physical network transmission time. Once `sendBinary` accepts a
frame, the connection owns the in-flight lifecycle; the client must not retire
it as unsent while an authenticated send acceptance may still arrive. This
change does not solve native socket buffering, inter-process session locking,
M3 after-builder disk durability, or on-device WSS/media acceptance. #116, #87,
#88 remain OPEN. No microphone, WebRTC runtime, infrastructure, release, or M6.
