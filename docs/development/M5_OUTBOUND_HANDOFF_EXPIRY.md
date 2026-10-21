# M5 outbound voice handoff expiry at M3 build boundary

This is an isolated JVM-only hardening for `VoiceOutboundHandoffStager`, not
an Android voice effect runner or WebRTC integration.

The earlier outbound preflight timestamp is used for signed event generation,
but **not** treated as proof that the encrypted handoff remains fresh. A second
clock read, immediately before the in-M3-builder validation/return, must be
non-regressed and strictly earlier than the immutable encrypted envelope expiry.
Expired and backwards-clock events throw inside the atomic staging builder so
that no outbound voice record is persisted by the M3 handoff transaction.

Three JVM regressions simulate M3 builder delay past expiry, a backwards clock
jump and a still-fresh delayed handoff. Any native ratchet work already done
before the builder callback is ephemeral until that transaction commits;
this check does not independently prove the production session-store atomicity.

**Remaining boundary:** a delay after callback return but before actual disk
commit/send still requires serialized M3/WSS lifecycle and a fresh transport
send-time expiry guard. This does not enable a voice sender, microphone, vendor
WebRTC, new infrastructure, release or M6; #116/#87/#88 remain OPEN.
