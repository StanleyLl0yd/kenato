# M5 client call-state reducer

Scope: first client-only slice of #84. This is not yet a voice calling feature.

The reducer is deterministic and free of Android framework, audio, networking,
storage and UI dependencies. It consumes a validated event, returns a new
single-call snapshot and side-effect intents. The application layer will own
timers, call signaling, media transport and trusted peer verification.

Call keys use a canonical base64url 16-byte nonzero call identifier and a
canonical base64url 32-byte nonzero pinned peer identifier. These are
correlation values, not authentication credentials.

States: IDLE, OUTGOING_RINGING, INCOMING_RINGING, CONNECTING and ACTIVE.
An incoming offer never replaces an active call. Duplicate or delayed
events do not restart media. Every event is bound to the exact call key.
Local accept is explicit. Ring and connection timeout events are handled
only in the matching phase, and later-stage media failures stop media.
A bounded in-memory cache remembers the last 64 finished call identifiers.

This cache is not durable replay protection. Later authenticated signaling
must enforce message freshness, identity bindings and expiry separately,
including after process restart. Simultaneous outgoing calls also require
an explicit glare policy in a later M5 slice.

The original M5 roadmap names WebRTC, Opus, ICE/STUN and coturn fallback,
while the owner requested no new server components. This first slice is
limited to Android call control and adds none. NAT fallback architecture
requires an explicit owner decision before claiming M5 completion.

Do not expose call content to a server or permit unauthenticated media.
M5 signaling, WebRTC media, audio permissions, background calling and
device acceptance are not implemented in this PR.

Checks: Android unit tests, full repository CI and security review.
