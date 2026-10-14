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

## Pinned-consent revocation during a proposed call

The isolated `VoiceCallAdmissionCoordinator` exposes `revalidateActiveCall()`
for a future serialized runtime boundary to call after contact-pinning,
consent or Keystore changes and immediately before executing call effects.
A failed check silently retires the exact call ID without proposing an
outbound signal to an unapproved peer. When media could already exist
(`CONNECTING` or `ACTIVE`), the only proposed effect is a keyed, local
`STOP_MEDIA`. The `MEDIA_CONNECTED` callback also revalidates current
consent and retires instead of entering `ACTIVE` after revocation.

The coordinator itself does not execute `STOP_MEDIA`. A production adapter
must reliably apply this local teardown even when encryption, network,
consent storage or the Keystore fails, and must check the same exact
peer/call key before creating or retaining media. This is JVM-only
call-control verification, not Android lifecycle, audio or device acceptance.

## Fail-closed teardown after revoked consent

All currently active, exact-key local hangup/reject requests and asynchronous
media-failure/ring/connect timeout callbacks now revalidate the pinned M2
identity and durable M5 v2 consent before reducing a transition. If approval
has been revoked, the call is retired without proposing an outbound signaling
effect. In CONNECTING/ACTIVE it proposes only keyed local `STOP_MEDIA`;
during ringing it proposes no effect. Stale callbacks for a different call
key are ignored without disturbing the current call.

This fixes a JVM-only call-control proposal gap: before this check,
`MEDIA_FAILED`, timeouts and user hangup/reject could still propose
`SEND_HANGUP` or `SEND_REJECT` after consent revocation. An approved
contact continues to receive normal proposed control effects.

**Security boundary:** returned effects are never executed by this class.
A future production effect runner must revalidate consent, active peer/call
key and durable single-use claims *again, immediately before every effect*,
including between `SEND_ACCEPT` and `START_MEDIA`; independent M2/M3
storage and asynchronous revocation still lack a serialized commit boundary.
No Android media, WebRTC, microphone or live voice transport is activated.
