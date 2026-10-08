# M4.5 diagnostics: closed physical acceptance

Scope: #81, parent #59. This is an operational diagnostic facility, not a telemetry
service. It does not modify wire protocol, identity/session storage, WSS auth policy,
TLS validation or server endpoints. Android versionCode 4 and versionName 0.0.4
support in-place upgrade without deleting identity/session data.

## Android (diagnostic viewer from 0.0.3; clock-skew fix in 0.0.4)

Open section **6. Local diagnostics**. This displays the newest 40 event-code entries
while the bounded, persisted journal retains at most 128 entries. The screen
refreshes approximately every two seconds. Press **Copy log** or **Share** to
explicitly export all retained events; **Clear** deletes only the diagnostic journal,
not identity, contacts, sessions, history, or the accepted service origin.

Only ISO-8601 UTC timestamps and fixed enum codes are stored in app-private
SharedPreferences. Android application backup is disabled. Do not add exception
messages, socket URLs, account/identity/contact identifiers, IP addresses, invite
URIs, plaintext, keys, ciphertext, signatures, frames or HTTP headers to this
journal. Never send diagnostics to a server automatically. Clipboard/export is
explicit and may be visible to the chosen destination; check before sharing.

Significant sequence examples:

- `CONNECT_ATTEMPT`, `SOCKET_UPGRADED`, `AUTH_CHALLENGE_RECEIVED`,
  `AUTH_RESPONSE_SENT`, `AUTHENTICATED`: working connection.
- `AUTH_CHALLENGE_REJECTED`: reject an expired/invalid challenge, including
  phone/server clock skew. Confirm automatic time.
- `AUTH_CHALLENGE_CLOCK_SKEW_TOLERATED` (0.0.4+): accepted a valid challenge
  with at most five seconds of slow local clock. No nonce, clock offset or expiry logged.
- `LOCAL_IDENTITY_INVALID`, `IDENTITY_SIGNING_FAILED`: identity or
  Android Keystore path failed; do not clear app data.
- `AUTH_CONFIRMATION_REJECTED` following `AUTH_RESPONSE_SENT`: server
  rejected or failed to confirm authentication; cross-reference server journal.
- `TRANSPORT_CERTIFICATE_ERROR`, `TRANSPORT_DNS_ERROR`,
  `TRANSPORT_HTTP_4XX`, `TRANSPORT_HTTP_5XX`, `TRANSPORT_HTTP_OTHER`,
  `TRANSPORT_TLS_ERROR`, `TRANSPORT_IO_ERROR`:
  transport-level failure categories only, not raw exception text.
- `SERVER_FRAME_INVALID`, `SERVER_PROTOCOL_REJECTED`, `RECOVERY_FAILED`,
  `TRANSPORT_FAILED_CLOSED`: fail-closed operation.
- `RECONNECT_SCHEDULED`, `RECONNECT_EXHAUSTED`: retry path.

## OCI Go server

Systemd captures Go `log/slog` diagnostic records, including only fixed stage
labels with `event` and `reason` fields. The server intentionally never emits
user IDs or other correlation-sensitive values. Use a bounded time window:

```sh
sudo journalctl -u kenato-server --since '10 minutes ago' --no-pager | grep kenato_messaging_wss
```

Server stage codes include `response_read_or_timeout`,
`response_decode_or_shape`, `challenge_response_mismatch_or_expiry`, and
`identity_signature_not_verified`. `authentication_ok` is success.

Security note: publicly exposed WSS is reachable by unauthenticated clients,
so event volume can grow under scanning. Limit diagnostic traffic via the
already-reviewed Nginx edge policy and journal retention controls; never enable
raw payload or request-header logging as a substitute. Keep backend TCP 8080
bound to loopback. 

## Android 0.0.4 receive-only clock tolerance

Android 10 physical WSS diagnostics showed a decoded challenge being rejected before
any signature or response. Go issues the challenge with server time +30 seconds.
Android's previous 30-second maximum remaining lifetime falsely rejected fresh
challenges when the device wall clock was even slightly behind.

For **receiving a WSS authentication challenge only**, Android now permits
remaining lifetime <=35 seconds (the 30-second server lifetime plus <=5 seconds
of possible clock lag), but still rejects expired, malformed and farther-future
challenges. The strict 30-second protocol validator remains unchanged and is used
for local response checks. The Go server still independently verifies every
response within its exact 30-second window and validates the P-256 signature,
challenge bytes and identity. No wire format, certificate policy, server lifetime,
identity, storage or state-machine transitions have been changed.

Never delete app data or republish identity/session state as a workaround.
Two-device physical E2EE acceptance is still required by #59 before M5.
