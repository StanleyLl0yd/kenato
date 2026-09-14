# M4 deterministic canonical framing vectors

Status: M4 protocol/authentication contract. These vectors cover Kenato-owned canonical identity-authentication framing. They do not make randomized ECDSA signatures or M3/Olm ciphertext deterministic.

All integer fields are unsigned big-endian in canonical signed payloads. Identity ids and challenges below are raw bytes.

## WSS identity authentication proof

Inputs:

- identity id: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- connection challenge: `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`
- challenge expiry Unix seconds: `1700000030` (`0x000000006553f11e`)

Expected canonical payload hex:

```text
4b454e41544f2d4d4553534147494e472d415554482d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000000006553f11e
```

Equivalent framing:

```text
"KENATO-MESSAGING-AUTH-V1\0"
|| identity_id[32]
|| challenge[32]
|| expires_at_unix_seconds:u64be
```

The resulting bytes are signed with ECDSA P-256/SHA-256 through the existing Kenato identity key. Production signatures are not expected to be byte-for-byte deterministic.

## Authenticated delivery-context invariant

For every delivered `Envelope`, the recipient decrypts `Envelope.ciphertext` through the already-pinned M3 session and then decodes `MessagingPlaintext`. Before application-visible delivery or ACK, all of these must match exactly:

- `Envelope.sender` == M3 sender identity == `MessagingPlaintext.sender_identity_id`;
- `Envelope.recipient` == local/M3 recipient identity == `MessagingPlaintext.recipient_identity_id`;
- `Envelope.message_id` == `MessagingPlaintext.message_id`;
- `Envelope.expires_at_unix_seconds` == `MessagingPlaintext.expires_at_unix_seconds`.

The Go and Android protocol tests use the same authentication vector and include negative tests for challenge substitution, exact-expiry rejection, overlong TTL/text and routing-context rewrite.
