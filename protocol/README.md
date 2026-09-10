# Kenato Protocol

The Kenato wire protocol is platform-independent and versioned independently of Android and server releases.

## Current state

M0 established the outer server-routable envelope. M1 established device-local identity only. M2 adds the first server-visible public identity and invite/contact-establishment contract under the existing `kenato.v1` package.

The current schemas live under:

`protocol/kenato/v1/`

- `envelope.proto` — minimum server-routable encrypted envelope for later messaging;
- `contact.proto` — M2 public identity publication and invite/contact establishment.

M2 does **not** define the Double Ratchet, encrypted-message session state, one-time-prekey claim/consumption semantics, or message delivery. Those remain M3/M4 work.

## M2 invite URI

QR codes and deep links carry exactly this URI form:

```text
kenato://invite/v1/<creator-identity-id>/<invite-token>/<invite-signature>
```

All three path components are unpadded Base64url. The decoded creator identity id is exactly 32 bytes, the decoded invite token is exactly 32 bytes, and the invite signature is a bounded DER ECDSA signature made by the creator identity key over the canonical invite payload below.

No display name, phone number, email address, server address, or other user-searchable identifier is embedded in the invite.

## M2 canonical signature payloads

All integer fields below are unsigned big-endian. Length fields are 32-bit. Timestamps are represented as non-negative 64-bit Unix seconds after validation. Identity ids are exactly 32 raw bytes and invite tokens are exactly 32 raw bytes.

### Identity publication

The publication signature uses SHA-256 with ECDSA P-256 over this exact byte sequence:

1. UTF-8/ASCII `KENATO-PUBLICATION-V1` followed by one NUL byte;
2. 32-byte identity id;
3. 64-bit publication revision;
4. identity public-key length, then exact X.509 SubjectPublicKeyInfo bytes;
5. signed-prekey id;
6. signed-prekey creation timestamp;
7. signed-prekey public-key length and bytes;
8. signed-prekey signature length and bytes;
9. one-time-prekey count;
10. each one-time prekey in strictly increasing id order: id, creation timestamp, public-key length, public-key bytes.

The publication signature itself is excluded from the signed payload. A publication revision is positive and must increase when the published bundle changes; an implementation may accept an exact byte-for-byte replay of the same revision idempotently but must reject a different payload at an already accepted revision.

### Invite creation/binding

The invite signature payload is:

```text
KENATO-INVITE-V1\0 || creator_identity_id[32] || invite_token[32]
```

This lets the redeemer verify end-to-end that the token was created by the identity named in the URI, rather than trusting the server to bind a token to an identity correctly.

### Redemption proof

The redeemer signs:

```text
KENATO-REDEEM-V1\0 || creator_identity_id[32] || redeemer_identity_id[32] || invite_token[32]
```

The server retains this bounded signature only until the creator claims the completed invite or the invite record expires. The creator verifies it before pinning the redeemer identity.

### Claim authentication

The creator signs:

```text
KENATO-CLAIM-V1\0 || creator_identity_id[32] || invite_token[32]
```

Possession of the token alone is therefore not sufficient to retrieve the redeemer bundle from the server.

## M2 server-visible state

The server may retain only the minimum M2 state required to implement the protocol:

- public identity key material and public prekeys;
- monotonically accepted publication revision;
- SHA-256 hash of an invite token, never the raw token at rest;
- creator identity id;
- creation/expiry timestamp;
- redeemed/not-redeemed state;
- while awaiting creator claim, redeemer identity id, redemption signature, and redemption timestamp.

There is no public identity lookup/search endpoint. Creator public material is disclosed only to a party presenting a valid unexpired invite token; redeemer public material is disclosed only to the authenticated creator of that invite.

## Rules

- Unknown protocol versions must fail safely.
- Old wire data must never be silently reinterpreted with new semantics.
- Protocol changes must consider compatibility, malformed input, replay, duplication, and reordering.
- Deterministic test vectors are required when canonical cryptographic framing is introduced.
- Private identity/prekey keys and plaintext user content never belong in server-visible protocol messages.
- Identity public keys, signed-prekey public keys/signatures, one-time public prekeys, signature sizes, repeated counts, request bodies, invite attempts, and retained state are explicitly bounded by implementations.
- Contact identity is pinned locally after verification and must not change silently.

Numeric resource limits are enforced by implementations/configuration and documented alongside the relevant behavior.
