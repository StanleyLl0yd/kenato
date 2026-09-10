# M2 Invite and Contact Test Vectors

These vectors define deterministic canonical payload framing for M2 signatures and invite-link parsing. They do not define M3 session-key derivation or ratchet state.

All integers are unsigned big-endian. The sample key/signature byte strings are intentionally synthetic framing fixtures, not literal DER/X.509 keys unless explicitly stated.

## Publication payload

Inputs:

```text
identity id: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
publication revision: 3
identity public key: 010203
signed prekey id: 7
signed prekey created_at: 10
signed prekey public key: 040506
signed prekey signature: 070809
one-time prekeys:
  id=8 created_at=11 public_key=0a0b
  id=9 created_at=12 public_key=0c
```

Expected canonical publication payload (hex):

```text
4b454e41544f2d5055424c49434154494f4e2d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000030000000301020300000007000000000000000a00000003040506000000030708090000000200000008000000000000000b000000020a0b00000009000000000000000c000000010c
```

## Invite signature payload

Inputs:

```text
creator identity id: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
invite token: 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
```

Expected payload (hex):

```text
4b454e41544f2d494e564954452d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
```

## Redemption signature payload

Inputs:

```text
creator identity id: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
redeemer identity id: 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
invite token: 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
```

Expected payload (hex):

```text
4b454e41544f2d52454445454d2d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
```

## Claim signature payload

Inputs use the creator identity id and invite token from the invite vector above.

Expected payload (hex):

```text
4b454e41544f2d434c41494d2d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
```

## Invite URI

The URI vector uses the same creator identity id and invite token bytes as above, plus the synthetic signature bytes `aa bb cc`.

Encode each byte sequence independently with unpadded Base64url, then concatenate exactly as:

```text
kenato://invite/v1/<base64url-creator-id>/<base64url-token>/<base64url-signature>
```

Executable parser tests must assert the exact resulting URI and round-trip bytes. The documentation intentionally keeps the high-entropy Base64url token out of source text so repository secret scanning does not need an allowlist for a synthetic bearer-token-shaped fixture.

Parsers must reject wrong scheme/authority/version, missing or extra path components, padding, invalid Base64url, non-32-byte identity ids/tokens, empty signatures, and signatures above the implementation limit.
