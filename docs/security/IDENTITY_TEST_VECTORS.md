# M1 Identity Test Vectors

These vectors cover deterministic local-identity derivation and signed-prekey canonicalization. They do not define a network wire format; M2 owns publication/transport encoding.

## Identity identifier

Algorithm: SHA-256 over the exact DER SubjectPublicKeyInfo bytes, encoded as unpadded Base64url.

Input public-key bytes (hex):

```text
0102030405
```

Expected identity id:

```text
dPgf4WfZm0y0HW0MzagieMrunz4vJdXlo5Nv89zsYNA
```

## Signed-prekey payload

Canonical payload fields, in order:

1. ASCII/UTF-8 domain separator `KENATO-SIGNED-PREKEY-V1` followed by one NUL byte;
2. prekey id as a 32-bit unsigned-compatible positive integer encoded big-endian;
3. public-key byte length as a 32-bit big-endian integer;
4. exact DER SubjectPublicKeyInfo public-key bytes.

Vector input:

```text
prekey id: 7
public key: 0102030405
```

Expected canonical payload (hex):

```text
4b454e41544f2d5349474e45442d5052454b45592d56310000000007000000050102030405
```

ECDSA signatures are intentionally not represented as deterministic byte vectors because Android Keystore ECDSA uses randomized signing. Verification behavior is tested instead.
