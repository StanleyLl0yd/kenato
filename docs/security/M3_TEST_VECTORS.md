# M3 deterministic canonical framing vectors

Status: M3 in progress. These vectors cover only Kenato-owned canonical payload framing. They do not attempt to make randomized ECDSA signatures or Olm ciphertext deterministic.

All integer fields are unsigned big-endian. Identity ids and Olm public keys below are raw bytes.

## Session bootstrap binding

Inputs:

- identity id: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- account generation: `2`
- publication revision: `3`
- Olm Ed25519 identity key: `606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f`
- Olm Curve25519 identity key: `808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f`
- one-time key #7: `a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf`
- one-time key #8: `c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf`

Expected canonical payload hex:

```text
4b454e41544f2d53455353494f4e2d424f4f5453545241502d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000020000000000000003606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f000000020000000000000007a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000008c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
```

## Session reservation proof

Inputs:

- creator identity id: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- redeemer identity id: `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`
- invite token: `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f`

Expected canonical payload hex:

```text
4b454e41544f2d53455353494f4e2d524553455256452d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
```

## Creator claim proof

Inputs:

- creator identity id: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- invite token: `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f`

Expected canonical payload hex:

```text
4b454e41544f2d53455353494f4e2d434c41494d2d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
```

The submit-init proof additionally includes SHA-256 of the opaque Olm pre-key frame. Its deterministic framing is exercised directly in Go tests while the ciphertext itself remains intentionally opaque and randomized by the session engine.
