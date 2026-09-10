# ADR 0007 — Local identity key model

Status: Accepted  
Date: 2026-09-10

## Context

M1 introduces the first persistent cryptographic identity on Android. The design must preserve the repository invariants that private identity keys never leave the device, contact identity cannot later change silently, sensitive state is excluded from backup, and cryptographic behavior uses mature platform/JCA primitives rather than custom cryptography.

Android API 26 is the minimum supported platform. Direct Android Keystore ECDH support is not uniformly available across the supported API range, while ECDSA P-256 and AES-GCM protection are available through Android Keystore.

## Decision

Kenato M1 uses the following local identity model:

- the long-lived identity key is an ECDSA P-256 key pair generated inside Android Keystore;
- the private identity key is non-exportable and is used only for signatures;
- the public identity key is the X.509 SubjectPublicKeyInfo DER encoding exported by Android Keystore;
- the local identity identifier is the full SHA-256 digest of those public-key bytes, encoded as unpadded Base64url;
- signed prekeys and one-time prekeys are P-256 key pairs generated with the platform JCA provider;
- each prekey private key is immediately encrypted with AES-256-GCM using a separate non-exportable Android Keystore AES key before durable persistence;
- AES-GCM additional authenticated data binds the encrypted private key to its prekey kind, id, and exact public key;
- the current signed prekey is signed by the long-lived identity key using SHA-256 with ECDSA over a domain-separated canonical payload;
- at most one previous signed prekey is retained for a later publication/grace-period lifecycle;
- the default one-time prekey pool is 32 and the persisted pool is hard-bounded at 100;
- prekey ids are positive, monotonically increasing local integers and are never silently reused;
- the complete local metadata/wrapped-prekey state is persisted as one versioned, bounded record with synchronous commit semantics;
- the serialized record includes a SHA-256 corruption checksum so accidental bit-level corruption fails closed; this checksum is not treated as an authentication boundary, while secret/public-key bindings are protected by AES-GCM AAD and signed-prekey signatures;
- state corruption, missing Keystore material, or a public-key/Keystore mismatch fails closed and never causes automatic identity regeneration;
- destructive identity reset exists only as an explicit recovery primitive; product UI must require an explicit user decision before invoking it;
- M1 does not publish any identity material to the server. Server publication, prekey distribution, and invite/session establishment belong to M2 or later milestones.

The app does not require per-use user authentication for these Keystore keys because background communication must eventually be able to use the identity without an interactive unlock prompt. Hardware-backed storage is used when the device's Android Keystore provides it but is not a compatibility requirement.

## Persistence and backup

The versioned state record is stored in app-private Android storage. Private identity key material remains exclusively in Android Keystore; only AES-GCM-wrapped prekey private material is persisted outside Keystore.

Existing manifest and backup-rule policy denies Android cloud backup and device-to-device transfer for all app data domains. M1 does not introduce an exception.

## Consequences

Benefits:

- the long-lived private identity key is non-exportable;
- prekey private material is not persisted in plaintext;
- supported Android 8+ devices share one auditable design;
- state is bounded and failure behavior is explicit;
- accidental persisted-record corruption is detected before state is accepted;
- the design leaves network publication and protocol framing to M2 rather than prematurely coupling M1 to the server.

Trade-offs:

- P-256 is chosen for the M1 compatibility floor rather than requiring Curve25519 Keystore support available only on newer hardware/API combinations;
- software-generated prekeys exist briefly in process memory before being wrapped;
- losing either app-private state or the required Keystore entries makes the identity unusable and requires explicit reset, which intentionally changes identity;
- no identity recovery across uninstall/device loss exists in 1.0 unless a future separately reviewed secure recovery design is approved.

## Security review

This ADR changes the persistent identity model and secret-persistence boundary, so `docs/security/THREAT_MODEL.md` is updated in the same milestone. The deterministic identifier and signed-prekey payload vectors are recorded in `docs/security/IDENTITY_TEST_VECTORS.md`.
