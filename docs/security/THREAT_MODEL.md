# Kenato Threat Model

Status: M2 Invite + Contact Establishment complete. M3 E2EE Session is in progress: the authenticated protocol/server bootstrap boundary is implemented under review, while Android/native ratchet execution and secret persistence remain pending.

This document describes what Kenato intends to protect, what the system trusts, and what it does not claim to solve.

## Assets

Primary assets:

- private identity keys;
- private prekey material;
- session and message keys;
- message plaintext;
- call signaling plaintext;
- voice plaintext;
- contact identity bindings;
- authentication credentials;
- invite secrets.

Secondary privacy-sensitive data:

- communication timing;
- recipient routing identifiers;
- IP addresses visible during normal network operation;
- temporary invite/redemption/session-bootstrap relationship metadata;
- mailbox state.

## Trust boundaries

### Mobile device

Trusted to protect application secrets while the operating system and application sandbox remain uncompromised.

Kenato cannot protect plaintext from a fully compromised device or OS.

M1 generates the long-lived identity signing key inside Android Keystore. Its private key is non-exportable. Prekey private keys are generated in process memory and immediately persisted only after AES-256-GCM wrapping with a separate non-exportable Android Keystore key. Hardware backing is used when the device provides it but is not assumed by the security model.

Loss, corruption, or mismatch of the M1 persisted identity record and required Keystore entries fails closed. Kenato does not silently create a replacement identity in that condition; replacement requires an explicit destructive recovery action.

M2 adds local contact identity pins. A newly established peer binding is accepted only after the peer public identity bundle and invite/redemption proof have been cryptographically verified. An existing pin is never silently replaced.

Pending M2 invite bearer secrets and contact pins are app-private and excluded from Android cloud backup and device-to-device transfer under the repository's all-domain backup policy.

M3 keeps the M1/M2 P-256 identity as the sole contact trust anchor. The selected vodozemac Olm account identity keys and public one-time keys are separate session-engine material and must be authenticated by a P-256 binding signature before use. The Android/native implementation must additionally pin the exact peer M3 account generation and engine identity keys and must fail closed on unexpected replacement. Native account/session secret persistence and crash-safe ratchet commits are part of the still-pending M3 Android/native slice and are not claimed as implemented by the protocol/server slice alone.

### Kenato server

The server is not trusted with user content or private identity/prekey/session material.

It may process:

- public identity material;
- public M1/M2 prekeys and their signatures;
- monotonically accepted M2 publication revisions;
- invite token bytes transiently while handling a bounded request;
- SHA-256 invite-token hashes at rest;
- invite creation/expiry/redemption state;
- temporary creator/redeemer identity-id relationship metadata until claim/expiry cleanup;
- M3 public Olm account identity material and public one-time keys authenticated by the owner's P-256 identity;
- monotonic M3 account generation/publication revision metadata;
- a single creator one-time-key allocation bound to a live redeemed invite;
- a bounded opaque Olm pre-key initialization frame and its authenticated submit proof until creator claim/expiry;
- routing identifiers and opaque encrypted payloads in later messaging milestones;
- bounded operational state needed to deliver traffic.

Compromise of the server must not reveal message or voice plaintext or any device private key.

M2/M3 expose no public identity or session-bootstrap search/lookup endpoint. Creator public material is disclosed through invite-authorized flows; redeemer material and the initial session frame are disclosed only to the authenticated creator of that invite.

Successful creator claim deletes the invite relationship row and cascades deletion of temporary M3 reservation/init state in the same SQLite transaction that retrieves the bounded claim result. Unclaimed expired rows are removed by explicit retention cleanup at server startup and on an hourly schedule; the M3 temporary rows reference the invite/reservation rows with cascading foreign keys.

### TURN server

TURN is treated as an untrusted network relay. It must not require end-to-end plaintext.

### Push providers

Push services may be required for reliable background wake-up. Push payloads should contain the minimum information necessary and should not include message plaintext, contact names, or sensitive call details.

### Source repository, CI, and release signing

GitHub source control and GitHub Actions are security-sensitive supply-chain boundaries.

Ordinary pull-request code is untrusted and must not receive production signing material or privileged write tokens.

The M0 repository/release foundation establishes:

- the default branch and release tags are protected by active no-bypass rulesets;
- critical merge gates are required and strict;
- external Actions/container dependencies are immutable-pinned;
- the protected `release` environment exists; production signing secrets and certificate trust material, when provisioned, are confined to it;
- release artifacts are tied to a verified source revision and signing identity and receive artifact attestations.

The M3 native slice introduces a Rust/NDK dependency boundary. Exact vodozemac/toolchain pinning, committed Rust dependency locking, supported ABI validation and native supply-chain checks are M3 exit requirements; they are not satisfied merely by the server bootstrap implementation.

## Threats in scope

### Software supply-chain and release compromise

An attacker attempts to introduce malicious source/dependencies, weaken CI checks, replace a release tag, steal signing material, or substitute release artifacts.

Mitigations:

- pull-request-only protected default branch with strict required checks;
- no force pushes/deletion and no ruleset bypass actors;
- required signed commits on the default branch;
- immutable `v*` release tags;
- full-SHA-pinned GitHub Actions and digest-pinned critical containers;
- least-privilege workflow permissions and non-persistent checkout credentials;
- Semgrep, Gitleaks, Dependency Review, govulncheck, Android lint, Qodana, and CodeQL according to stack support;
- release signing secrets isolated in the `release` environment;
- independent expected certificate fingerprint verification;
- release source must be a successfully verified `main` commit;
- release checksums and OIDC-backed artifact attestations.

### Network interception

A network observer may capture or modify traffic.

Mitigations implemented through the current M3 server-bootstrap slice:

- TLS for client-server transport at the reviewed deployment boundary;
- identity-key signatures over M2 publication/invite/redemption/claim canonical payloads;
- P-256 identity signatures over M3 session-account bindings, reservation intent, initial-frame submission, and creator claim;
- explicit protocol-version, generation, identity, invite-token and one-time-key bindings;
- explicit replay/idempotency handling for bootstrap operations.

TLS protects invite bearer secrets in transit from passive/active network attackers, while client-verifiable signatures make token-to-identity, redemption-to-identity, session-account-to-identity and initial-frame bindings independently verifiable. Authenticated Double Ratchet payload protection is provided only after the Android/native vodozemac slice lands and therefore is not yet claimed by this intermediate server slice.

### Malicious or compromised server

An attacker obtains server storage, process access, or operator privileges.

Mitigations:

- no private identity, prekey, Olm account, one-time-key, or ratchet keys on the server;
- no plaintext messages or voice on the server;
- server stores invite-token hashes rather than raw tokens at rest;
- M2 invite descriptor is signed by the creator identity key;
- redeemer intent is signed over creator identity id, redeemer identity id, and invite token;
- clients derive identity ids from exact public-key bytes and validate publication/signed-prekey signatures before pinning;
- M3 public Olm account identity keys and OTK set are covered by the existing P-256 trust anchor;
- M3 reservation and submit proofs bind the exact invite participants, creator generation/OTK allocation, redeemer generation and SHA-256 of the opaque initial frame;
- creator claim returns enough authenticated fields for the correct client to independently re-verify the stored submit proof instead of trusting server assertions;
- M2 and M3 publication revisions/generations are monotonic and signed;
- no public identity/session enumeration endpoint;
- successful claims delete temporary relationship/bootstrap records and expired invite state is removed by bounded retention cleanup;
- minimum durable metadata;
- secrets isolated from logs;
- contact/session identity verification performed by clients.

A malicious server can deny service, suppress a redemption/bootstrap, exhaust or withhold public one-time keys, retain metadata outside Kenato's intended implementation policy, or replay stale-but-valid public material within accepted protocol rules. It must not be able to make a correct client silently pin a different Kenato identity or M3 engine identity, or alter/transplant the authenticated initial frame, without a signature/hash/pin verification failure, assuming SHA-256 and ECDSA P-256 remain secure and the peer private identity key is uncompromised.

### Invite/session-bootstrap theft, replay, and substitution

An attacker obtains or guesses an invite, replays a creation/redemption/reservation/submit request, attempts to reuse a consumed token or OTK, substitutes another participant/account, or tries to claim peer/session material without creator authorization.

Mitigations:

- 32-byte cryptographically random invite tokens;
- fixed 24-hour server expiry;
- single-use redemption state transition performed atomically;
- SHA-256 hash-at-rest token storage;
- creator signature binds creator identity id to the exact token and travels in the QR/deep link;
- redeemer signature binds both identity ids to the exact token;
- creator claim requires both token possession and a valid creator identity signature;
- M3 redeemer role is deterministic and reservation requires that exact already-redeemed identity;
- one creator OTK is atomically removed from the available pool and reserved to one token hash; exact reservation replay returns the same key;
- OTK ids are positive, strictly increasing within signed publications, and server high-water tracking prevents retired/consumed ids from being resurrected;
- fallback-key reuse is not supported;
- submit proof binds both identities, token, both account generations, creator OTK id, message type and opaque-frame digest;
- exact duplicate/idempotency behavior is explicit and conflicting replays fail closed;
- malformed/expired/redeemed/wrong-identity requests fail without disclosing unrelated identities;
- a process-wide bounded pre-crypto concurrency/rate gate runs before expensive service verification;
- per-identity active-invite quotas and global retained-state caps bound persistent abuse.

Anyone who obtains an unused invite URI before its intended recipient redeems it can attempt redemption. Invite secrecy is therefore a bearer-capability assumption until first use or expiry; Kenato does not claim recipient-specific confidentiality for a shared invite before redemption.

M2/M3 creator claim is intentionally destructive on the server: a successful claim removes the temporary relationship/bootstrap rows rather than retaining a replay cache. If the successful claim response is lost before the creator durably commits local contact/session state, the peers must establish a fresh invite rather than recovering the consumed claim from the server. This trades retry availability for lower relationship-metadata retention and does not permit silent identity substitution.

The server prevents reuse of a consumed OTK id within an account generation, but it does not retain an unbounded historical set of every old OTK public-key byte string. Correct clients must generate genuinely fresh vodozemac OTKs and monotonically increasing bookkeeping ids when replenishing a generation. Reusing old private/public OTK material under a fresh id is a client compromise/bug and is prohibited by the M3 client implementation contract.

### Message tampering and replay

An attacker reorders, duplicates, modifies, or replays encrypted protocol messages.

Current M3 server-bootstrap mitigation authenticates the single initial opaque pre-key frame with the redeemer's P-256 submit proof and binds it to the exact invite/session context. The actual Olm/Double Ratchet replay, reordering and skipped-key behavior becomes implemented only when the vodozemac native session slice lands.

M3 exit requires:

- authenticated Olm encryption/decryption;
- crash-safe ratchet/session state evolution;
- bounded skipped-message handling using the selected engine's fixed limits;
- malformed/oversized/replayed/reordered integration tests;
- no caller override that increases those engine limits.

Ordinary encrypted-message transport, mailbox routing and delivery acknowledgement remain M4.

### Identity and session-account substitution

A server or attacker attempts to replace a contact's Kenato identity key or M3 Olm account identity.

Mitigations:

- identity id is the full SHA-256 digest of exact X.509 SubjectPublicKeyInfo identity-public-key bytes;
- public M2 identity publication is signed by the corresponding long-lived identity key;
- the current signed prekey is independently signed by that identity key;
- creator invite and redeemer proof signatures bind contact establishment to those identity ids;
- M3 Ed25519/Curve25519 account identity keys and OTK set are signed by the same P-256 identity;
- account generation/revision transitions are monotonic and engine identity keys cannot change inside one generation;
- identity binding is stored locally after verification and M3 must additionally pin exact peer account-generation/engine-key bytes;
- existing pins cannot be silently replaced;
- unexpected identity/account change must become an explicit user-visible recovery decision rather than automatic trust.

M1 rejects local identity-state/Keystore mismatches rather than silently rotating the local identity. M3 native account recovery must preserve the same fail-closed principle and invalidate affected sessions rather than silently replacing engine identity material.

### User enumeration and spam

An attacker tries to discover users or flood them.

Mitigations:

- no public user/session search or identity/session bootstrap lookup;
- invite-only discovery and M3 bootstrap authorization through an already redeemed invite;
- single-use/expiring invites;
- active-invite quotas;
- bounded total retained identity/invite/session-bootstrap state;
- process-wide concurrency/rate limits before expensive cryptographic verification;
- request-body, field and collection limits;
- missing-identity failures at public HTTP boundaries use the same generic invalid-request category as malformed/unauthenticated requests rather than exposing a dedicated identity-existence response.

The in-process rate gate is deliberately a coarse resource bound, not a full public-edge anti-abuse system. Source-aware/distributed rate limiting must be designed together with the reviewed TLS/reverse-proxy deployment boundary rather than trusting arbitrary forwarded-address headers inside the loopback service.

### Resource exhaustion

Malformed or excessive requests attempt to exhaust memory, CPU, storage, signature verification, SQLite locks, WebSocket slots, prekeys, mailbox capacity, or TURN allocations.

Mitigations implemented through the current M3 server-bootstrap slice:

- 64 KiB M2 contact request/response limits and 128 KiB M3 bootstrap request/response limits;
- M3 opaque initial frame capped at 96 KiB;
- bounded parser fields and repeated-key counts;
- M3 public Olm keys fixed at 32 bytes and session bundle OTK count limited to 1..50;
- strict public-key/signature/token sizes before cryptographic parsing;
- process-wide pre-crypto concurrency and operation-window limits;
- active invite quotas, global identity/invite/session-bootstrap caps, exact expiry checks and periodic expired-invite cleanup;
- atomic single-OTK allocation and explicit exhaustion failure;
- SQLite busy timeout, bounded transactions, indexes and serialized writes;
- HTTP header/body and operation timeouts;
- cancellation propagation through request contexts.

M3 Android/native work must additionally bound persisted sessions (maximum 256), application plaintext (64 KiB), serialized engine snapshots and native/JNI allocations while preserving vodozemac's skipped-key/message-gap limits. Later milestones must additionally bound WebSocket connections/queues, mailbox quotas/retention and TURN allocations/credential lifetimes.

The M1 persisted identity record has an explicit maximum serialized size and one-time prekey pool. M2 preserves those bounds for published prekey collections and Android contact state. M3 server session-bootstrap state is separately bounded and temporary reservation/init rows are tied to the bounded invite lifecycle.

### Local data leakage

Backups, logs, crash reports, screenshots, or local storage may expose sensitive information.

Mitigations:

- long-lived identity and prekey-wrapping keys in Android Keystore;
- prekey private material persisted only as AES-256-GCM authenticated ciphertext bound to its kind, id, and public key;
- M2 contact pins and pending invite secrets remain app-private and are covered by the existing all-domain backup/device-transfer denial;
- cloud backup and Android device-to-device transfer are denied by manifest policy plus explicit all-domain rules for both legacy and Android 12+ backup formats;
- cross-platform transfer is not configured; it requires a separate reviewed iOS app identity and transfer contract before use;
- backup policy is enforced by repository checks and Android build/lint validation;
- no raw invite tokens, private keys, secret-bearing signatures, Olm ciphertext, complete public bundles, or plaintext user content are intentionally written to logs;
- minimum telemetry;
- UI screenshot restrictions considered only where they improve privacy without harming normal UX.

The M3 native slice must keep Olm account/session snapshots app-private and backup-excluded. ADR 0009 requires a fresh random 32-byte vodozemac pickle key for every encrypted snapshot, with that key protected by a non-exportable Android Keystore AES-GCM wrapping key; snapshot-key reuse is prohibited. These local-secret controls remain an M3 exit requirement until #34 lands and is verified.

## Threats not fully solved

Kenato does not claim to provide:

- anonymity against a global network observer;
- protection from a fully compromised or unlocked device;
- protection from malicious recipients who intentionally record or disclose a conversation;
- guaranteed concealment of communication timing or traffic volume;
- recipient-specific confidentiality of an invite URI before it is redeemed;
- protection from denial of service by a malicious/compromised Kenato server;
- distributed/source-aware public-edge anti-DoS protection from the loopback service alone;
- server-side replay recovery after a successful creator claim whose response is lost before local commit;
- proof that a malicious/compromised client generated fresh OTK private material merely because it used a fresh public bookkeeping id;
- completed ratchet-state secrecy/crash-safety until the M3 Android/native vodozemac slice is implemented and verified;
- guaranteed recovery of identity/history after device loss when no secure backup exists.

These limitations must not be obscured in marketing.

## Security review triggers

A dedicated security review is required for changes to:

- cryptographic protocol or primitives;
- identity/session-account lifecycle;
- invite/session bootstrap handshake;
- authentication;
- wire protocol;
- persistence of secrets or ratchet state;
- server retention of identity/contact/session metadata;
- native/JNI cryptographic boundaries;
- call key establishment;
- WebRTC security assumptions;
- push payload content;
- logging/telemetry;
- backup behavior;
- dependency or CI supply-chain policy;
- GitHub Actions permissions/triggers;
- release-tag, signing, provenance, or artifact-publication behavior.

## Pre-1.0 exit criteria

Before the first stable public release:

- threat model updated to match implementation;
- protocol test vectors checked;
- malformed/replayed/reordered input tests exist for protocol layers that implement those semantics;
- invite/session lifecycle and abuse limits validated;
- M3 native crypto persistence and replay/reordering bounds validated before M3 completion;
- mailbox and TURN abuse limits validated in their milestones;
- dependency and supply-chain review completed;
- default-branch, release-tag, and CodeQL rulesets verified active;
- release signing identity/provenance controls verified;
- Android backup and logging behavior reviewed;
- repository-wide security audit completed;
- no open Critical or High severity security findings.
