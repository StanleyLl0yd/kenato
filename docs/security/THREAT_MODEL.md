# Kenato Threat Model

Status: M0-M2 complete. M3 E2EE session protocol/server and Android/native implementation are present in PR #40 and are in final exact-head verification; M3 is not complete until #34 is merged and the repository-wide #35 audit/verification succeeds on exact `main`.

This document describes what Kenato intends to protect, what the system trusts, and what it does not claim to solve.

## Assets

Primary assets:

- private identity keys;
- private prekey material;
- Olm account/session and ratchet keys;
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
- mailbox state in later messaging milestones.

## Trust boundaries

### Mobile device

Trusted to protect application secrets while the operating system and application sandbox remain uncompromised.

Kenato cannot protect plaintext from a fully compromised device or OS.

M1 generates the long-lived identity signing key inside Android Keystore. Its private key is non-exportable. Prekey private keys are generated in process memory and persisted only after AES-256-GCM wrapping with a separate non-exportable Android Keystore key. Hardware backing is used when the device provides it but is not assumed by the security model.

Loss, corruption, or mismatch of the M1 persisted identity record and required Keystore entries fails closed. Kenato does not silently create a replacement identity in that condition; replacement requires an explicit destructive recovery action.

M2 adds local contact identity pins. A newly established peer binding is accepted only after the peer public identity bundle and invite/redemption proof have been cryptographically verified. An existing pin is never silently replaced.

Pending M2 invite bearer secrets and contact pins are app-private and excluded from Android cloud backup and device-to-device transfer under the repository's all-domain backup policy.

M3 keeps the M1/M2 P-256 identity as the sole contact trust anchor. Vodozemac Olm account identity keys and public one-time keys are separate session-engine material and are accepted only after P-256 binding verification. Persisted sessions bind the exact peer M3 account generation and Ed25519/Curve25519 account identity keys. Returned creator generation and OTK id/public bytes must exactly match local creator account state before an inbound session is committed.

M3 Olm account/session snapshots are app-private and backup/device-transfer excluded. Every encrypted native snapshot uses a fresh random 32-byte pickle key; the pickle key is wrapped with a non-exportable Android Keystore AES-GCM key using context-specific AAD. Missing/mismatched Keystore or persisted M3 state fails closed and requires explicit recovery rather than silent Olm-account regeneration.

Ratchet-state durability is part of the cryptographic boundary: outbound ciphertext and inbound plaintext are not returned until the advanced session state is durably committed. Inbound-session creation commits consumed local OTK bookkeeping and the new session together in one atomic M3 state write before returning the authenticated control plaintext.

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

Successful creator claim deletes the invite relationship row and cascades deletion of temporary M3 reservation/init state in the same SQLite transaction that retrieves the bounded claim result. Unclaimed expired rows are removed by explicit retention cleanup at server startup and on an hourly schedule; M3 temporary rows reference the invite/reservation rows with cascading foreign keys.

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

The M3 native boundary is exact-pinned to vodozemac 0.10.0, Rust 1.85.0, Android NDK 28.2.13676358, cargo-ndk 4.1.2, API 26, and the reviewed `armeabi-v7a`/`arm64-v8a`/`x86_64` ABI set. Both native crates have committed lockfiles. CI/release paths build and validate the native libraries before Gradle packaging, and repository security policy checks the same pin/ABI contract for drift.

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
- Semgrep, Gitleaks, Dependency Review, govulncheck, Android lint, Qodana, CodeQL and Rust checks according to stack support;
- exact native dependency/toolchain/NDK/cargo-ndk pins and committed Cargo locks;
- three-ABI native build/packaging verification before Android build/release;
- release signing secrets isolated in the `release` environment;
- independent expected certificate fingerprint verification;
- release source must be a successfully verified `main` commit;
- release checksums and OIDC-backed artifact attestations.

### Network interception

A network observer may capture or modify traffic.

Mitigations implemented through M3:

- TLS for client-server transport at the reviewed deployment boundary;
- identity-key signatures over M2 publication/invite/redemption/claim canonical payloads;
- P-256 identity signatures over M3 session-account bindings, reservation intent, initial-frame submission, and creator claim;
- explicit protocol-version, generation, identity, invite-token and one-time-key bindings;
- explicit replay/idempotency handling for bootstrap operations;
- authenticated vodozemac Olm/Double Ratchet encryption/decryption at the M3 client session primitive;
- local durable ratchet advancement before application-visible ciphertext/plaintext is returned.

TLS protects invite bearer secrets in transit from passive/active network attackers. Client-verifiable signatures make token-to-identity, redemption-to-identity, session-account-to-identity and initial-frame bindings independently verifiable. The M3 local crypto primitive provides authenticated ratcheted payload protection once a session is established. Ordinary encrypted-message routing/mailbox transport is not implemented until M4 and is not claimed by M3.

### Malicious or compromised server

An attacker obtains server storage, process access, or operator privileges.

Mitigations:

- no private identity, prekey, Olm account, one-time-key, session or ratchet keys on the server;
- no plaintext messages or voice on the server;
- server stores invite-token hashes rather than raw tokens at rest;
- M2 invite descriptor is signed by the creator identity key;
- redeemer intent is signed over creator identity id, redeemer identity id, and invite token;
- clients derive identity ids from exact public-key bytes and validate publication/signed-prekey signatures before pinning;
- M3 public Olm account identity keys and OTK set are covered by the existing P-256 trust anchor;
- M3 reservation and submit proofs bind the exact invite participants, creator generation/OTK allocation, redeemer generation and SHA-256 of the opaque initial frame;
- creator claim returns enough authenticated fields for the correct client to independently re-verify the stored submit proof instead of trusting server assertions;
- responder additionally checks the exact creator account generation and OTK id/public bytes against local state and checks the decrypted canonical control payload;
- M2 and M3 publication revisions/generations are monotonic and signed;
- no public identity/session enumeration endpoint;
- successful claims delete temporary relationship/bootstrap records and expired invite state is removed by bounded retention cleanup;
- minimum durable metadata;
- secrets isolated from logs;
- contact/session identity verification performed by clients.

A malicious server can deny service, suppress a redemption/bootstrap, exhaust or withhold public one-time keys, retain metadata outside Kenato's intended implementation policy, or replay stale-but-valid public material within accepted protocol rules. It must not be able to make a correct client silently pin a different Kenato identity or M3 engine identity, substitute a different local creator OTK, or alter/transplant the authenticated initial frame without a signature/hash/pin/provenance/control verification failure, assuming SHA-256, ECDSA P-256 and the selected Olm primitives remain secure and peer private identity/session material is uncompromised.

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
- the initiator persists the exact pre-key frame before submit and reuses it after failed submit/restart rather than generating a second session;
- malformed/expired/redeemed/wrong-identity requests fail without disclosing unrelated identities;
- a process-wide bounded pre-crypto concurrency/rate gate runs before expensive service verification;
- per-identity active-invite quotas and global retained-state caps bound persistent abuse.

Anyone who obtains an unused invite URI before its intended recipient redeems it can attempt redemption. Invite secrecy is therefore a bearer-capability assumption until first use or expiry; Kenato does not claim recipient-specific confidentiality for a shared invite before redemption.

M2/M3 creator claim is intentionally destructive on the server: a successful claim removes the temporary relationship/bootstrap rows rather than retaining a replay cache. If the successful claim response is lost before the creator durably commits local contact/session state, the peers must establish a fresh invite rather than recovering the consumed claim from the server. This trades retry availability for lower relationship-metadata retention and does not permit silent identity substitution.

After a successful destructive M3 claim response, the client suppresses cancellation through verification/local commit. The authenticated M2 pin is committed first and atomic M3 inbound state second. An M2 commit failure leaves M3 state/OTK untouched. An M3 commit failure can leave the valid M2 pin but does not persist an M3 session or consume the local OTK; recovery requires a fresh invite. M3-first ordering is prohibited because it could create a durable session without the M2 trust anchor.

The server prevents reuse of a consumed OTK id within an account generation, but it does not retain an unbounded historical set of every old OTK public-key byte string. Correct clients generate genuinely fresh vodozemac OTKs and monotonically increasing bookkeeping ids when replenishing a generation. Reusing old private/public OTK material under a fresh id is a client compromise/bug and is prohibited by the M3 client implementation contract. Local active-key alias detection compares exact key bytes.

### Message tampering, replay, and reordering

An attacker reorders, duplicates, modifies, or replays encrypted protocol messages.

M3 authenticates the initial opaque pre-key frame with the redeemer's P-256 submit proof and binds it to the exact invite/session context. The responder also verifies the expected peer Curve25519 identity and the decrypted canonical control payload before accepting the inbound session.

For established sessions, Kenato delegates authenticated Olm/Double Ratchet message processing, replay behavior, out-of-order skipped-key handling, and maximum message-gap behavior to exact-pinned vodozemac 0.10.0. Kenato does not expose a caller override that raises the engine's fixed skipped-key/message-gap limits. The native engine tests exercise replay/reordering and boundary behavior, while Kotlin persistence tests ensure a failed local commit does not release the newly produced ciphertext/plaintext.

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
- M3 sessions persist the exact peer account generation and engine identity-key bytes used for bootstrap;
- creator response handling requires the exact returned local generation/OTK id/public bytes to match current local state;
- existing M2 identity pins cannot be silently replaced;
- persisted M3 state/Keystore mismatch fails closed instead of silently replacing engine identity material;
- unexpected identity/account change requires explicit recovery rather than automatic trust.

M1 rejects local identity-state/Keystore mismatches rather than silently rotating the local identity. M3 applies the same fail-closed principle to its Olm account and sessions.

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

Malformed or excessive requests attempt to exhaust memory, CPU, storage, signature verification, SQLite locks, native/JNI allocations, prekeys, later WebSocket/mailbox capacity, or TURN allocations.

Mitigations through M3:

- 64 KiB M2 contact request/response limits and 128 KiB M3 bootstrap request/response limits;
- 64 KiB M3 application plaintext bound;
- 96 KiB M3 Olm-frame bound;
- bounded parser fields and repeated-key counts;
- M3 public Olm keys fixed at 32 bytes;
- one shared maximum of 50 tracked/published M3 OTKs and a normal target of 32;
- at most 256 persisted Android M3 sessions;
- bounded serialized account/session snapshots, wrapped-key envelopes, session ids and JNI byte arrays;
- vodozemac's fixed skipped-key/message-gap limits remain unchanged;
- strict public-key/signature/token sizes before cryptographic parsing;
- process-wide pre-crypto concurrency and operation-window limits;
- active invite quotas, global identity/invite/session-bootstrap caps, exact expiry checks and periodic expired-invite cleanup;
- atomic single-OTK allocation and explicit exhaustion failure;
- SQLite busy timeout, bounded transactions, indexes and serialized writes;
- HTTP header/body and operation timeouts;
- cancellation propagation before destructive/network boundaries and explicit cancellation suppression where a post-success durable commit is mandatory.

The M1 persisted identity record has an explicit maximum serialized size and one-time prekey pool. M2 preserves those bounds for published prekey collections and Android contact state. M3 server bootstrap state is separately bounded and temporary reservation/init rows are tied to the bounded invite lifecycle. Later milestones must additionally bound WebSocket connections/queues, mailbox quotas/retention and TURN allocations/credential lifetimes.

### Local data leakage

Backups, logs, crash reports, screenshots, or local storage may expose sensitive information.

Mitigations:

- long-lived identity and prekey-wrapping keys in Android Keystore;
- prekey private material persisted only as AES-256-GCM authenticated ciphertext bound to its kind, id, and public key;
- M2 contact pins and pending invite secrets remain app-private and are covered by the existing all-domain backup/device-transfer denial;
- M3 account/session state is app-private and covered by the same backup/device-transfer denial;
- every M3 native account/session snapshot uses a fresh random 32-byte pickle key, protected by a non-exportable Android Keystore AES-GCM wrapping key with context AAD;
- cloud backup and Android device-to-device transfer are denied by manifest policy plus explicit all-domain rules for both legacy and Android 12+ backup formats;
- cross-platform transfer is not configured; it requires a separate reviewed iOS app identity and transfer contract before use;
- backup policy is enforced by repository checks and Android build/lint validation;
- no raw invite tokens, private keys, pickle keys, secret-bearing signatures, Olm ciphertext, complete public bundles, or plaintext user content are intentionally written to logs;
- secret-bearing state is not placed in UI state or `SavedStateHandle`;
- minimum telemetry;
- UI screenshot restrictions are considered only where they improve privacy without harming normal UX.

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
- ordinary encrypted-message routing, offline delivery, acknowledgements, conversation history, or other M4 product messaging behavior;
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
- M3 native crypto persistence, substitution, replay/reordering and native-boundary behavior pass M3's final repository-wide audit/verification;
- mailbox and TURN abuse limits validated in their milestones;
- dependency and supply-chain review completed;
- default-branch, release-tag, and CodeQL rulesets verified active;
- release signing identity/provenance controls verified;
- Android backup and logging behavior reviewed;
- repository-wide security audit completed;
- no open Critical or High severity security findings.
