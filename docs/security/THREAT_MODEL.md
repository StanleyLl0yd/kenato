# Kenato Threat Model

Status: M0–M3 complete. M4 is active under tracker #49; #50 protocol/authentication and #51 bounded mailbox are complete, #52 authenticated WSS/direct routing is active, and #53 Android history plus #54 final M4 verification remain.

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
- M4 connection, delivery and bounded mailbox state.

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

Ratchet-state durability is part of the cryptographic boundary: outbound ciphertext and inbound plaintext are not returned until the advanced session state is durably committed. Inbound-session creation commits consumed local OTK bookkeeping and the new session together in one atomic M3 state write before returning the authenticated control plaintext. Android AtomicFile reads perform backup recovery before validating recovered base-file size, preserving crash-recovery semantics without weakening state-size bounds.

The Rust/JNI bridge treats controllable native copies of pickle keys and application/control plaintext as short-lived secrets. Java-to-Rust plaintext copies and engine-produced inbound/decrypted plaintext are held in zeroizing RAII buffers, including error paths, and the encoded native response buffer is zeroized after the JVM copy is attempted. This reduces avoidable native-heap remanence; it does not claim synchronous erasure of managed JVM copies outside native buffer control.

M4 adds a second durability boundary after successful M3 decrypt: a client must not ACK merely because plaintext existed transiently. Because M3 has already durably advanced the ratchet before returning plaintext, #53 must establish a crash-safe durable delivery handoff/history record before network ACK so a process crash cannot lose the only recoverable plaintext while a redelivered ciphertext is correctly rejected as replay.

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
- M4 sender/recipient routing identity ids, random message ids, expiry, opaque ciphertext, authenticated connection timing and bounded direct-delivery/mailbox bookkeeping;
- bounded operational state needed to deliver traffic.

Compromise of the server must not reveal message or voice plaintext or any device private key.

M2/M3 expose no public identity or session-bootstrap search/lookup endpoint. Creator public material is disclosed through invite-authorized flows; redeemer material and the initial session frame are disclosed only to the authenticated creator of that invite. M4 connection authentication resolves an already-published identity internally and uses the same coarse authentication-failure class for unknown identities and invalid proofs rather than exposing a new lookup endpoint. M4 also exposes no public mailbox or presence lookup.

Successful creator claim deletes the invite relationship row and cascades deletion of temporary M3 reservation/init state in the same SQLite transaction that retrieves the bounded claim result. Unclaimed expired rows are removed by explicit retention cleanup at server startup and on an hourly schedule; M3 temporary rows reference the invite/reservation rows with cascading foreign keys. Session-init insertion is also transaction-guarded against a concurrent redeemer account rollover so a stale `redeemer_account_generation` cannot commit after the earlier service-layer validation.

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

The completed post-M3 native boundary is exact-pinned to vodozemac 0.10.0, Rust 1.85.0, Android NDK 28.2.13676358, cargo-ndk 4.1.2, API 26, and the reviewed `armeabi-v7a`/`arm64-v8a`/`x86_64` ABI set. The engine's direct `rand` dependency is pinned to reviewed fixed `=0.8.6`. Both native crates have committed lockfiles, Cargo Dependabot coverage, and pinned cargo-audit scanning. CI/release paths build and validate the native libraries before Gradle packaging, and repository security policy checks the same pin/ABI contract for drift. The post-M3 verification baseline includes protolint, repository-wide `make test`, and CodeQL coverage for Go, Java/Kotlin, Rust, and GitHub Actions. Dependency Review enforces both vulnerability policy and an explicit strong-copyleft AGPL/GPL deny policy so ADR 0006's pre-1.0 licensing decision cannot be silently constrained by a dependency update. M4 adds dedicated protocol, mailbox and transport policy verifiers to keep schema, Go/Kotlin bounds, canonical auth framing, storage/routing constraints, security reviews, and authoritative protocol/architecture documentation synchronized.

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
- Semgrep, Gitleaks, Dependency Review vulnerability/license policy, govulncheck, cargo-audit, protolint, Android lint, Qodana, repository-wide `make test`, and CodeQL for Go/Java-Kotlin/Rust/Actions;
- exact native dependency/toolchain/NDK/cargo-ndk pins and committed Cargo locks;
- Cargo Dependabot coverage for both native crates;
- three-ABI native build/packaging verification before Android build/release;
- release signing secrets isolated in the `release` environment;
- independent expected certificate fingerprint verification;
- release source must be a successfully verified `main` commit;
- release checksums and OIDC-backed artifact attestations.

### Network interception

A network observer may capture or modify traffic.

Mitigations implemented through completed M3 and the active M4 implementation through #52:

- TLS for client-server transport at the reviewed deployment boundary;
- identity-key signatures over M2 publication/invite/redemption/claim canonical payloads;
- P-256 identity signatures over M3 session-account bindings, reservation intent, initial-frame submission, and creator claim;
- explicit protocol-version, generation, identity, invite-token and one-time-key bindings;
- explicit replay/idempotency handling for bootstrap operations;
- authenticated vodozemac Olm/Double Ratchet encryption/decryption at the M3 client session primitive;
- local durable ratchet advancement before application-visible ciphertext/plaintext is returned;
- M4 WSS authentication using a 32-byte random, single-use, connection-scoped challenge with at most 30 seconds lifetime and a 10-second authentication deadline, signed by the existing Kenato P-256 identity;
- binary-only M4 application frames with WebSocket compression disabled and a 100 KiB read limit;
- M4 outer sender/recipient/message-id/expiry routing fields duplicated inside M3 authenticated plaintext and compared after decrypt;
- message semantic type/text remaining inside M3 ciphertext.

TLS protects invite bearer secrets and WSS transport from passive/active network attackers at the deployment boundary. Client-verifiable signatures make token-to-identity, redemption-to-identity, session-account-to-identity, initial-frame, and M4 connection-identity bindings independently verifiable. The M3 local crypto primitive provides authenticated ratcheted payload protection once a session is established. M4 does not treat its challenge proof as a TLS replacement.

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
- session-init persistence atomically revalidates the redeemer's current account generation inside SQLite, closing the validation/rollover TOCTOU;
- creator claim returns enough authenticated fields for the correct client to independently re-verify the stored submit proof instead of trusting server assertions;
- responder additionally checks the exact creator account generation and OTK id/public bytes against local state and checks the decrypted canonical control payload;
- M2 and M3 publication revisions/generations are monotonic and signed;
- M4 WSS identity requires proof of possession of the existing P-256 key; an identity id alone is never a credential;
- failed same-identity authentication cannot evict the current authenticated connection; replacement occurs only after the new proof succeeds;
- M4 receivers verify authenticated inner sender/recipient/message-id/expiry against the outer routing envelope before delivery or ACK;
- M4 `SendAccepted` intentionally omits online/offline/delivery-mode state;
- no public identity/session/mailbox/presence enumeration endpoint;
- successful claims delete temporary relationship/bootstrap records and expired invite/mailbox state is removed by bounded retention cleanup;
- minimum durable metadata;
- secrets isolated from logs;
- contact/session identity verification performed by clients.

A malicious server can deny service, suppress a redemption, bootstrap, or message, and exhaust or withhold the public one-time-key inventory. It can also delay, reorder, or duplicate encrypted traffic; report send acceptance dishonestly; retain metadata or ciphertext outside Kenato's intended retention policy; or replay stale-but-valid public material within accepted protocol rules. It must not be able to make a correct client silently pin a different Kenato identity or M3 engine identity, substitute a different local creator OTK, commit a stale redeemer generation after rollover, alter/transplant the authenticated initial frame, or relabel an M4 message's sender/recipient/message-id/expiry without a signature/hash/pin/provenance/transaction/M3/context verification failure, assuming SHA-256, ECDSA P-256 and the selected Olm primitives remain secure and peer private identity/session material is uncompromised.

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

An attacker reorders, duplicates, modifies, relabels, or replays encrypted protocol messages.

M3 authenticates the initial opaque pre-key frame with the redeemer's P-256 submit proof and binds it to the exact invite/session context. The responder also verifies the expected peer Curve25519 identity and the decrypted canonical control payload before accepting the inbound session.

For established sessions, Kenato delegates authenticated Olm/Double Ratchet message processing, replay behavior, out-of-order skipped-key handling, and maximum message-gap behavior to exact-pinned vodozemac 0.10.0. Kenato does not expose a caller override that raises the engine's fixed skipped-key/message-gap limits. The native engine tests exercise replay/reordering and boundary behavior, while Kotlin persistence tests ensure a failed local commit does not release the newly produced ciphertext/plaintext.

M4 transport is intentionally at-least-once until authenticated ACK. A sender generates a fresh 16-byte non-zero random message id. Sender, recipient, message id and expiry are duplicated inside the encrypted M4 plaintext and must match the outer `Envelope` after M3 decrypt. A mismatch fails closed before application-visible delivery or ACK. Duplicate/reconnect delivery is expected and recipients deduplicate by authenticated sender/message id after validating the encrypted context. Reordering remains permitted; correctness cannot depend on exactly-once transport or global arrival order.

An ACK names sender identity id and message id, while recipient identity comes only from authenticated WSS connection state. A valid ACK may delete only that recipient's exact retained message. Cross-recipient or mismatched ACK deletion is prohibited. The Android implementation must durably preserve the successful delivery handoff/history before ACK because the M3 ratchet has already advanced.

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
- M4 WSS authentication uses the same P-256 identity key and domain-separated canonical challenge framing;
- unexpected identity/account change requires explicit recovery rather than automatic trust.

M1 rejects local identity-state/Keystore mismatches rather than silently rotating the local identity. M3 applies the same fail-closed principle to its Olm account and sessions. M4 does not introduce an independent transport identity.

### User enumeration and spam

An attacker tries to discover users, probe presence, or flood them.

Mitigations:

- no public user/session search or identity/session bootstrap lookup;
- invite-only discovery and M3 bootstrap authorization through an already redeemed invite;
- single-use/expiring invites;
- active-invite quotas;
- bounded total retained identity/invite/session-bootstrap state;
- process-wide concurrency/rate limits before expensive cryptographic verification;
- request-body, field and collection limits;
- missing-identity failures at public HTTP boundaries use the same generic invalid-request category as malformed/unauthenticated requests rather than exposing a dedicated identity-existence response;
- M4 unknown-identity and invalid-signature WSS authentication failures use the same coarse authentication result;
- failed authentication cannot displace an already authenticated same-identity socket;
- M4 send errors are coarse and must not distinguish unknown recipient, offline recipient, detailed quota state or mailbox contents;
- `MessagingSendAccepted` does not reveal whether direct delivery or durable mailbox custody was selected.

The in-process rate gate is deliberately a coarse resource bound, not a full public-edge anti-abuse system. Source-aware/distributed rate limiting must be designed together with the reviewed TLS/reverse-proxy deployment boundary rather than trusting arbitrary forwarded-address headers inside the loopback service. M4 does not claim to hide all timing-based presence hints from an already established correspondent; it avoids creating an explicit protocol presence oracle.

### Resource exhaustion

Malformed or excessive requests attempt to exhaust memory, CPU, storage, signature verification, SQLite locks, native/JNI allocations, prekeys, WebSocket/mailbox capacity, or TURN allocations.

Mitigations through completed M3 and the current M4 implementation through #52:

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
- cancellation propagation before destructive/network boundaries and explicit cancellation suppression where a post-success durable commit is mandatory;
- M4 text at most 16 KiB, ciphertext at most 64 KiB, encoded envelope at most 96 KiB and WSS frame at most 100 KiB;
- M4 message lifetime at most 72 hours and auth challenge lifetime at most 30 seconds;
- M4 mailbox at most 500 messages / 16 MiB per recipient, 1,000 / 32 MiB per sender, and 100,000 / 256 MiB globally;
- M4 retained delivery pages at most 50 and physical cleanup batches at most 1,000 rows;
- M4 active authenticated registry at most 128 peers and unauthenticated handshakes at most 32;
- M4 per-peer outbound queue at most 4 frames and concurrent sends at most 4;
- M4 global send workers at most 128 and pending direct deliveries at most 256;
- M4 authentication deadline 10 seconds and direct ACK/write/mailbox-operation bounds 5 seconds.

The M1 persisted identity record has an explicit maximum serialized size and one-time prekey pool. M2 preserves those bounds for published prekey collections and Android contact state. M3 server bootstrap state is separately bounded and temporary reservation/init rows are tied to the bounded invite lifecycle. #51 bounds retained row/byte storage and cleanup; #52 bounds WebSocket authentication, connection ownership, direct-delivery queues/workers and retry timers. #53 must similarly bound local history, pending delivery-handoff state, reconnect/backoff and client-side queues before M4 can close. TURN allocation/credential-lifetime bounds remain a later milestone.

### Local data leakage

Backups, logs, crash reports, screenshots, or local storage may expose sensitive information.

Mitigations:

- long-lived identity and prekey-wrapping keys in Android Keystore;
- prekey private material persisted only as AES-256-GCM authenticated ciphertext bound to its kind, id, and public key;
- M2 contact pins and pending invite secrets remain app-private and are covered by the existing all-domain backup/device-transfer denial;
- M3 account/session state is app-private and covered by the same backup/device-transfer denial;
- every M3 native account/session snapshot uses a fresh random 32-byte pickle key, protected by a non-exportable Android Keystore AES-GCM wrapping key with context AAD;
- temporary native JNI copies of pickle keys and application/control/decrypted plaintext are stored in zeroizing buffers and erased when those buffers leave scope, including native error paths where the backing buffer is under Kenato's control;
- M4 ordinary text remains inside M3 ciphertext on the network/server boundary;
- M4 local delivery/history state must remain app-private and backup/device-transfer policy must be reviewed in #53/#54 before the milestone closes;
- cloud backup and Android device-to-device transfer are denied by manifest policy plus explicit all-domain rules for both legacy and Android 12+ backup formats;
- cross-platform transfer is not configured; it requires a separate reviewed iOS app identity and transfer contract before use;
- backup policy is enforced by repository checks and Android build/lint validation;
- no raw invite tokens, private keys, pickle keys, secret-bearing signatures, Olm ciphertext, M4 ciphertext bodies, complete public bundles, or plaintext user content are intentionally written to logs;
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
- protection against a malicious server retaining M4 ciphertext/metadata longer than the implementation's intended retention policy;
- full M4 product messaging behavior yet: #50 protocol/auth and #51 bounded mailbox are complete, #52 authenticated WSS/direct routing is active, and Android conversation history/durable handoff plus final end-to-end verification remain #53–#54;
- guaranteed recovery of identity/history after device loss when no secure backup exists.

These limitations must not be obscured in marketing.

## Security review triggers

A dedicated security review is required for changes to:

- cryptographic protocol or primitives;
- identity/session-account lifecycle;
- invite/session bootstrap handshake;
- authentication;
- wire protocol;
- WebSocket authentication/routing, queues, retry or mailbox semantics;
- persistence of secrets, ratchet state, delivery handoff, message history or server mailbox data;
- server retention of identity/contact/session/message metadata;
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
- completed M3 native crypto persistence, substitution, replay/reordering, JNI-boundary, and final repository-wide verification remain green as a regression baseline;
- mailbox and TURN abuse limits validated in their milestones;
- dependency and supply-chain review completed, including explicit dependency-license policy;
- default-branch, release-tag, and CodeQL rulesets verified active;
- release signing identity/provenance controls verified;
- Android backup and logging behavior reviewed;
- repository-wide security audit completed;
- no open Critical or High severity security findings.
