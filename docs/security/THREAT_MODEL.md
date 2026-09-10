# Kenato Threat Model

Status: M2 Invite + Contact Establishment in progress. This model is authoritative for the implemented M0/M1 foundation and the accepted M2 contact-establishment design as implementation lands.

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
- temporary invite/redemption relationship metadata;
- mailbox state.

## Trust boundaries

### Mobile device

Trusted to protect application secrets while the operating system and application sandbox remain uncompromised.

Kenato cannot protect plaintext from a fully compromised device or OS.

M1 generates the long-lived identity signing key inside Android Keystore. Its private key is non-exportable. Prekey private keys are generated in process memory and immediately persisted only after AES-256-GCM wrapping with a separate non-exportable Android Keystore key. Hardware backing is used when the device provides it but is not assumed by the security model.

Loss, corruption, or mismatch of the M1 persisted identity record and required Keystore entries fails closed. Kenato does not silently create a replacement identity in that condition; replacement requires an explicit destructive recovery action.

M2 adds local contact identity pins. A newly established peer binding is accepted only after the peer public identity bundle and invite/redemption proof have been cryptographically verified. An existing pin is never silently replaced.

### Kenato server

The server is not trusted with user content or private identity/prekey material.

It may process:

- public identity material;
- public prekeys and their signatures;
- monotonically accepted publication revisions;
- invite token bytes transiently while handling a bounded request;
- SHA-256 invite-token hashes at rest;
- invite creation/expiry/redemption state;
- temporary creator/redeemer identity-id relationship metadata until claim/expiry;
- routing identifiers;
- opaque encrypted payloads in later messaging milestones;
- bounded operational state needed to deliver traffic.

Compromise of the server must not reveal message or voice plaintext or any device private key.

M2 deliberately exposes no public identity search/lookup endpoint. A creator bundle is disclosed only to a requester presenting a valid unexpired invite token; a redeemer bundle is disclosed only to the authenticated creator presenting the same token.

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

Mitigations:

- TLS for client-server transport;
- identity-key signatures over M2 publication/invite/redemption/claim canonical payloads;
- authenticated end-to-end encryption for user payloads in later milestones;
- authenticated call signaling;
- explicit replay handling.

TLS protects invite bearer secrets in transit from passive/active network attackers, while M2 identity signatures make token-to-identity and redemption-to-identity bindings independently verifiable by the clients.

### Malicious or compromised server

An attacker obtains server storage, process access, or operator privileges.

Mitigations:

- no private identity or prekey keys on the server;
- no plaintext messages or voice on the server;
- server stores invite-token hashes rather than raw tokens at rest;
- M2 invite descriptor is signed by the creator identity key;
- redeemer intent is signed over creator identity id, redeemer identity id, and invite token;
- clients derive identity ids from exact public-key bytes and validate publication/signed-prekey signatures before pinning;
- publication revisions are monotonic and signed;
- no public identity enumeration endpoint;
- completed/expired invite state is short-lived and removed by retention cleanup;
- minimum durable metadata;
- secrets isolated from logs;
- contact identity verification performed by clients.

A malicious server can deny service, suppress a redemption, or return stale-but-valid public material within protocol limits. It must not be able to make a client silently pin a different identity without a signature/hash verification failure, assuming SHA-256 and ECDSA P-256 remain secure and the peer private identity key is uncompromised.

### Invite theft, replay, and substitution

An attacker obtains or guesses an invite, replays a creation/redemption request, attempts to reuse a consumed token, substitutes another creator identity, or tries to claim the redeemer result without creator authorization.

Mitigations:

- 32-byte cryptographically random invite tokens;
- fixed 24-hour server expiry;
- single-use redemption state transition performed atomically;
- SHA-256 hash-at-rest token storage;
- creator signature binds creator identity id to the exact token and travels in the QR/deep link;
- redeemer signature binds both identity ids to the exact token;
- creator claim requires both token possession and a valid creator identity signature;
- exact duplicate/idempotency behavior is explicit;
- malformed/expired/redeemed/wrong-identity requests fail without disclosing unrelated identities;
- pre-authentication and authenticated rate/resource limits.

Anyone who obtains an unused invite URI before its intended recipient redeems it can attempt redemption. Invite secrecy is therefore a bearer-capability assumption until first use or expiry; Kenato does not claim recipient-specific confidentiality for a shared invite before redemption.

### Message tampering and replay

An attacker reorders, duplicates, modifies, or replays encrypted protocol messages.

Mitigations in later session/messaging milestones:

- authenticated encryption;
- ratchet/session state;
- message identifiers/counters;
- bounded skipped-message handling;
- explicit replay tests.

M2 does not yet implement encrypted-message session state and must not claim those later protections as implemented.

### Identity substitution

A server or attacker attempts to replace a contact's identity key.

Mitigations:

- identity id is the full SHA-256 digest of exact X.509 SubjectPublicKeyInfo identity-public-key bytes;
- public identity publication is signed by the corresponding long-lived identity key;
- the current signed prekey is independently signed by that identity key;
- creator invite and redeemer proof signatures bind the contact-establishment event to those identity ids;
- identity binding is stored locally after verification;
- an existing contact pin cannot be silently replaced;
- unexpected identity change must become an explicit user-visible recovery decision rather than automatic trust.

M1 also rejects local identity-state/Keystore mismatches rather than silently rotating the local identity.

### User enumeration and spam

An attacker tries to discover users or flood them.

Mitigations:

- no public user search or identity lookup;
- invite-only discovery;
- single-use/expiring invites;
- active-invite quotas;
- pre-authentication source limits before expensive verification;
- authenticated per-identity rate limits after verification;
- request-body, field, collection, and database-retention bounds;
- indistinguishable/not-overly-informative failure responses where identity existence would otherwise be exposed.

### Resource exhaustion

Malformed or excessive requests attempt to exhaust memory, CPU, storage, signature verification, SQLite locks, WebSocket slots, prekeys, mailbox capacity, or TURN allocations.

Mitigations:

- request and envelope size limits;
- bounded parser fields/repeated counts;
- strict public-key/signature/token sizes before cryptographic parsing;
- bounded queues and connection lifetimes;
- invite quotas and expiry cleanup;
- pre-authentication IP/source limits before expensive signature work;
- authenticated identity limits after verification;
- SQLite busy timeout, bounded transactions, indexes, and retention cleanup;
- mailbox quotas in M4;
- short-lived TURN credentials in voice milestones;
- cancellation and request timeouts.

The M1 persisted identity record has an explicit maximum serialized size and the one-time prekey pool is hard-bounded. M2 preserves that bound for published prekey collections.

### Local data leakage

Backups, logs, crash reports, screenshots, or local storage may expose sensitive information.

Mitigations:

- long-lived identity and prekey-wrapping keys in Android Keystore;
- prekey private material persisted only as AES-256-GCM authenticated ciphertext bound to its kind, id, and public key;
- M2 contact pins and pending invite secrets remain app-private and are covered by the existing all-domain backup/device-transfer denial;
- cloud backup and Android device-to-device transfer are denied by manifest policy plus explicit all-domain rules for both legacy and Android 12+ backup formats;
- cross-platform transfer is not configured; it requires a separate reviewed iOS app identity and transfer contract before use;
- backup policy is enforced by repository checks and Android build/lint validation;
- no raw invite tokens, private keys, signatures over secret-bearing payloads, or plaintext user content in logs;
- minimum telemetry;
- UI screenshot restrictions considered only where they improve privacy without harming normal UX.

## Threats not fully solved

Kenato does not claim to provide:

- anonymity against a global network observer;
- protection from a fully compromised or unlocked device;
- protection from malicious recipients who intentionally record or disclose a conversation;
- guaranteed concealment of communication timing or traffic volume;
- recipient-specific confidentiality of an invite URI before it is redeemed;
- protection from denial of service by a malicious/compromised Kenato server;
- guaranteed recovery of identity/history after device loss when no secure backup exists.

These limitations must not be obscured in marketing.

## Security review triggers

A dedicated security review is required for changes to:

- cryptographic protocol or primitives;
- identity lifecycle;
- invite handshake;
- authentication;
- wire protocol;
- persistence of secrets;
- server retention of identity/contact metadata;
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
- malformed/replayed/reordered input tests exist;
- invite lifecycle and abuse limits validated;
- mailbox and TURN abuse limits validated in their milestones;
- dependency and supply-chain review completed;
- default-branch, release-tag, and CodeQL rulesets verified active;
- release signing identity/provenance controls verified;
- Android backup and logging behavior reviewed;
- repository-wide security audit completed;
- no open Critical or High severity security findings.
