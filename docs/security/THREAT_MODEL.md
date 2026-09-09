# Kenato Threat Model

Status: M0 architecture baseline. M0 is complete; this model remains authoritative until implementation changes require an update.

This document describes what Kenato intends to protect, what the system trusts, and what it does not claim to solve.

## Assets

Primary assets:

- private identity keys;
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
- mailbox state.

## Trust boundaries

### Mobile device

Trusted to protect application secrets while the operating system and application sandbox remain uncompromised.

Kenato cannot protect plaintext from a fully compromised device or OS.

### Kenato server

The server is not trusted with user content.

It may process:

- public identity material;
- prekeys;
- invite state;
- routing identifiers;
- opaque encrypted payloads;
- operational state needed to deliver traffic.

Compromise of the server must not reveal message or voice plaintext.

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
- authenticated end-to-end encryption for user payloads;
- authenticated call signaling;
- replay protection.

### Malicious or compromised server

An attacker obtains server storage, process access, or operator privileges.

Mitigations:

- no private identity keys on the server;
- no plaintext messages or voice on the server;
- short mailbox retention;
- minimum durable metadata;
- secrets isolated from logs;
- contact identity verification performed by clients.

### Message tampering and replay

An attacker reorders, duplicates, modifies, or replays encrypted protocol messages.

Mitigations:

- authenticated encryption;
- ratchet/session state;
- message identifiers/counters;
- bounded skipped-message handling;
- explicit replay tests.

### Identity substitution

A server or attacker attempts to replace a contact's identity key.

Mitigations:

- identity binding stored locally;
- unexpected identity change must be visible;
- new key must not be silently trusted.

### User enumeration and spam

An attacker tries to discover users or flood them.

Mitigations:

- no public user search;
- invite-only discovery;
- single-use/expiring invites by default;
- quotas and rate limits;
- authenticate before expensive server work.

### Resource exhaustion

Malformed or excessive requests attempt to exhaust memory, CPU, storage, WebSocket slots, prekeys, mailbox capacity, or TURN allocations.

Mitigations:

- request and envelope size limits;
- bounded queues;
- mailbox quotas;
- connection limits;
- prekey lifecycle controls;
- short-lived TURN credentials;
- rate limiting.

### Local data leakage

Backups, logs, crash reports, screenshots, or local storage may expose sensitive information.

Mitigations:

- secrets in Android Keystore;
- sensitive backup behavior explicitly controlled and tested;
- no plaintext secrets in logs;
- minimum telemetry;
- UI screenshot restrictions considered only where they improve privacy without harming normal UX.

## Threats not fully solved

Kenato does not claim to provide:

- anonymity against a global network observer;
- protection from a fully compromised or unlocked device;
- protection from malicious recipients who intentionally record or disclose a conversation;
- guaranteed concealment of communication timing or traffic volume;
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
- mailbox and TURN abuse limits validated;
- dependency and supply-chain review completed;
- default-branch, release-tag, and CodeQL rulesets verified active;
- release signing identity/provenance controls verified;
- Android backup and logging behavior reviewed;
- repository-wide security audit completed;
- no open Critical or High severity security findings.
