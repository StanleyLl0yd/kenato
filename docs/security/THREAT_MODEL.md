# Kenato Threat Model

Status: initial architecture baseline for M0.

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

## Threats in scope

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
- backup behavior.

## Pre-1.0 exit criteria

Before the first stable public release:

- threat model updated to match implementation;
- protocol test vectors checked;
- malformed/replayed/reordered input tests exist;
- mailbox and TURN abuse limits validated;
- dependency and supply-chain review completed;
- Android backup and logging behavior reviewed;
- repository-wide security audit completed;
- no open Critical or High severity security findings.
