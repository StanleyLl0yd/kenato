# Kenato — Agent Instructions

This file is the root operating contract for coding agents working in this repository.

Keep it high-signal. Do not duplicate detailed architecture, security, protocol, brand, or contribution documentation here when a stable source already exists.

## Scope

These instructions apply to the entire repository unless a more specific nested `AGENTS.md` exists for a subdirectory.

## Instruction precedence

When instructions conflict, use this order:

1. The project owner's explicit current instruction.
2. This `AGENTS.md`.
3. Accepted Architecture Decision Records in `docs/adr/`.
4. `docs/security/THREAT_MODEL.md` for security assumptions and review triggers.
5. `SECURITY.md` for security-reporting and repository security policy.
6. `docs/architecture/OVERVIEW.md` for architecture direction.
7. `docs/brand/BRAND.md` for UI/brand rules.
8. `CONTRIBUTING.md` for repository workflow.
9. `README.md` for product-level summary.

Do not silently resolve a conflict by inventing a new product, protocol, cryptographic, or architecture direction.

For security-sensitive conflicts, preserve the stricter existing invariant and make the conflict explicit.

## Project

Kenato is a privacy-first mobile communication app focused on 1-to-1 voice calls and minimal end-to-end encrypted messaging.

Brand:

- Name: Kenato
- Visual direction: Zen Minimal
- Primary tagline: `Talk freely.`

Current repository phase:

`M2 — Invite + Contact Establishment`: complete.

Next planned milestone:

`M3 — E2EE Session`

Do not start M3 or any later-milestone implementation unless explicitly requested. Do not implement later-milestone features merely because the architecture could support them.

Kenato 1.0 is intentionally narrow:

- 1-to-1 voice calls;
- minimal end-to-end encrypted text messaging;
- invite-only contact establishment;
- no phone number or email requirement;
- Android first;
- RuStore first, Google Play later.

Do not add phone-number identity, email identity, address-book upload, public user search, groups, video, file transfer, cloud history, or multi-device synchronization unless an explicit milestone or owner instruction requires it.

## Core invariants

These are critical project invariants and must not be weakened without an explicit owner decision and corresponding security/architecture review.

1. The server must never require plaintext user messages, call signaling content, or voice content.
2. Private identity keys never leave the device.
3. Contact identity must never change silently.
4. All untrusted inputs are bounded.
5. There is no public user search or enumeration.
6. Sensitive data and secrets must never be written to logs.
7. Prefer simple, auditable designs over feature-rich abstractions.
8. Do not implement custom cryptographic primitives when mature, reviewed primitives or protocols exist.

## Engineering rules

- Keep `main` buildable and releasable.
- Use short-lived branches and small pull requests.
- Every behavior change requires appropriate tests.
- Protocol changes require compatibility consideration and test vectors where applicable.
- Security-sensitive changes require explicit security impact notes.
- Avoid unnecessary dependencies.
- Do not introduce telemetry or analytics SDKs without an explicit decision.
- Do not commit signing keys, credentials, tokens, secrets, generated release artifacts, or local configuration.
- Prefer the smallest implementation that fully preserves current product and security requirements.
- Do not build speculative infrastructure for hypothetical future scale or features.

## Architecture

Target repository structure:

```text
android/
server/
protocol/
deploy/
docs/
scripts/
```

Current architecture baseline:

- Android client: native Kotlin + Jetpack Compose;
- server: Go;
- media: WebRTC + Opus;
- signaling transport: HTTPS/WSS;
- NAT traversal/relay: ICE + STUN/TURN via coturn;
- initial server datastore: SQLite;
- protocol serialization: Protocol Buffers.

The protocol is platform-independent even though Android is the first client.

### Android boundaries

UI must be separate from call, media, session, identity, and cryptographic state.

Do not let Composables directly own or manipulate WebRTC `PeerConnection` objects.

Keep clear boundaries around:

- Identity;
- Crypto/session state;
- Signaling;
- WebRTC transport;
- Audio session;
- Persistence;
- UI/application state.

Android framework concerns should not leak into protocol or cryptographic logic when avoidable.

### Server boundaries

The initial backend is intentionally small:

- one Go service binary;
- SQLite/WAL;
- coturn as a separate service.

Do not introduce Redis, Kafka, RabbitMQ, Kubernetes, a service mesh, or a microservice split unless measured requirements justify the added complexity.

The server may process only the metadata and opaque encrypted payloads required for routing, delivery, invites, public identity material/prekeys, and bounded operational state.

Do not expand durable metadata collection without explicit privacy review.

## Protocol and cryptography

Protocol and cryptographic behavior are security boundaries, not ordinary implementation details.

### Protocol versioning

The wire protocol must remain versioned independently of implementation language.

Protocol changes must consider:

- backward/forward compatibility where applicable;
- unknown message/version handling;
- migration/rollout behavior;
- replay/reordering behavior;
- malformed input handling;
- deterministic test vectors where applicable.

Unknown or unsupported protocol states must fail safely.

Do not silently reinterpret old wire data as a new meaning.

### Cryptographic rules

Do not:

- invent custom cryptographic primitives;
- implement ad-hoc encryption formats when a mature reviewed protocol/primitives exist;
- silently downgrade algorithms or verification requirements;
- bypass authentication/integrity checks to preserve compatibility;
- trust replaced contact identity keys silently;
- serialize private identity keys to the server;
- log cryptographic secrets or plaintext user content.

Any change touching cryptographic protocol, identity lifecycle, invite handshake, authentication, wire protocol, secret persistence, call key establishment, WebRTC security assumptions, push payload contents, logging/telemetry, or backup behavior requires review against `docs/security/THREAT_MODEL.md`.

### Metadata minimization

Keep server-visible metadata to the minimum required for routing and protocol evolution.

When the server does not need semantic content, keep it inside authenticated ciphertext.

Push payloads must not contain message plaintext, contact names, or sensitive call details unless an explicit reviewed design requires otherwise.

## Identity and contact discovery

Identity is generated on-device.

Private identity keys remain on-device.

Contacts are established through explicit invites.

There is no public user search in 1.0.

Contact identity bindings are pinned locally and unexpected identity changes must be visible to the user.

Do not silently auto-accept a changed identity key merely to avoid UX friction.

Invite behavior must preserve the accepted invite-only discovery architecture unless explicitly changed through a new decision.

## Bounded untrusted input

"All untrusted inputs are bounded" applies to more than HTTP body size.

Do not allow attacker-controlled unbounded:

- allocations;
- queues;
- loops;
- recursion;
- retained messages;
- WebSocket connections;
- retries;
- timers;
- parser depth/counts;
- protocol envelopes;
- prekeys;
- invite attempts;
- authentication attempts;
- TURN allocations;
- expensive cryptographic or database work.

Apply limits before expensive processing where practical.

Use:

- explicit maximum sizes;
- bounded queues;
- explicit timeouts;
- bounded retries;
- rate limiting;
- connection limits;
- mailbox quotas;
- expiration;
- cancellation propagation.

Specific numeric limits may live in config or architecture docs, but the bounded-resource invariant is mandatory.

## Messaging

The server is a bounded store-and-forward relay for opaque encrypted payloads.

Prefer direct forwarding without durable mailbox storage when the recipient is online.

Offline storage must remain bounded and expire.

Message delivery, retry, acknowledgement, replay, duplication, and reordering behavior must be explicit and testable.

Do not make reliability improvements by weakening end-to-end encryption or identity verification.

## Voice calling

Voice is audio-only for 1.0.

Use WebRTC for media transport.

Use direct P2P connectivity when available and coturn relay when direct connectivity fails.

TURN is an untrusted packet relay and must not require plaintext voice.

Do not introduce a media server that terminates end-to-end media confidentiality unless explicitly approved as a product/security change.

## Android security

Private identity and other long-lived sensitive keys should use Android Keystore-backed protection where appropriate.

Do not place sensitive plaintext or secrets in:

- logs;
- analytics;
- crash-report metadata;
- `SavedStateHandle`;
- UI snapshots/test fixtures;
- debug dumps;
- unprotected backups;
- notifications/push payloads.

Backup behavior for sensitive state must be explicit, reviewed, and tested.

Background calling, audio routing, Bluetooth handling, notifications, lock-screen behavior, and Android lifecycle are correctness and security concerns, not merely UI details.

Avoid blocking work on the main thread.

Preserve cancellation and lifecycle correctness.

## Server security

The server must remain safe under malformed, abusive, duplicated, delayed, reordered, and replayed traffic.

Prefer:

- explicit HTTP/WebSocket limits;
- request deadlines/timeouts;
- bounded goroutine/concurrency patterns;
- cancellation propagation;
- structured error handling;
- rate limits before expensive work;
- short-lived TURN credentials;
- bounded mailbox retention;
- minimal durable metadata.

Do not place plaintext user content or private identity keys in server storage, diagnostics, or logs.

Administrative and operational logging must avoid sensitive payloads and secrets.

## Dependencies and supply chain

Before adding a dependency, evaluate:

- necessity;
- maintenance activity;
- license;
- security history;
- binary/native size impact;
- telemetry behavior;
- supply-chain risk;
- whether a simpler standard-library/platform solution exists.

Avoid overlapping libraries that solve the same problem.

Do not replace a mature reviewed cryptographic/networking implementation with custom code merely to reduce dependency count.

Native/cgo/JNI dependencies require additional scrutiny because they affect portability, build security, binary size, and platform compatibility.

Dependency resolution rules:

- use exact dependency/tool versions rather than dynamic selectors such as `latest` or `+`;
- commit ecosystem lock/checksum/integrity files when the ecosystem produces them;
- commit `go.sum` as soon as Go module dependencies require it;
- keep Gradle Wrapper distribution verification enabled and preserve the pinned wrapper JAR checksum gate;
- use package-manager integrity mechanisms rather than blindly executing downloaded tools;
- any direct executable/archive download in CI must use HTTPS plus a pinned version and checksum/signature verification.

For GitHub Actions and CI:

- every non-local GitHub Action must use a full immutable 40-character commit SHA; retain a human-readable version comment;
- critical workflow container images must be pinned by SHA-256 digest;
- checkouts must use `persist-credentials: false`;
- top-level workflow permissions must be empty/read-only and job permissions must follow least privilege;
- `security-events: write`, `id-token: write`, `attestations: write`, and `contents: write` belong only to jobs that actually require them;
- ordinary pull-request workflows must use `pull_request`, not `pull_request_target`;
- do not inherit reusable-workflow secrets or expose production signing/deployment secrets to untrusted PR code;
- repository CI supply-chain policy checks are mandatory and must stay green;
- merge gates must include the relevant build/tests, SAST, secret scan, dependency review/vulnerability scan, and CodeQL checks that are supported by the current stack.

Release integrity rules:

- release tags are immutable and must resolve to reviewed `main` commits;
- production signing keys/certificates never enter source control;
- release workflows verify source revision, application identity, version, signing identity, checksums, and successful main security gates before producing a production artifact;
- binary release artifacts must receive provenance/attestation when the hosting platform supports it;
- temporary decoded signing material must be removed even on workflow failure.

## Code quality

Prefer simple, explicit, auditable code.

Rules:

- keep responsibilities clear;
- minimize mutable state;
- minimize hidden control flow;
- avoid duplicate sources of truth;
- avoid wrapper chains with no useful semantics;
- avoid abstractions created only for hypothetical future use;
- prefer standard library/platform behavior when it is simpler and sufficient;
- do not optimize for minimum line count;
- do not make a broad rewrite just because another architecture is more fashionable.

Comments must be:

- minimal;
- useful;
- current;
- written in English.

Prefer comments that explain why an invariant exists rather than narrating obvious code.

Do not keep commented-out legacy code.

Remove stale TODO/FIXME comments when their meaning is no longer actionable.

## UI / brand

Brand: Kenato  
Visual direction: Zen Minimal  
Tagline: Talk freely.

Prefer calm, simple, spacious UI.

Avoid:

- security theatrics;
- fear-driven copy;
- visual clutter;
- neon/cyberpunk styling;
- decorative Japanese clichés;
- exposing cryptographic/network implementation details in normal UI.

Follow `docs/brand/BRAND.md` for detailed visual rules.

Do not sacrifice accessibility, legibility, or minimum touch targets for decorative consistency.

## Testing

Every behavior change requires appropriate tests where practical.

Highest-priority security/protocol test areas include:

- protocol compatibility;
- deterministic test vectors where applicable;
- malformed input;
- oversized input;
- replay;
- duplicate delivery;
- reordering;
- identity substitution/change;
- authentication failure;
- invite lifecycle;
- mailbox bounds;
- retry behavior;
- WebSocket disconnect/reconnect;
- TURN credential lifetime/abuse limits;
- backup behavior;
- logging redaction;
- call-state transitions;
- Android lifecycle/background behavior.

For bugs, prefer a regression test that fails before the fix and passes after it.

Do not add tests that merely mirror implementation details without protecting meaningful behavior.

For risky security-sensitive refactors without coverage, add a minimal regression test first when practical.

## Verification

Run the narrowest relevant checks first, then expand when needed.

Depending on repository state and changed area, verification can include:

- formatting;
- lint;
- Kotlin/JVM unit tests;
- Android tests;
- Android build;
- Go tests;
- race detector where relevant;
- protocol tests/test vectors;
- malformed-input/fuzz tests where available;
- dependency/security checks;
- static analysis;
- server build;
- deployment/config validation.

Before a release or full audit, perform repository-wide verification.

Never claim a test, build, security scan, race check, or other verification step passed unless it was actually run and completed successfully.

If a required check cannot run in the current environment, state that explicitly.

## Repository workflow

Default workflow:

1. Start from an issue or clearly scoped task.
2. Create a short-lived branch from `main`.
3. Keep changes focused.
4. Avoid unrelated churn.
5. Add or update tests for behavior changes.
6. Document protocol, architecture, security, or compatibility changes.
7. Open a pull request.
8. Explain security/privacy and compatibility impact.
9. Run relevant checks before merge.
10. Prefer squash merge unless preserving a meaningful commit series is useful.

Protocol, cryptography, identity, authentication, persistence, and call-state changes deserve extra review attention.

## Documentation and ADRs

Do not duplicate detailed security/architecture documentation in this file.

Add or update an ADR when changing a durable architectural decision such as:

- client platform strategy;
- server architecture;
- contact discovery;
- protocol ownership/versioning;
- persistent identity model;
- message-storage model;
- media-relay trust assumptions;
- major persistence boundaries.

Update the threat model when implementation changes alter:

- protected assets;
- trust boundaries;
- attacker capabilities;
- security assumptions;
- review triggers;
- explicit non-goals.

Security guarantees must not exist only in code comments.

## Repository-wide audit and refactoring tasks

A request for a full audit, cleanup, optimization, simplification, or deep refactor is an implementation task, not a request for recommendations only.

The objective is to reduce the repository to the minimum necessary complexity while preserving all current functionality, protocol behavior, security/privacy guarantees, compatibility requirements, and supported platform behavior.

### Audit before editing

Before broad refactoring, inspect the whole relevant repository surface:

- production source;
- tests;
- protocol definitions and test vectors;
- resources/assets;
- build scripts;
- CI/CD;
- dependencies;
- deployment/configuration;
- documentation;
- platform integration;
- generated-code integration points.

Identify first:

- actual architecture;
- authoritative state;
- user-visible functionality;
- cryptographic/protocol boundaries;
- persistence formats;
- public/internal contracts;
- framework- or convention-driven entry points.

Do not classify code as unused only because textual search shows no direct call.

Check possible indirect use through:

- callbacks;
- lifecycle hooks;
- reflection;
- serialization;
- Protocol Buffers/generated code;
- dependency injection;
- manifests;
- resources;
- routing/registration;
- build scripts;
- CI/release tooling;
- tests;
- Android platform integration;
- Go init/registration behavior;
- WebRTC callbacks/state machines.

If reasonable uncertainty remains, preserve the code.

### Removal and simplification priorities

Actively remove or simplify when safety is demonstrated:

- dead/unreachable code;
- unused files/resources;
- obsolete legacy paths;
- duplicated implementations;
- redundant checks;
- redundant conversions/copies;
- unnecessary wrappers/helpers;
- unnecessary abstraction layers;
- obsolete feature flags;
- unused dependencies;
- stale commented-out code;
- stale migration leftovers;
- speculative architecture with no current value.

Prefer:

- deletion over deprecation when compatibility is not required;
- consolidation over parallel implementations;
- fewer states and branches;
- fewer sources of truth;
- simpler control flow;
- bounded rather than open-ended behavior;
- standard library/platform behavior over unnecessary custom code.

Do not perform code golf or broad rewrites without measurable value.

### Security preservation during refactoring

A reduction in code size or architectural complexity must never weaken:

- cryptographic verification;
- authentication/integrity checks;
- replay protection;
- identity verification;
- input validation;
- resource bounds;
- rate limiting;
- secret handling;
- logging privacy;
- backup protections;
- protocol compatibility.

Do not remove an apparently redundant security check until the invariant that makes it redundant is explicit, enforced, and covered by tests.

### Refactor verification

Work in small coherent groups.

After meaningful groups, run the relevant checks.

Perform a mandatory second pass after the first refactor pass to catch newly exposed:

- dead code;
- duplication;
- redundant abstractions;
- stale imports/dependencies;
- unnecessary state;
- obsolete compatibility paths.

Never report a build/test/security check as green unless it actually ran.

## App icon source artwork

When the project owner provides a new app icon as a PNG and identifies it as the app icon, treat that exact PNG as the canonical full-color source artwork.

Keep that source as the original raster PNG.

Do not trace, vectorize, redraw, restyle, recreate, recompress, optimize in place, or replace the canonical PNG unless the project owner explicitly requests it.

Do not convert the canonical source into a new vector master such as:

- SVG;
- vector PDF;
- Android VectorDrawable;
- any other vector representation.

Platform-required derivatives may be generated separately from the canonical PNG.

For Android, required derivative assets may include:

- adaptive foreground/background assets;
- monochrome themed icon;
- simplified notification icon;
- raster density variants.

These derivatives do not replace the canonical PNG.

The canonical full-color artwork must remain unchanged unless explicitly requested.

Do not alter its:

- composition;
- colors;
- proportions;
- details;
- crop;
- padding;
- styling.

Android-specific monochrome or notification derivatives may necessarily simplify or recolor the symbol to satisfy platform requirements, but they must preserve the recognizable Kenato symbol and must remain clearly derived assets rather than replacements for the canonical artwork.

If an older icon is currently canonical, keep it until the project owner explicitly supplies a replacement PNG as the new app icon.

## Definition of done

A change is not complete merely because code was written.

Before considering work complete:

- required behavior is implemented;
- relevant tests are added or updated;
- protocol compatibility is considered where applicable;
- security/privacy impact is reviewed;
- threat-model impact is reviewed for security-sensitive changes;
- malformed/oversized/replayed input behavior is covered where relevant;
- documentation/ADR is updated when an invariant or durable decision changes;
- dependency/supply-chain impact is explicit;
- no secrets or sensitive plaintext were introduced into logs or artifacts;
- relevant checks were actually run where possible;
- the final diff is reviewed for unnecessary complexity and unrelated churn.

For repository-wide audit/refactor work, also complete the required second pass and summarize what was removed, simplified, preserved, and verified.
