# M4 Final Repository-Wide Security Review

Status: final M4 verification for issue #54 / tracker #49. The mandatory second repository-wide pass is complete with no unresolved Critical/High M4 finding. M4 is **not complete** until this review branch is squash-merged and the resulting exact `main` push is fully green. M5 remains prohibited. After M4 closure the next permitted work is #59/M4.5.

## Scope

This is the final repository-wide M4 review after the completed implementation slices:

- #50 — authenticated messaging protocol/auth/delivery contract;
- #51 — bounded durable mailbox persistence;
- #52 — authenticated WSS connection ownership, direct delivery and mailbox fallback;
- #53 — Android durable messaging transport, crash-safe handoff and bounded local history;
- #54 — this final repository-wide end-to-end/security verification.

The review covers protocol definitions and canonical encoding, Go server routing/mailbox/lifecycle behavior, Android messaging/session/history boundaries, persistence and restart behavior, the M3 native/JNI cryptographic boundary, CI/supply-chain and release policy, repository configuration/resources, documentation consistency, and required exact-head/exact-main gates. It does not authorize M5 calling/WebRTC work.

## Findings closed during #54

The final pass found and closed the following concrete issues/regression gaps:

1. CI verification regenerated committed Cargo lockfiles before `--locked` checks, making PR/main verification registry-dependent. Lock regeneration was removed from verification and CI policy now forbids `cargo generate-lockfile` / `cargo update` in verification workflows.
2. WSS authentication now has an explicit replay regression proving that a proof valid for one connection/challenge cannot authenticate a fresh connection or displace the existing peer.
3. Authenticated sender substitution is regression-tested before routing or mailbox persistence.
4. An ACK from the wrong authenticated identity is regression-tested and cannot resolve another recipient's direct pending delivery.
5. The direct-delivery ACK versus durable-fallback `Store` race is deterministically regression-tested so an ACK that wins during the fallback write cannot strand a retained mailbox row.
6. Go and Android share deterministic canonical M4 Envelope/client-send/server-delivery golden vectors.
7. Unexpected HTTP-server failure now enters the common ordered shutdown path: upgraded WSS work stops before HTTP shutdown and SQLite closure.
8. Root/protocol/server/architecture/toolchain/security review documentation is synchronized with #53 complete and #54 active.
9. The new WSS replay regression itself used a fixed 2033 server clock with a helper envelope expiring from the real 2026 clock, producing a false `SEND_REJECTED`. The test now derives expiry from the same fixed clock and additionally proves the exact original authenticated peer remains registered after the replay attempt.
10. The second repository-wide documentation pass found two additional stale current-state claims in `CONTRIBUTING.md` and `docs/development/OCI_HOST.md` that still said M4 had not started. Both now reflect #50–#53 complete, #54 active, #59/M4.5 next, and M5 blocked.

## Security invariants rechecked

The final review preserves these M4 boundaries:

- identity ids are routing identifiers, never credentials;
- WSS ownership requires possession of the pinned P-256 identity key and a fresh single-use challenge;
- authenticated sender identity must match the outer envelope sender before routing/storage;
- delivery ACK authority belongs only to the authenticated recipient;
- ordinary message plaintext remains inside M3 authenticated encryption;
- inner authenticated routing context must match the outer envelope before local delivery/ACK;
- direct and durable custody reuse the exact immutable envelope/message id;
- mailbox retention, bytes, TTL and per-recipient/global resource usage remain bounded;
- inbound ACK is emitted only after crash-safe durable client handoff/history state exists;
- outbound retries reuse durable ciphertext and never re-encrypt/advance the ratchet for transport retry;
- Android conversation history remains app-private, no-backup and bounded;
- M3/JNI secret pickle-key and plaintext native buffers remain bounded and zeroized at the reviewed boundary;
- verification never mutates committed Cargo dependency resolution state.

## Regression evidence pinned by repository tests

The repository must retain and execute these exact regression surfaces:

- `server/internal/httpapi/messaging_ws_authorization_test.go`
  - `TestMessagingWSSRejectsAuthenticationProofReplayAcrossConnections`
  - `TestMessagingWSSRejectsAuthenticatedSenderSubstitution`
  - `TestMessagingWSSUnauthorizedAckCannotResolveDirectDelivery`
- `server/internal/httpapi/messaging_ack_store_race_test.go`
  - `TestMessagingDirectAckRacingFallbackDeletesCommittedMailboxRow`
- `server/internal/messaging/wire_vectors_m4_test.go`
  - `TestM4ServerVisibleWireVectors`
- `android/app/src/test/java/com/sl/kenato/messaging/MessagingWireVectorTest.kt`
  - `serverVisibleWireMatchesSharedM4Vectors`
- `scripts/verify_m4_server_lifecycle.py`
  - pins ordered WSS → HTTP → SQLite shutdown and the server-failure common path.

The existing protocol/mailbox/transport/Android messaging verifiers remain mandatory and are not replaced by this final-review verifier.

## Repository-wide verification contract

`make test` must include and pass:

- protocol descriptor generation and protolint;
- Go formatting, unit tests, race tests, vet, govulncheck and amd64/arm64 builds;
- Rust fmt/check/clippy/tests/release builds with committed lockfiles and `--locked`, plus cargo-audit;
- CI supply-chain, security baseline and repository-verification policy checks;
- all M4 protocol/mailbox/transport/server-lifecycle/Android/final-audit verifiers;
- Android native build, lint, unit tests, debug/release builds and release bundle.

The final PR head must then be green for the protected-branch matrix: CI (Android, Go, Protocol syntax, Repository make test), Security and Quality/Semgrep, Gitleaks, Dependency Review, and CodeQL for Go, Java/Kotlin, Rust and Actions.

Because earlier M4 work exposed PR/main nondeterminism, PR success is insufficient by itself. After squash merge, the exact resulting `main` SHA must independently pass the main-push CI/security/Gitleaks/CodeQL checks before tracker #49 / issue #54 are treated as complete. Dependency Review is PR-only and is therefore expected not to run on the main push.

## Mandatory second repository-wide pass — completed

The repository tree was recursively re-enumerated after the #54 edits and the second pass covered the whole repository surface rather than only the PR diff: production source, tests, protocol, native/JNI code, persistence, Android manifest/resources/build configuration, CI/release/security workflows, dependencies and lock/integrity policy, repository metadata, documentation/ADRs, and development/release configuration.

The second pass specifically rechecked newly exposed dead/stale state, duplicated authority, mutable verification inputs, unbounded work, authentication/ACK ownership, mailbox quotas/TTL/corruption/restart behavior, shutdown ordering, Android crash/retry/recovery boundaries, backup/logging/privacy surfaces, native secret handling, later-milestone leakage, and current milestone/status text.

Its material results were the replay-regression fixture correction and the two stale current-state documentation corrections listed above. No new production runtime/security defect was found after those corrections, and no unresolved Critical/High M4 finding remains. M5/WebRTC implementation is absent from the current repository surface.

## Closure rule

M4 closes only in this order:

1. complete the second repository-wide pass with no unresolved Critical/High M4 finding;
2. freeze an exact PR head;
3. obtain the complete required green PR matrix on that exact SHA;
4. verify merge rules/reviews/threads/base are still satisfied;
5. mark PR ready and squash-merge using the expected head SHA;
6. obtain the required green exact-`main` push matrix;
7. close #54 and tracker #49 and clean up the merged branch.

Only then may work move to #59/M4.5. M5 remains blocked until #59 is complete.
