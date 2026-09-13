# Contributing to Kenato

Kenato is in pre-1.0 milestone-driven development. M0 Foundation, M1 Local Identity, and M2 Invite + Contact Establishment are complete. M3 E2EE Session implementation (#34/#40) is merged and the final repository-wide M3 audit/remediation and exact-main verification (#35) are in progress. M4 remains scope-gated by `ROADMAP.md` and `AGENTS.md` and must not start before M3 closes.

## Workflow

1. Open or reference an issue for non-trivial changes.
2. Create a short-lived branch.
3. Keep pull requests focused.
4. Add or update tests for behavior changes.
5. Document protocol, architecture, or security changes.
6. Ensure relevant checks pass before requesting review.

## Pull requests

A pull request should explain:

- what changed;
- why it changed;
- security/privacy impact;
- compatibility impact;
- how it was tested.

Changes to cryptography, identity, wire formats, authentication, persistence, or call state machines require extra review attention.

## CI and supply chain

Workflow changes must preserve full-SHA Action pins, least-privilege permissions, non-persistent checkout credentials, required security gates, and release-secret isolation. The repository-wide `make test` contract, protobuf linting, Go vulnerability scanning, Rust advisory scanning for both native lockfiles, security-policy verification, Android lint/tests/builds, and CodeQL coverage for Go, Java/Kotlin, Rust, and GitHub Actions are part of the M3 verification baseline. Do not merge around a failing security gate; fix the cause or make an explicit reviewed policy change.

## Dependencies

Before adding a dependency, consider:

- whether it is necessary;
- maintenance activity;
- license;
- security history;
- binary/native size impact;
- telemetry;
- supply-chain risk;
- lock/checksum/integrity impact and vulnerability-scanner coverage.

## Scope discipline

Kenato 1.0 is intentionally narrow: 1-to-1 voice calls, invite-only contacts, and minimal encrypted text messaging. Feature expansion should follow the roadmap rather than ad-hoc growth.
