# Contributing to Kenato

Kenato is in pre-1.0 milestone-driven development. M0 Foundation, M1 Local Identity, M2 Invite + Contact Establishment, and M3 E2EE Session are complete. M4 Minimal Messaging is active under tracker #49 in final repository-wide verification #54 after completion of implementation slices #50–#53. Do not treat M4 as complete until #54 is merged and the resulting exact `main` push is fully green. After M4, #59/M4.5 is the next permitted milestone; M5 remains blocked until that closed messaging-alpha gate is complete.

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

Workflow changes must preserve full-SHA Action pins, least-privilege permissions, non-persistent checkout credentials, required security gates, and release-secret isolation. The repository-wide `make test` contract, protobuf linting, Go vulnerability scanning, Rust advisory scanning for both native lockfiles, security-policy verification, Android lint/tests/builds, and CodeQL coverage for Go, Java/Kotlin, Rust, and GitHub Actions are part of the current verification baseline. Dependency Review must enforce the reviewed dependency-license policy in addition to vulnerability checks. Do not merge around a failing security gate; fix the cause or make an explicit reviewed policy change.

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

Until the owner makes a different reviewed licensing decision, do not silently add strong-copyleft AGPL/GPL dependencies that would constrain Kenato's reserved pre-1.0 licensing choices.

## Scope discipline

Kenato 1.0 is intentionally narrow: 1-to-1 voice calls, invite-only contacts, and minimal encrypted text messaging. Feature expansion should follow the roadmap rather than ad-hoc growth.
