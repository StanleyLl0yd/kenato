# Contributing to Kenato

Kenato is in pre-1.0 milestone-driven development. M0 Foundation and M1 Local Identity are complete; M2 Invite + Contact Establishment is the next planned milestone and remains scope-gated by `ROADMAP.md` and `AGENTS.md`.

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

Workflow changes must preserve full-SHA Action pins, least-privilege permissions, non-persistent checkout credentials, required security gates, and release-secret isolation. Do not merge around a failing security gate; fix the cause or make an explicit reviewed policy change.

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
