# Contributing to Kenato

Kenato is currently in early foundation work.

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

## Dependencies

Before adding a dependency, consider:

- whether it is necessary;
- maintenance activity;
- license;
- security history;
- binary/native size impact;
- telemetry;
- supply-chain risk.

## Scope discipline

Kenato 1.0 is intentionally narrow: 1-to-1 voice calls, invite-only contacts, and minimal encrypted text messaging. Feature expansion should follow the roadmap rather than ad-hoc growth.
