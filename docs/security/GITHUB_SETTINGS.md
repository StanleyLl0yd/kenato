# GitHub Security Settings

These repository-owner settings are part of the M0 security baseline and must be verified from the live repository before M0 closes.

## Dependency and secret security

Enable all available repository protections for this public repository:

- Dependency graph;
- Dependabot alerts;
- Dependabot security updates;
- secret scanning;
- push protection;
- Private Vulnerability Reporting.

Dependency Review, Dependabot version updates, Gitleaks, Semgrep, govulncheck, and CodeQL remain defense-in-depth even when GitHub-native protections are enabled.

## Default branch ruleset

Create one active branch ruleset named `Protect main` for:

`~DEFAULT_BRANCH`

Required rules:

- deletion: blocked;
- non-fast-forward/force push: blocked;
- linear history: required;
- pull request: required;
- approving review count: 0 for the current single-maintainer model;
- conversation resolution: required;
- allowed merge method: squash only;
- required signatures: enabled;
- bypass actors: none;
- strict required status checks: enabled.

After the hardening PR has produced these exact successful check contexts, require:

- `Android`;
- `Go`;
- `Protocol syntax`;
- `Semgrep`;
- `Gitleaks`;
- `Dependency Review`;
- `Analyze (go)`;
- `Analyze (actions)`.

Do not add Qodana as a required merge gate: it is intentionally scheduled/manual defense-in-depth so an external tooling failure cannot deadlock a single-maintainer repository.

Required signatures are compatible with the current workflow: squash merges created by GitHub are verified, and release automation does not write to `main`.

## Release tag ruleset

Create one active tag ruleset named `Protect release tags` for:

`refs/tags/v*`

Required rules:

- update existing tag: blocked;
- deletion: blocked;
- bypass actors: none.

Initial tag creation remains allowed. The release workflow separately validates tag syntax, version/application identity, `main` ancestry, successful `main` verification, signing identity, and artifact provenance.

## Code scanning ruleset

Create one active branch ruleset named `Require CodeQL` for:

`~DEFAULT_BRANCH`

Add Code Scanning enforcement:

- tool: CodeQL;
- security alerts threshold: `medium_or_higher`;
- alert/error threshold: `errors`;
- bypass actors: none.

Kenato currently runs CodeQL for Go and GitHub Actions. Kotlin 2.4.20 remains outside the deployed CodeQL Kotlin support ceiling documented in `docs/development/TOOLCHAIN.md`; Semgrep is therefore the required complementary SAST gate and Qodana provides scheduled JVM/Kotlin analysis.

## Repository merge settings

Use repository merge settings consistent with the ruleset:

- allow squash merge: enabled;
- allow merge commits: disabled;
- allow rebase merge: disabled;
- automatically delete head branches after merge: enabled;
- branch update support may remain enabled if useful.

Do not require a human approval count merely to increase a security score in a single-maintainer repository.

## Actions

Set default workflow permissions to read-only repository contents.

Do not allow ordinary Actions workflows to create/approve pull requests unless a future reviewed automation explicitly requires it.

Committed workflow policy additionally requires:

- full-SHA pins for every non-local Action;
- digest pins for critical containers;
- `persist-credentials: false` on checkouts;
- least-privilege job permissions;
- no `pull_request_target`;
- no inherited reusable-workflow secrets.

## Release environment

Create a GitHub Actions environment named:

`release`

Store only the production signing trust material documented in `docs/release/ANDROID_SIGNING.md`.

If a second trusted reviewer exists, an environment approval can be useful. Do not enable a self-review-preventing approval policy that makes releases impossible for the current single-maintainer model.

## Verification record

### M0 final state — verified 2026-09-09

- `main` is protected.
- Active repository rulesets:
  - `Protect main` — ID `22649078`;
  - `Protect release tags` — ID `22649083`;
  - `Require CodeQL` — ID `22649087`.
- `Protect main` has no bypass actors and requires strict status checks, signed commits, linear history, squash-only pull requests, conversation resolution, and blocks deletion/non-fast-forward updates.
- Required checks are:
  - `Android`;
  - `Go`;
  - `Protocol syntax`;
  - `Semgrep`;
  - `Gitleaks`;
  - `Dependency Review`;
  - `Analyze (go)`;
  - `Analyze (actions)`.
- Release tags matching `v*` cannot be updated or deleted and have no bypass actors.
- CodeQL enforcement is active for the default branch at `medium_or_higher` security alerts and `errors` alert/error threshold.
- Repository merges are squash-only; merge/rebase commits are disabled and merged head branches are deleted automatically.
- Secret scanning and push protection are enabled.
- Dependabot alerts and security updates are enabled.
- Private Vulnerability Reporting is enabled.
- Actions default token permissions are read-only and workflows may not approve pull requests.
- The protected `release` environment exists.
- Production signing secrets and certificate trust material are intentionally not yet provisioned; they are required before the first production-signed release.

### Ongoing verification

Re-read live rulesets and owner-controlled security/release settings whenever a change affects CI permissions, required checks, release tags, signing, provenance, or the repository security boundary. Do not rely on this record as a substitute for live verification before a production release.
