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

### Verified on 2026-09-09 before this hardening change

- Dependency Review is operational.
- Dependabot version updates are operational.
- Current `main` commits produced through GitHub squash merge are cryptographically verified.
- No release tags or GitHub Releases exist yet.
- Repository rulesets are absent (`rulesets = []`), so `main`, CodeQL enforcement, and `v*` tags are not yet protected.
- The current connector cannot read or mutate the owner-only repository settings listed above.

### M0 close condition

Do not close M0 until:

1. this hardening change is merged and all new check names above are proven green;
2. the three rulesets are active and re-read from the repository API;
3. owner-only secret-scanning/Dependabot/PVR/Actions/environment settings are verified;
4. final repository-wide CI/security verification is green.
