# GitHub Security Settings

These repository settings require repository-owner administration and are part of the M0 security baseline.

## Dependency graph

Required for the Dependency Review workflow.

Enable:

`Settings → Security → Advanced Security → Dependency graph`

The PR gate intentionally fails while the dependency graph is disabled.

## Dependabot

Enable where available:

- Dependabot alerts;
- Dependabot security updates.

Version update configuration is committed in `.github/dependabot.yml`.

## Secret scanning

A pinned Gitleaks workflow scans pull requests, main-branch pushes, and a weekly schedule with a read-only token.

Also enable all repository-level secret-scanning protections GitHub offers for this public repository, including push protection when available.

The CI scan is defense in depth; it is not a substitute for repository-level push protection.

## Private vulnerability reporting

Enable GitHub private vulnerability reporting so `SECURITY.md` can direct reporters away from public issues.

## Main branch rules

After the M0 checks have stable names, protect `main` with a branch ruleset.

Required intent:

- changes reach `main` through pull requests;
- required CI/security checks must pass;
- force pushes are blocked;
- branch deletion is blocked;
- conversations/reviews are resolved where applicable;
- administrators should not casually bypass security gates.

Do not require a check until it has successfully run on `main`/a PR and its final check name is known.

## Actions

Keep default workflow permissions read-only unless a workflow explicitly needs a narrower write permission.

Production secrets must never be exposed to ordinary pull-request workflows.

## Release environment

Create a protected environment named `release` before the first signed artifact run.

Required environment secrets are documented in `docs/release/ANDROID_SIGNING.md`.

Consider requiring manual approval for the release environment before public production releases.

## Verification

Before closing M0, verify and record the actual repository settings rather than assuming GitHub defaults.

### M0 verification record — 2026-09-09

Verified from repository behavior/API:

- Dependency Review is operational and passes on pull requests, which confirms the dependency graph required by that gate is available.
- Dependabot version updates are operational; its initial Gradle and GitHub Actions update pull requests were created and verified.
- Repository rulesets are currently absent (`rulesets = []`). The required `main` protection ruleset is therefore an open M0 blocker.

Requires repository-owner verification in the GitHub UI because the current GitHub connector cannot read or change these administration settings:

- Dependabot alerts and security updates;
- secret scanning and push protection;
- private vulnerability reporting;
- default Actions workflow permissions;
- the protected `release` environment and its approval policy.

Do not close M0 until the required owner-controlled security settings are verified and the `main` ruleset blocker is resolved.
