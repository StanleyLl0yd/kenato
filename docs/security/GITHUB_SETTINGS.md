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

For this public repository, enable all available secret-scanning protections, including push protection when GitHub offers them for the repository.

No committed workflow or configuration is a substitute for repository-level push protection.

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
