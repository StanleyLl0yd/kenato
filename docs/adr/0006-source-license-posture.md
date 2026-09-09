# ADR 0006: Pre-1.0 Source License Posture

Status: Accepted for pre-1.0 development

## Context

Kenato is developed in a public GitHub repository, but the project owner has not selected a permanent open-source license.

Choosing a permissive or copyleft license now would grant rights that cannot later be revoked from already distributed copies. The long-term licensing model also needs to account for the Android client, Go server, future iOS distribution, third-party dependency licenses, and store requirements.

## Decision

During pre-1.0 development, do not grant an open-source license by default.

The repository remains source-visible with no repository-level license file. The README explicitly states that no rights are granted to copy, modify, or redistribute the source code unless separately permitted.

This is a conservative temporary posture, not a permanent rejection of open source.

A permanent license decision is required before the first stable public release.

## Consequences

Positive:

- no irreversible licensing grant is made before the product and distribution model are stable;
- Android, server, and future iOS licensing can be reviewed together;
- the owner retains the full set of future licensing choices.

Negative:

- the repository is not currently open source in the OSI sense;
- external contributors cannot assume redistribution or modification rights;
- accepting substantial external contributions would require an explicit contribution/licensing policy first.

## Follow-up

Before 1.0, explicitly choose and document the permanent licensing model. Any change to this ADR requires an owner decision.
