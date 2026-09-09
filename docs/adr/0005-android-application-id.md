# ADR 0005: Android Application ID

Status: Accepted for pre-release development

## Context

Android application IDs become effectively immutable after store publication. Kenato needs one stable namespace shared by RuStore and Google Play builds.

No existing application using the exact package identifier `com.sl.kenato` was identified during M0 screening.

## Decision

Use:

`com.sl.kenato`

for the Android namespace and application ID during pre-release development.

RuStore and Google Play builds use the same application ID and source tree.

## Consequences

- store-specific source forks are not created;
- package naming follows the project's reserved `com.sl` namespace;
- changing the ID after public publication is treated as a new application identity.

Before the first public store submission, re-confirm that the identifier is still appropriate and conflict-free. If it must change, do so before any public release.
