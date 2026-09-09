# Release Conventions

## Versioning

Kenato uses SemVer for public product versions:

- development: `0.x.y`;
- first stable release: `1.0.0`.

Android `versionCode` is monotonically increasing and never reused for a published artifact.

## Git

Stable and release-candidate artifacts are built from immutable Git tags:

- `v0.9.0`;
- `v1.0.0-rc.1`;
- `v1.0.0`.

`main` remains the integration branch. Store-specific release branches are not used.

## Android artifacts

Every Android release produces from the same commit:

- signed APK;
- signed AAB;
- SHA-256 checksums.

A release is not valid if one artifact is produced from a different source commit or signing identity.

## Release gates

Before a stable release:

- repository-wide relevant tests pass;
- Android lint/build passes;
- Go tests/vet/builds pass;
- protocol validation passes;
- security/dependency checks pass;
- signing is verified;
- native 16 KiB page compatibility is verified once native libraries are present;
- privacy/store documentation matches implementation;
- no open Critical/High security findings remain.

## Store order

1. RuStore
2. Google Play

Current store policy requirements are re-checked immediately before each submission because external policies change.
