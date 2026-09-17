# Release Conventions

## Versioning

Kenato uses ordinary SemVer numbers for every published product version, including pre-1.0 releases:

- first release: `0.0.1`;
- subsequent releases: `0.0.2`, `0.0.3`, and so on;
- first stable release: `1.0.0`.

Kenato does not use alpha, beta, release-candidate, or other prerelease suffixes.

Android `versionCode` is monotonically increasing and never reused for a published artifact. `0.0.1` uses `versionCode = 1`; later releases increment it.

## Git

Release artifacts are built only from protected immutable Git tags matching exactly `vX.Y.Z`, for example:

- `v0.0.1`;
- `v0.0.2`;
- `v1.0.0`.

Prerelease-suffixed tags are not accepted by the release workflow.

`main` remains the integration branch. Store-specific release branches are not used.

## Android artifacts

Every Android release produces from the same verified commit:

- signed APK;
- signed AAB;
- SHA-256 checksums;
- GitHub artifact attestations for APK and AAB;
- a GitHub Release containing the verified package.

A release is not valid if one artifact is produced from a different source commit or signing identity. APK and AAB certificate fingerprints must match the independently protected expected release certificate fingerprint.

## Release gates

Before any published release:

- the tag resolves to a reviewed commit contained in protected `main`;
- exact-main CI, Security and Quality, Gitleaks, and CodeQL runs are successful for that commit;
- repository-wide relevant tests pass;
- Android lint/build passes;
- Go tests/vet/builds pass;
- protocol validation passes;
- security/dependency checks pass;
- signing identity and artifact checksums are verified;
- artifact provenance/attestation is created;
- native 16 KiB page compatibility is verified once native libraries are present;
- privacy/store documentation matches implementation;
- no open Critical/High security findings remain.

## Store order

1. RuStore
2. Google Play

Current store policy requirements are re-checked immediately before each submission because external policies change.
