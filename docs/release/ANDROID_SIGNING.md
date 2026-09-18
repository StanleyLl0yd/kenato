# Android Release Signing

Kenato release signing is designed so production signing material never enters the repository or an ordinary pull-request workflow.

## Required GitHub environment

Use the protected GitHub Actions environment named:

`release`

The environment exists. For the first signed release (`0.0.1`), provision these environment secrets:

- `ANDROID_KEYSTORE_BASE64` — complete release keystore encoded as base64;
- `ANDROID_KEYSTORE_PASSWORD`;
- `ANDROID_KEY_ALIAS`;
- `ANDROID_KEY_PASSWORD`;
- `ANDROID_CERT_SHA256` — expected SHA-256 fingerprint of the release signing certificate.

This intentionally matches the release-secret shape already used by the owner's other Android repositories, while keeping the expected certificate fingerprint as a protected Kenato secret rather than repository data.

The expected certificate fingerprint is an environment-protected trust anchor so changing repository code alone cannot silently authorize a different signing identity.

Do not store the raw keystore, passwords, decoded temporary files, or production signing configuration in source control.

## Workflow behavior

The release workflow:

1. runs only on protected `main` pushes that change the Android release version or the release workflow, serializes all release attempts through one main publication group, derives only `vX.Y.Z`, and no-ops after that version is already published; alpha/beta/rc or other prerelease suffixes are rejected;
2. verifies the workflow source is the exact current protected `main` revision;
3. requires successful `main` runs of CI, Security and Quality, Gitleaks, and CodeQL for that exact commit;
4. verifies `versionName`, `versionCode`, namespace and `com.sl.kenato` application id;
5. verifies monotonically increasing release `versionCode` against prior numeric release tags;
6. verifies the Gradle Wrapper before build execution;
7. decodes the keystore with restrictive permissions into `$RUNNER_TEMP`;
8. validates the expected keystore alias;
9. runs tests/lint and builds signed APK/AAB from the same source revision;
10. verifies APK/AAB signatures and matches both certificate fingerprints to `ANDROID_CERT_SHA256`;
11. creates and verifies SHA-256 artifact checksums;
12. creates OIDC-backed GitHub artifact attestations for APK and AAB;
13. uploads only the packaged signed artifacts/checksum;
14. rechecks that the workflow SHA is still the current protected `main` immediately before draft mutation, creates exactly one canonical draft targeted at that commit after removing any stale unpublished drafts for the same numeric version, attaches and verifies the APK/AAB/checksum, rechecks exact `main` again immediately before publication, publishes that release by its release ID (which creates the protected `vX.Y.Z` tag when no tag exists yet), then verifies the published tag resolves to that exact commit;
15. removes the temporary decoded keystore even when a later workflow step fails.

The ephemeral runner is discarded after the job as an additional containment boundary.

## Provisioning the existing JKS

The existing release JKS should be kept outside the repository. Before the `0.0.1` release workflow runs, derive and verify the JKS alias and SHA-256 certificate fingerprint locally, then place the JKS and credentials only in the five protected `release` environment secrets above.

The keystore base64 value must be the complete binary JKS encoded without modification. Do not commit an encoded JKS file to the repository merely because it is base64 text.

## Local signing

For a local release build, keep the keystore outside the repository and export:

```bash
export KENATO_KEYSTORE_PATH=/secure/path/kenato.jks
export KENATO_KEYSTORE_PASSWORD='...'
export KENATO_KEY_ALIAS='...'
export KENATO_KEY_PASSWORD='...'

./gradlew :android:app:assembleRelease :android:app:bundleRelease
```

Gradle accepts either all four release-signing variables or none. A partial signing configuration fails during configuration rather than silently producing an unsigned release.

Verify the resulting certificate identity independently before publication.

Never add signing variables to committed shell scripts, Gradle files, `.env` files, or local properties tracked by Git.

## Store strategy

The same application ID, signing identity and source commit are used for RuStore and Google Play.

- RuStore is the first publication target.
- Google Play follows later.
- Store-specific differences remain configuration/integration differences rather than separate source branches.

Google Play App Signing/upload-key decisions are finalized when Play Console access is available.

## Rotation and recovery

The project owner is responsible for an offline backup of the original signing key and passwords.

Before public store publication, document:

- secure offline backup location;
- key recovery procedure;
- trusted `ANDROID_CERT_SHA256` value;
- Google Play upload-key/app-signing-key split, when applicable;
- RuStore key replacement/recovery rules current at publication time.
