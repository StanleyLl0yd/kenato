# Android Release Signing

Kenato release signing is designed so production signing material never enters the repository or an ordinary pull-request workflow.

## Required GitHub environment

Use the protected GitHub Actions environment named:

`release`

The environment exists. Production signing secrets and certificate trust material remain unprovisioned until first production-signed release preparation.

When provisioning signing, store these environment secrets:

- `ANDROID_KEYSTORE_BASE64` — complete release keystore encoded as base64;
- `ANDROID_KEYSTORE_PASSWORD`;
- `ANDROID_KEY_ALIAS`;
- `ANDROID_KEY_PASSWORD`;
- `ANDROID_CERT_SHA256` — expected SHA-256 fingerprint of the release signing certificate.

The expected certificate fingerprint is kept as an environment-protected trust anchor so changing repository code alone cannot silently authorize a different signing identity.

Do not store the raw keystore, passwords, decoded temporary files, or production signing configuration in source control.

## Workflow behavior

The release workflow:

1. accepts only immutable-style `vX.Y.Z` or `vX.Y.Z-rc.N` tag pushes;
2. verifies the tagged commit is the exact requested revision and is contained in `main`;
3. requires successful `main` runs of CI, Semgrep/security, Gitleaks, and CodeQL for that exact commit;
4. verifies versionName/versionCode and `com.sl.kenato`;
5. verifies monotonically increasing release `versionCode`;
6. verifies the Gradle Wrapper before build execution;
7. decodes the keystore with restrictive permissions into `$RUNNER_TEMP`;
8. validates the expected keystore alias;
9. runs tests/lint and builds signed APK/AAB from the same source revision;
10. verifies APK/AAB signatures and matches both certificate fingerprints to `ANDROID_CERT_SHA256`;
11. creates and verifies SHA-256 artifact checksums;
12. creates OIDC-backed GitHub artifact attestations for APK and AAB;
13. uploads only the packaged release artifacts/checksum;
14. removes the temporary decoded keystore even when a later workflow step fails.

The ephemeral runner is discarded after the job as an additional containment boundary.

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

The same application ID and source commit are used for RuStore and Google Play.

- RuStore is the first publication target.
- Google Play follows later.
- Store-specific differences remain configuration/integration differences rather than separate source branches.

Google Play App Signing/upload-key decisions are finalized when Play Console access is available.

## Rotation and recovery

The project owner is responsible for an offline backup of the original signing key and passwords.

Before the first public release, document:

- secure offline backup location;
- key recovery procedure;
- trusted `ANDROID_CERT_SHA256` value;
- Google Play upload-key/app-signing-key split, when applicable;
- RuStore key replacement/recovery rules current at publication time.
