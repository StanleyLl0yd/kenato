# Android Release Signing

Kenato release signing is designed so signing material never enters the repository.

## Required GitHub environment

Create a protected GitHub Actions environment named:

`release`

Store these secrets in that environment:

- `ANDROID_KEYSTORE_BASE64` — the complete keystore encoded as base64;
- `ANDROID_KEYSTORE_PASSWORD`;
- `ANDROID_KEY_ALIAS`;
- `ANDROID_KEY_PASSWORD`.

Do not store the raw keystore, passwords, aliases, or decoded temporary files in source control.

## Workflow behavior

The release workflow:

1. checks out the exact tagged commit;
2. sets up JDK 17 and the committed Gradle Wrapper;
3. decodes the keystore into `$RUNNER_TEMP`;
4. exports only the environment variables consumed by Gradle;
5. runs release lint/tests and builds both APK and AAB;
6. verifies that both artifacts are signed;
7. creates SHA-256 checksums;
8. uploads the release artifacts to the workflow run.

The temporary runner is discarded after the job.

## Local signing

For a local release build, keep the keystore outside the repository and export:

```bash
export KENATO_KEYSTORE_PATH=/secure/path/kenato.jks
export KENATO_KEYSTORE_PASSWORD='...'
export KENATO_KEY_ALIAS='...'
export KENATO_KEY_PASSWORD='...'

./gradlew :android:app:assembleRelease :android:app:bundleRelease
```

Never add these variables to committed shell scripts, Gradle files, or `.env` files.

## Store strategy

The same application ID and source commit are used for RuStore and Google Play.

- RuStore is the first publication target.
- Google Play follows later.
- Store-specific differences must remain configuration/integration differences rather than separate source branches.

Google Play App Signing/upload-key decisions are finalized when Play Console access is available.

## Rotation and recovery

The project owner is responsible for an offline backup of the original signing key and passwords.

Before the first public release, document:

- secure offline backup location;
- key recovery procedure;
- Google Play upload-key/app-signing-key split, when applicable;
- RuStore key replacement/recovery rules current at publication time.
