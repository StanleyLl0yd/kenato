# Development Toolchain

M0 baseline:

- Android Gradle Plugin: 9.4.0
- Gradle Wrapper: 9.7.1
- Kotlin / Compose compiler plugin: 2.4.20 (AGP 9 built-in Kotlin; no `org.jetbrains.kotlin.android` plugin)
- JDK: 17
- compileSdk: 37
- targetSdk: 37
- minSdk: 26
- Compose BOM: 2026.08.00
- Go: 1.27.1 in CI
- Go vulnerability scanner: govulncheck `709015412431dd2b5b28a53c06c70bc02d49074c` (2026-09-08 upstream revision; pinned because released v1.1.4 predates Go 1.27 AST support)
- SAST: Semgrep CE 1.172.0 (required PR/main gate)
- Kotlin/JVM defense-in-depth: Qodana JVM Community 2026.2.1 (scheduled/manual)

The committed Gradle Wrapper is the authoritative Gradle entry point for local and CI builds.

Release signing material must never be committed. Signing/release architecture is defined separately before the first signed release pipeline is enabled.


## CodeQL compatibility

GitHub CodeQL 2.26.4 supports Kotlin only through 2.4.10, while Kenato intentionally uses Kotlin 2.4.20.

Kenato does not downgrade the application toolchain solely to satisfy a scanner version ceiling. Until CodeQL adds Kotlin 2.4.20 support:

- CodeQL analyzes Go and GitHub Actions;
- Android CI still performs Kotlin compilation, lint, debug build, unsigned release APK build, and unsigned release AAB build;
- Kotlin CodeQL analysis is re-enabled when the deployed CodeQL extractor supports the project Kotlin version.
