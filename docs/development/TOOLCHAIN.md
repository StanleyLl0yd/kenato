# Development Toolchain

M0 baseline:

- Android Gradle Plugin: 9.4.0
- Gradle Wrapper: 9.6.1
- Kotlin / Compose compiler plugin: 2.4.20
- JDK: 17
- compileSdk: 37
- targetSdk: 37
- minSdk: 26
- Compose BOM: 2026.08.00
- Go: 1.27.1 in CI

The committed Gradle Wrapper is the authoritative Gradle entry point for local and CI builds.

Release signing material must never be committed. Signing/release architecture is defined separately before the first signed release pipeline is enabled.
