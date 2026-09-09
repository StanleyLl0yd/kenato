# Development Toolchain

M0 baseline:

- Android Gradle Plugin: 9.4.0
- Gradle: 9.6.1
- Kotlin / Compose compiler plugin: 2.4.20
- JDK: 17
- compileSdk: 37
- targetSdk: 37
- minSdk: 26
- Compose BOM: 2026.08.00
- Go: 1.27.1 in CI

The repository currently uses the Gradle executable provisioned by CI rather than a committed Gradle Wrapper. A wrapper should be generated and committed before M0 is closed so local and CI invocation use the same verified distribution.

Release signing material must never be committed. Signing/release architecture is defined separately before the first signed release pipeline is enabled.
