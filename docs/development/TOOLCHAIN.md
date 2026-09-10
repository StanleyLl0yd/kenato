# Development Toolchain

Current post-M2 baseline:

- Android Gradle Plugin: 9.4.0
- Gradle Wrapper: 9.7.1
- Kotlin / Compose compiler plugin: 2.4.20 (AGP 9 built-in Kotlin; no `org.jetbrains.kotlin.android` plugin)
- JDK: 17
- compileSdk: 37
- targetSdk: 37
- minSdk: 26
- Compose BOM: 2026.08.00
- ZXing Core: 3.5.4 (M2 QR encoding only; no scanner SDK)
- Go: 1.27.1 in CI
- Protocol Buffers Go runtime: `google.golang.org/protobuf` 1.36.12
- SQLite Go driver: pure-Go `modernc.org/sqlite` 1.58.0
- Go vulnerability scanner: govulncheck `709015412431dd2b5b28a53c06c70bc02d49074c` (2026-09-08 upstream revision; pinned because released v1.1.4 predates Go 1.27 AST support)
- SAST: Semgrep CE 1.172.0 (required PR/main gate)
- Kotlin/JVM defense-in-depth: Qodana JVM Community 2026.2.1 (scheduled/manual)

The committed Gradle Wrapper is the authoritative Gradle entry point for local and CI builds. The committed `server/go.mod` and `server/go.sum` are the authoritative Go dependency graph; CI runs `go mod tidy` and requires those files to remain unchanged.

The SQLite dependency is intentionally pure Go so `kenato-server` remains cross-buildable for the ARM64 OCI target with `CGO_ENABLED=0`. CI verifies both linux/amd64 and linux/arm64 server builds.

The ZXing dependency is limited to deterministic QR matrix generation for canonical M2 invite URIs. Camera capture/scanning is not introduced by M2.

Release signing material must never be committed. The tag-triggered signed-release pipeline is committed and gated; production signing secrets and certificate trust material must be provisioned only in the protected `release` environment before the first production-signed release.

## CodeQL compatibility

Re-checked 2026-09-10: current CodeQL documentation supports Kotlin through the 2.4.1x line, while Kenato intentionally uses Kotlin 2.4.20.

Kenato does not downgrade the application toolchain solely to satisfy a scanner version ceiling. Until CodeQL adds Kotlin 2.4.20 support:

- CodeQL analyzes Go and GitHub Actions;
- Semgrep remains the required complementary SAST gate for Kotlin source;
- Qodana provides scheduled/manual Kotlin/JVM defense-in-depth analysis;
- Android CI performs Kotlin compilation, lint, unit tests, debug build, unsigned release APK build, and unsigned release AAB build;
- Kotlin CodeQL analysis is re-enabled when the deployed CodeQL extractor supports the project Kotlin version.
