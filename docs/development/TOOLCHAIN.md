# Development Toolchain

Current post-M3 baseline:

- Android Gradle Plugin: 9.4.0
- Gradle Wrapper: 9.7.1
- Kotlin / Compose compiler plugin: 2.4.10 (AGP 9 built-in Kotlin; pinned to the newest release accepted by the currently published CodeQL 2.27.0 manual Kotlin extractor)
- JDK: 17
- compileSdk: 37
- targetSdk: 37
- minSdk: 26
- Compose BOM: 2026.08.00
- ZXing Core: 3.5.4 (M2 QR encoding only; no scanner SDK)
- Go: 1.27.1 in CI
- Protocol Buffers Go runtime: `google.golang.org/protobuf` 1.36.12
- protobuf lint: protolint 0.56.4
- SQLite Go driver: pure-Go `modernc.org/sqlite` 1.58.0
- Go vulnerability scanner: govulncheck `709015412431dd2b5b28a53c06c70bc02d49074c` (2026-09-08 upstream revision; pinned because released v1.1.4 predates Go 1.27 AST support)
- M3 session engine: vodozemac 0.10.0 behind Kenato-owned Rust/JNI crates
- native Rust toolchain: 1.85.0
- Android NDK: 28.2.13676358
- cargo-ndk: 4.1.2 (installed with Rust 1.86.0, building the Rust 1.85.0 native crates)
- Rust advisory scanner: cargo-audit 0.22.2, installed with Rust 1.88.0 because that cargo-audit release declares Rust 1.88 as its minimum toolchain; it audits both committed native Cargo lockfiles without changing the crates' Rust 1.85 baseline
- SAST: Semgrep CE 1.172.0 (required PR/main gate)
- CodeQL: Go (`manual`), Java/Kotlin (`manual` with a real Android debug build), Rust (`none`), and GitHub Actions (`none`)
- Kotlin/JVM defense-in-depth: Qodana JVM Community 2026.2.1 (scheduled/manual)
- repository-wide local/CI verification entry point: `make test`

The committed Gradle Wrapper is the authoritative Gradle entry point for local and CI builds. The committed `server/go.mod` and `server/go.sum` are the authoritative Go dependency graph; CI runs `go mod tidy` and requires those files to remain unchanged. The two committed native `Cargo.lock` files are authoritative for their Rust dependency graphs and are audited with the pinned cargo-audit release.

Rust verification must consume those committed lockfiles with `--locked`. Verification workflows must not run `cargo generate-lockfile` or `cargo update` before checking/building the native crates: doing so makes the dependency graph depend on the current registry index and can cause the same source commit to pass a PR and fail a later exact-main push when a newly published semver-compatible transitive release appears. `scripts/verify_ci_supply_chain.py` rejects those mutating Cargo-resolution commands in GitHub Actions verification paths.

The Kotlin 2.4.10 pin is a verification-compatibility constraint, not a product downgrade. The published CodeQL 2.27.0 Java/Kotlin extractor rejects Kotlin 2.4.20 during manual extraction, while buildless `java-kotlin` analysis does not analyze Kotlin source. A Kotlin upgrade must therefore be reviewed together with the pinned CodeQL bundle/action so the required Java/Kotlin gate continues to analyze the actual Kotlin source rather than silently reducing coverage.

The SQLite dependency is intentionally pure Go so `kenato-server` remains cross-buildable for the ARM64 OCI target with `CGO_ENABLED=0`. CI verifies both linux/amd64 and linux/arm64 server builds.

The ZXing dependency is limited to deterministic QR matrix generation for canonical M2 invite URIs. Camera capture/scanning is not introduced by M2.

Release signing material must never be committed. The tag-triggered signed-release pipeline is committed and gated; production signing secrets and certificate trust material must be provisioned only in the protected `release` environment before the first production-signed release.

## Verification baseline

M3 #35 established the repository-wide verification baseline rather than weakening the existing gates. `make test` is the repository-wide contract and covers protobuf/protolint validation, Go module/format/test/race/vet/govulncheck/build checks, both Rust crates' format/check/clippy/test/build/advisory scans, security-policy verification, Gradle Wrapper verification, pinned native JNI build, and Android lint/unit/build/bundle verification.

M4 adds policy verification for the messaging protocol, mailbox, authenticated transport, Android messaging durability/privacy, and server lifecycle. The final M4 audit also pins shared Go/Android server-visible wire vectors and registry-independent Cargo lock verification.

CI also runs focused Android, Go, and protocol jobs. CodeQL analyzes Go, Java/Kotlin, Rust, and GitHub Actions. Java/Kotlin extraction installs the pinned Android SDK/NDK and native Rust tooling, builds the three reviewed JNI ABIs, and runs a real `:android:app:assembleDebug` under manual CodeQL build mode.

Dependency Review is a required PR gate for vulnerability and reviewed license-policy enforcement. Its explicit strong-copyleft deny policy prevents AGPL/GPL dependencies from silently constraining the pre-1.0 licensing decision reserved by ADR 0006; changing that policy requires explicit licensing review.

Semgrep remains a required complementary SAST gate and Qodana remains scheduled/manual JVM/Kotlin defense-in-depth; neither substitutes for the Java/Kotlin CodeQL job.
