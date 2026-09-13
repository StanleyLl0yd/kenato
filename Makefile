SHELL := /bin/bash

RUST_TOOLCHAIN ?= 1.85.0
PROTO_FILES := \
	protocol/kenato/v1/envelope.proto \
	protocol/kenato/v1/contact.proto \
	protocol/kenato/v1/session.proto

.PHONY: test test-protocol test-go test-rust test-security test-android
.NOTPARALLEL: test

test: test-protocol test-go test-rust test-security test-android

test-protocol:
	@command -v protoc >/dev/null || { echo "protoc is required" >&2; exit 1; }
	@command -v protolint >/dev/null || { echo "protolint is required" >&2; exit 1; }
	protoc --proto_path=protocol --descriptor_set_out=/tmp/kenato.pb $(PROTO_FILES)
	protolint lint protocol

test-go:
	@command -v go >/dev/null || { echo "go is required" >&2; exit 1; }
	@command -v govulncheck >/dev/null || { echo "govulncheck is required" >&2; exit 1; }
	cd server && go mod tidy
	git diff --exit-code -- server/go.mod server/go.sum
	cd server && files="$$(gofmt -l .)"; test -z "$$files" || { printf 'Unformatted Go files:\n%s\n' "$$files"; exit 1; }
	cd server && go test ./...
	cd server && go test -race ./...
	cd server && go vet ./...
	cd server && govulncheck ./...
	cd server && go build ./cmd/kenato-server
	cd server && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /tmp/kenato-server-arm64 ./cmd/kenato-server

test-rust:
	@command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
	@command -v cargo-audit >/dev/null || { echo "cargo-audit is required" >&2; exit 1; }
	cd native/session-engine && cargo +$(RUST_TOOLCHAIN) fmt --all -- --check
	cd native/session-engine && cargo +$(RUST_TOOLCHAIN) check --locked
	cd native/session-engine && cargo +$(RUST_TOOLCHAIN) clippy --locked --all-targets -- -D warnings
	cd native/session-engine && cargo +$(RUST_TOOLCHAIN) test --locked
	cd native/session-engine && cargo +$(RUST_TOOLCHAIN) build --locked --release
	cd native/session-jni && cargo +$(RUST_TOOLCHAIN) fmt --all -- --check
	cd native/session-jni && cargo +$(RUST_TOOLCHAIN) check --locked
	cd native/session-jni && cargo +$(RUST_TOOLCHAIN) clippy --locked --all-targets -- -D warnings
	cd native/session-jni && cargo +$(RUST_TOOLCHAIN) test --locked
	cd native/session-jni && cargo +$(RUST_TOOLCHAIN) build --locked --release
	cargo audit --file native/session-engine/Cargo.lock
	cargo audit --file native/session-jni/Cargo.lock
	git diff --exit-code -- native/session-engine/Cargo.lock native/session-engine/src/lib.rs native/session-jni/Cargo.lock native/session-jni/src/lib.rs

test-security:
	python3 scripts/verify_ci_supply_chain.py
	python3 scripts/verify_security_baseline.py
	python3 scripts/verify_repository_verification.py
	echo "7a9ce74cff467ca1bf60a4fcd9f05185acceda4d0f382434d393e17864262c5d  gradle/wrapper/gradle-wrapper.jar" | sha256sum -c -

test-android:
	bash scripts/build_android_native.sh
	./gradlew --no-daemon --stacktrace \
		:android:app:lintDebug \
		:android:app:lintRelease \
		:android:app:testDebugUnitTest \
		:android:app:assembleDebug \
		:android:app:assembleRelease \
		:android:app:bundleRelease
