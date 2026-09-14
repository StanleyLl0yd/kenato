#!/usr/bin/env python3
"""Verify repository-wide verification and dependency-monitoring controls."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

errors: list[str] = []


def read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"{path}: unable to read: {error}")
        return ""


manifest_text = read("native/session-engine/Cargo.toml")
if manifest_text:
    try:
        manifest = tomllib.loads(manifest_text)
    except tomllib.TOMLDecodeError as error:
        errors.append(f"native/session-engine/Cargo.toml: invalid TOML: {error}")
    else:
        if manifest.get("dependencies", {}).get("rand") != "=0.8.6":
            errors.append(
                "native/session-engine: rand must remain exactly pinned to =0.8.6 or a reviewed fixed successor"
            )

for lock_path in ("native/session-engine/Cargo.lock", "native/session-jni/Cargo.lock"):
    lock = read(lock_path)
    if not lock:
        continue
    if 'name = "rand"\nversion = "0.8.5"' in lock:
        errors.append(f"{lock_path}: vulnerable rand 0.8.5 must not be locked")
    if 'name = "rand"\nversion = "0.8.6"' not in lock:
        errors.append(f"{lock_path}: reviewed rand 0.8.6 lock entry is required")

versions_text = read("gradle/libs.versions.toml")
if versions_text:
    try:
        versions = tomllib.loads(versions_text)
    except tomllib.TOMLDecodeError as error:
        errors.append(f"gradle/libs.versions.toml: invalid TOML: {error}")
    else:
        compose_plugin = versions.get("plugins", {}).get("kotlin-compose")
        if not isinstance(compose_plugin, dict) or compose_plugin.get("version") != "2.4.10":
            errors.append(
                "gradle/libs.versions.toml: Kotlin Compose must remain at reviewed CodeQL-compatible 2.4.10 "
                "until the pinned CodeQL bundle is reviewed for a newer Kotlin release"
            )

dependabot = read(".github/dependabot.yml")
for directory in ("/native/session-engine", "/native/session-jni"):
    pattern = rf'package-ecosystem:\s*cargo\s+directory:\s*"{re.escape(directory)}"'
    if not re.search(pattern, dependabot):
        errors.append(f"dependabot.yml: Cargo monitoring is required for {directory}")

dependency_review = read(".github/workflows/dependency-review.yml")
for fragment in ("license-check: true", "deny-licenses: >-"):
    if fragment not in dependency_review:
        errors.append(f"dependency-review.yml: missing license-policy control {fragment!r}")
for license_id in (
    "AGPL-1.0",
    "AGPL-1.0-only",
    "AGPL-1.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "GPL-1.0",
    "GPL-1.0-only",
    "GPL-1.0-or-later",
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
):
    if not re.search(rf"(?<![A-Za-z0-9.-]){re.escape(license_id)}(?![A-Za-z0-9.-])", dependency_review):
        errors.append(f"dependency-review.yml: strong-copyleft license {license_id} must remain denied")

makefile = read("Makefile")
required_make_fragments = (
    "test: test-protocol test-go test-rust test-security test-android",
    "protolint lint protocol",
    "go test -race ./...",
    "go vet ./...",
    "govulncheck ./...",
    "cargo audit --file native/session-engine/Cargo.lock",
    "cargo audit --file native/session-jni/Cargo.lock",
    ":android:app:lintRelease",
    ":android:app:testDebugUnitTest",
    "scripts/verify_security_baseline.py",
)
for fragment in required_make_fragments:
    if fragment not in makefile:
        errors.append(f"Makefile: repository-wide test contract is missing {fragment!r}")

protolint = read(".protolint.yaml")
if "all_default: true" not in protolint:
    errors.append(".protolint.yaml: all default protobuf style rules must remain enabled")
if re.search(r"(?m)^\s*remove:\s*$", protolint):
    errors.append(".protolint.yaml: default protobuf lint rules must not be globally removed")
for legacy_rule in ("FILE_HAS_COMMENT", "MESSAGES_HAVE_COMMENT", "FIELDS_HAVE_COMMENT"):
    if f"- id: {legacy_rule}" not in protolint:
        errors.append(f".protolint.yaml: legacy exemption for {legacy_rule} must remain explicit")
for timestamp_field in (
    "created_at_unix_seconds",
    "expires_at_unix_seconds",
    "redeemed_at_unix_seconds",
):
    if timestamp_field not in protolint:
        errors.append(f".protolint.yaml: stable wire field {timestamp_field} must remain an explicit preposition exception")

ci = read(".github/workflows/ci.yml")
required_ci_fragments = (
    "rustup toolchain install 1.88.0 --profile minimal",
    "cargo +1.88.0 install cargo-audit --version 0.22.2 --locked --force",
    "cargo audit --file native/session-engine/Cargo.lock",
    "cargo audit --file native/session-jni/Cargo.lock",
    "github.com/yoheimuta/protolint/cmd/protolint@v0.56.4",
    "make test-protocol",
    "name: Repository make test",
    'run: ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358" make test',
)
for fragment in required_ci_fragments:
    if fragment not in ci:
        errors.append(f"ci.yml: missing verification control {fragment!r}")

codeql = read(".github/workflows/codeql.yml")
for language, build_mode in (("go", "manual"), ("java-kotlin", "manual"), ("rust", "none"), ("actions", "none")):
    pattern = rf'- language: {re.escape(language)}\s+build_mode: {re.escape(build_mode)}'
    if not re.search(pattern, codeql):
        errors.append(f"codeql.yml: {language} must use build mode {build_mode}")
for fragment in (
    '"ndk;28.2.13676358"',
    "cargo +1.86.0 install cargo-ndk --version 4.1.2 --locked --force",
    'ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358" bash scripts/build_android_native.sh',
    "--no-build-cache",
    "--rerun-tasks",
    ":android:app:assembleDebug",
):
    if fragment not in codeql:
        errors.append(f"codeql.yml: Java/Kotlin extraction is missing {fragment!r}")

jni_bridge = read("native/session-jni/src/lib.rs")
if jni_bridge:
    if "impl Drop for SecretBytes" not in jni_bridge or "self.0.zeroize();" not in jni_bridge:
        errors.append("session-jni: SecretBytes must zeroize its native backing buffer on drop")
    if jni_bridge.count("let plaintext = SecretBytes::new(plaintext);") < 2:
        errors.append("session-jni: inbound/decrypted engine plaintext must enter zeroizing RAII storage before response encoding")
    for java_array in ("initial_plaintext", "plaintext"):
        pattern = (
            rf"SecretBytes::new\(read_bytes\(\s*env,\s*&{java_array},\s*"
            rf"MAX_PLAINTEXT_BYTES,\s*true,?\s*\)\?\)"
        )
        if not re.search(pattern, jni_bridge):
            errors.append(f"session-jni: Java {java_array} copies must be zeroized after native use")

state_store = read("android/app/src/main/java/com/sl/kenato/session/SessionStateStore.kt")
if state_store:
    open_read = state_store.find("file.openRead()")
    size_check = state_store.find("file.baseFile.length()")
    if open_read < 0:
        errors.append("SessionStateStore.kt: AtomicFile reads must use openRead() so pending backups are recovered")
    if "FileNotFoundException" not in state_store:
        errors.append("SessionStateStore.kt: missing-state handling must distinguish FileNotFoundException")
    if open_read >= 0 and (size_check < 0 or size_check < open_read):
        errors.append("SessionStateStore.kt: base-file size validation must happen after AtomicFile.openRead() recovery")

session_schema = read("server/internal/contact/session_schema.go")
if "session_inits_redeemer_generation_guard" not in session_schema:
    errors.append("session_schema.go: atomic redeemer-generation guard trigger is required")

session_generation_tests = read("server/internal/contact/session_generation_init_test.go")
if "TestStoreRejectsStaleRedeemerGenerationAfterRollover" not in session_generation_tests:
    errors.append("session_generation_init_test.go: stale redeemer-generation store regression test is required")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("Repository verification policy OK")
