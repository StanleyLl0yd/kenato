#!/usr/bin/env python3
"""Pin the M4.5 numeric 0.0.1 release and signing contract."""

from __future__ import annotations

import re
from pathlib import Path

errors: list[str] = []


def read(path: str) -> str:
    candidate = Path(path)
    if not candidate.is_file():
        errors.append(f"missing required M4.5 release file: {path}")
        return ""
    return candidate.read_text(encoding="utf-8")


def require(path: str, *fragments: str) -> None:
    text = read(path)
    for fragment in fragments:
        if fragment not in text:
            errors.append(f"{path}: missing required M4.5 release evidence: {fragment}")


def forbid(path: str, *fragments: str) -> None:
    text = read(path)
    for fragment in fragments:
        if fragment in text:
            errors.append(f"{path}: forbidden/stale release fragment remains: {fragment}")


build = read("android/app/build.gradle.kts")
if build:
    version_name = re.search(r'^\s*versionName\s*=\s*"([^"]+)"', build, re.MULTILINE)
    version_code = re.search(r"^\s*versionCode\s*=\s*([0-9]+)", build, re.MULTILINE)
    if not version_name or version_name.group(1) != "0.0.1":
        errors.append("android/app/build.gradle.kts: M4.5 release versionName must be 0.0.1")
    if not version_code or version_code.group(1) != "1":
        errors.append("android/app/build.gradle.kts: first published release must use versionCode 1")

workflow = read(".github/workflows/release-android.yml")
if workflow:
    numeric_tag_regex = r'^v[0-9]+\.[0-9]+\.[0-9]+$'
    if workflow.count(numeric_tag_regex) < 2:
        errors.append(
            ".github/workflows/release-android.yml: numeric vX.Y.Z tag validation must protect both request and prior-tag scanning"
        )
    for forbidden_event in ("pull_request:", "pull_request_target:", "workflow_dispatch:"):
        if forbidden_event in workflow:
            errors.append(
                f".github/workflows/release-android.yml: privileged release workflow must not use {forbidden_event}"
            )

require(
    ".github/workflows/release-android.yml",
    'tags:\n      - "v*"',
    'test "$RELEASE_TAG" = "v$version_name"',
    'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
    'required_workflows=("CI" "Security and Quality" "Gitleaks" "CodeQL")',
    "environment: release",
    "ANDROID_KEYSTORE_BASE64",
    "ANDROID_KEYSTORE_PASSWORD",
    "ANDROID_KEY_ALIAS",
    "ANDROID_KEY_PASSWORD",
    "ANDROID_CERT_SHA256",
    "keytool -list",
    "apksigner\" verify --verbose --print-certs",
    "jarsigner -verify",
    "sha256sum --check",
    "actions/attest@",
    "actions/download-artifact@",
    'gh release create "$RELEASE_TAG"',
    "--verify-tag",
    'gh release upload "$RELEASE_TAG"',
    'gh release edit "$RELEASE_TAG" --draft=false --latest',
    'rm -f "$RUNNER_TEMP/kenato-release.jks"',
)
forbid(
    ".github/workflows/release-android.yml",
    "-rc.",
    "-alpha",
    "-beta",
)

require(
    "docs/release/RELEASES.md",
    "first release: `0.0.1`",
    "subsequent releases: `0.0.2`, `0.0.3`, and so on",
    "does not use alpha, beta, release-candidate, or other prerelease suffixes",
    "matching exactly `vX.Y.Z`",
)
require(
    "docs/release/ANDROID_SIGNING.md",
    "For the first signed release (`0.0.1`)",
    "ANDROID_CERT_SHA256",
    "accepts only immutable `vX.Y.Z` tag pushes",
    "creates a GitHub Release",
)
require(
    "README.md",
    "first closed messaging-only `0.0.1` release",
    "no alpha/beta/rc suffixes",
    "M5 remains blocked until #59 is complete",
)
require(
    "CONTRIBUTING.md",
    "first closed messaging-only `0.0.1` release",
    "Do not introduce alpha, beta, rc, or other prerelease suffixes",
)
for path in (
    "README.md",
    "CONTRIBUTING.md",
    "docs/release/RELEASES.md",
    "docs/release/ANDROID_SIGNING.md",
):
    forbid(path, "0.1.0-alpha.1")

if errors:
    for error in errors:
        print(f"ERROR: {error}")
    raise SystemExit(1)

print("M4.5 numeric release policy OK")
