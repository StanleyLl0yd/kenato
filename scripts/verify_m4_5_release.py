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
    if "group: android-release-main" not in workflow:
        errors.append(
            ".github/workflows/release-android.yml: release attempts must serialize on one main publication group"
        )
    if "group: android-release-${{ github.sha }}" in workflow:
        errors.append(
            ".github/workflows/release-android.yml: SHA-scoped release concurrency permits cross-main publication races"
        )
    for forbidden_event in ("pull_request:", "pull_request_target:", "workflow_dispatch:"):
        if forbidden_event in workflow:
            errors.append(
                f".github/workflows/release-android.yml: privileged release workflow must not use {forbidden_event}"
            )

    test_step = workflow.find("      - name: Test and lint release source")
    restore_step = workflow.find("      - name: Restore and validate release keystore")
    signed_build_step = workflow.find("      - name: Build signed APK and AAB")
    if min(test_step, restore_step, signed_build_step) < 0:
        errors.append(
            ".github/workflows/release-android.yml: release test/signing steps must all be present"
        )
    elif not (test_step < restore_step < signed_build_step):
        errors.append(
            ".github/workflows/release-android.yml: test/lint must run before restoring signing material, and signing material must be restored before the signed build"
        )

    publish_step = workflow.find("      - name: Publish verified GitHub release")
    if publish_step < 0:
        errors.append(
            ".github/workflows/release-android.yml: ID-driven verified release publication step must be present"
        )

publisher = read("scripts/publish_android_release.sh")
if publisher:
    if publisher.count("git/ref/heads/main\" --jq '.object.sha'") < 1 or publisher.count("require_exact_main_and_tag") < 3:
        errors.append(
            "scripts/publish_android_release.sh: exact main/tag guard must run before release creation and again immediately before publication"
        )
    create_step = publisher.find('created="$(gh api "${create_args[@]}")"')
    upload_step = publisher.find('uploaded="$(curl')
    draft_verify_step = publisher.find('draft_json="$(gh api "repos/$GITHUB_REPOSITORY/releases/$release_id")"')
    publish_step = publisher.find("--method PATCH")
    published_verify_step = publisher.find('published_by_id="$(gh api "repos/$GITHUB_REPOSITORY/releases/$release_id")"')
    if min(create_step, upload_step, draft_verify_step, publish_step, published_verify_step) < 0:
        errors.append(
            "scripts/publish_android_release.sh: create, upload, draft verification, publication, and final verification must all be present"
        )
    elif not (create_step < upload_step < draft_verify_step < publish_step < published_verify_step):
        errors.append(
            "scripts/publish_android_release.sh: release publication must remain create -> upload -> verify draft -> publish -> verify published"
        )

require("Makefile", "python3 scripts/verify_m4_5_release.py", "python3 scripts/test_publish_android_release.py")
require(
    ".github/workflows/release-android.yml",
    'branches:\n      - main',
    'android/app/build.gradle.kts',
    '.github/workflows/release-android.yml',
    'RELEASE_TAG="v$version_name"',
    'test "$GITHUB_SHA" = "$(git rev-parse refs/remotes/origin/main)"',
    'required_workflows=("CI" "Security and Quality" "Gitleaks" "CodeQL")',
    "timeout-minutes: 25",
    "for attempt in $(seq 1 80); do",
    "if (( attempt < 80 )); then",
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
    'if published="$(gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG" 2>/dev/null)"; then',
    "Checkout publication controller",
    'ref: ${{ github.sha }}',
    "persist-credentials: false",
    "Publish verified GitHub release",
    "bash scripts/publish_android_release.sh",
    'rm -f "$RUNNER_TEMP/kenato-release.jks"',
)
require(
    "scripts/publish_android_release.sh",
    'set -euo pipefail',
    'trap cleanup_unpublished_draft EXIT',
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
    'gh api --method DELETE "repos/$GITHUB_REPOSITORY/releases/$release_id"',
    '"repos/$GITHUB_REPOSITORY/releases"',
    '-f "tag_name=$RELEASE_TAG"',
    '-f "target_commitish=$GITHUB_SHA"',
    '-F draft=true',
    '-F generate_release_notes=true',
    'https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets?name=$asset_name',
    '--data-binary "@$path"',
    'test "$remote_digest" = "$expected_digest"',
    'draft_json="$(gh api "repos/$GITHUB_REPOSITORY/releases/$release_id")"',
    '--method PATCH',
    '-F draft=false',
    '-f make_latest=true',
    'published_by_tag="$(gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG")"',
    'test "$(jq -r \'.object.type\' <<< "$tag_json")" = "commit"',
    'test "$(jq -r \'.object.sha\' <<< "$tag_json")" = "$GITHUB_SHA"',
)
forbid(
    "scripts/publish_android_release.sh",
    'gh release create',
    'gh release upload',
    '--paginate --slurp "repos/$GITHUB_REPOSITORY/releases?per_page=100"',
)

forbid(
    ".github/workflows/release-android.yml",
    "-rc.",
    "-alpha",
    "-beta",
    'releases/tags/$RELEASE_TAG" 2>/dev/null || true',
    "for attempt in $(seq 1 40); do",
    "      - name: Verify immutable release source",
    "      - name: Create or resume draft release",
    "      - name: Verify draft release source",
    "      - name: Publish release",
    'gh release edit "$RELEASE_TAG" --draft=false --latest',
    '--paginate --slurp "repos/$GITHUB_REPOSITORY/releases?per_page=100"',
    'gh release create "$RELEASE_TAG"',
    'gh release upload "$RELEASE_TAG"',
)

require(
    "ROADMAP.md",
    "## M4.5 — Closed Messaging Release `0.0.1`",
    "Status: **Active**; #59/M4.5 is the current release gate",
    "source version `0.0.1`, Android `versionCode = 1`, immutable tag `v0.0.1`",
    "Alpha, beta, rc, and other prerelease suffixes are not used",
    "M5 must not start until #59 is complete",
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
    "runs only on protected `main` pushes",
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
    "ROADMAP.md",
    "docs/release/RELEASES.md",
    "docs/release/ANDROID_SIGNING.md",
):
    forbid(path, "0.1.0-alpha.1")

if errors:
    for error in errors:
        print(f"ERROR: {error}")
    raise SystemExit(1)

print("M4.5 numeric release policy OK")
