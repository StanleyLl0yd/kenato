#!/usr/bin/env python3
"""Regression gate for the opt-in, main-only ARM64 backend build recipe."""
from pathlib import Path

workflow = Path(".github/workflows/build-server-arm64.yml").read_text(encoding="utf-8")
required = (
    "workflow_dispatch:",
    "push:\\n    branches: [main]\\n    paths:\\n      - \\".github/workflows/build-server-arm64.yml\\"",
    "permissions: {}",
    'test "$GITHUB_REF" = "refs/heads/main"',
    'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
    'go-version: "1.27.2"',
    "GOTOOLCHAIN: local",
    "GOOS: linux",
    "GOARCH: arm64",
    'CGO_ENABLED: "0"',
    "go mod verify",
    "go test ./...",
    "-trimpath -buildvcs=true",
    '-o "$RUNNER_TEMP/kenato-server-linux-arm64"',
    'mv "$RUNNER_TEMP/kenato-server-linux-arm64" dist/kenato-server-linux-arm64',
    "readelf -h",
    "vcs.revision=$GITHUB_SHA",
    "sha256sum --check SHA256SUMS",
    "PROVENANCE.txt",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "retention-days: 14",
)
for token in required:
    if token not in workflow:
        raise SystemExit(f"ARM64 verified-build workflow missing: {token}")
for forbidden in ("pull_request_target:", "ssh ", "scp ", "sudo systemctl", "secrets."):
    if forbidden in workflow:
        raise SystemExit(f"ARM64 build workflow must not contain: {forbidden}")
print("Verified ARM64 backend workflow policy: PASS")
