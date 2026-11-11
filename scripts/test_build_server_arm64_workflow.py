#!/usr/bin/env python3
"""Regression gate for the opt-in, main-only ARM64 backend build recipe."""
from pathlib import Path

workflow = Path(".github/workflows/build-server-arm64.yml").read_text(encoding="utf-8")
if "go 1.27.4" not in Path("server/go.mod").read_text(encoding="utf-8").splitlines():
    raise SystemExit("Go module must refuse unpatched 1.27.x local toolchains")
required = (
    "workflow_dispatch:",
    '''push:
    branches: [main]
    paths:
      - ".github/workflows/build-server-arm64.yml"''',
    "permissions: {}",
    'test "$GITHUB_REF" = "refs/heads/main"',
    'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
    'go-version: "1.27.4"',
    "GOTOOLCHAIN: local",
    "GOOS: linux",
    "GOARCH: arm64",
    'CGO_ENABLED: "0"',
    "go version | grep -Eq '^go version go1[.]27[.]3 linux/amd64$'",
    "go mod verify",
    "go test ./...",
    "-trimpath -buildvcs=true",
    '-o "$RUNNER_TEMP/kenato-server-linux-arm64"',
    'mv "$RUNNER_TEMP/kenato-server-linux-arm64" dist/kenato-server-linux-arm64',
    "readelf -h",
    "vcs.revision=$GITHUB_SHA",
    "sha256sum --check SHA256SUMS",
    "cat dist/SHA256SUMS",
    "PROVENANCE.txt",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "retention-days: 14",
)
# CI, CodeQL and the artifact producer must all consume the same patched Go.
# The server/go.mod language floor does not override the pinned build toolchain.
expected_pins = {
    ".github/workflows/build-server-arm64.yml": 1,
    ".github/workflows/ci.yml": 3,
    ".github/workflows/codeql.yml": 1,
}
for workflow_path, count in expected_pins.items():
    content = Path(workflow_path).read_text(encoding="utf-8")
    if content.count('go-version: "1.27.4"') != count or any(
        f'go-version: "{old}"' in content for old in ("1.27.2", "1.27.3")
    ):
        raise SystemExit(f"Go toolchain security pin drift: {workflow_path}")

for token in required:
    if token not in workflow:
        raise SystemExit(f"ARM64 verified-build workflow missing: {token}")
for forbidden in ("pull_request_target:", "ssh ", "scp ", "sudo systemctl", "secrets."):
    if forbidden in workflow:
        raise SystemExit(f"ARM64 build workflow must not contain: {forbidden}")
print("Verified ARM64 backend workflow policy: PASS")
