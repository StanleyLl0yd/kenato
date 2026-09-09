#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

errors: list[str] = []

manifest = Path("android/app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
build = Path("android/app/build.gradle.kts").read_text(encoding="utf-8")
release = Path(".github/workflows/release-android.yml").read_text(encoding="utf-8")
gitignore = Path(".gitignore").read_text(encoding="utf-8")

required_manifest = {
    'android:allowBackup="false"': "Android backups must be explicitly disabled",
    'android:usesCleartextTraffic="false"': "cleartext network traffic must be explicitly disabled",
}
for needle, message in required_manifest.items():
    if needle not in manifest:
        errors.append(f"AndroidManifest.xml: {message}")

if 'android:debuggable="true"' in manifest:
    errors.append("AndroidManifest.xml: debuggable=true is forbidden")

for field in ("namespace", "applicationId"):
    match = re.search(rf'^\s*{field}\s*=\s*"([^"]+)"', build, re.MULTILINE)
    if not match or match.group(1) != "com.sl.kenato":
        errors.append(f"build.gradle.kts: {field} must remain com.sl.kenato")

for forbidden in ("pull_request_target:", "pull_request:", "workflow_dispatch:"):
    if forbidden in release:
        errors.append(f"release-android.yml: privileged release workflow must not use {forbidden}")

for required in (
    'tags:',
    '"v*"',
    "environment: release",
    "id-token: write",
    "attestations: write",
    "ANDROID_CERT_SHA256",
    "actions/attest@",
):
    if required not in release:
        errors.append(f"release-android.yml: missing required release control: {required}")

required_ignores = (
    ".env",
    "*.jks",
    "*.keystore",
    "*.p12",
    "*.pfx",
    "*.pem",
    "*.key",
    "local.properties",
    "keystore.properties",
    "secrets.properties",
)
for pattern in required_ignores:
    if pattern not in gitignore:
        errors.append(f".gitignore: missing sensitive-file pattern {pattern}")

tracked = subprocess.run(
    ["git", "ls-files"],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()

sensitive_names = {
    ".env",
    "local.properties",
    "keystore.properties",
    "secrets.properties",
}
sensitive_suffixes = (".jks", ".keystore", ".p12", ".pfx", ".pem", ".key")

for name in tracked:
    path = Path(name)
    if path.name == ".env.example":
        continue
    if path.name in sensitive_names or path.name.lower().endswith(sensitive_suffixes):
        errors.append(f"tracked sensitive file is forbidden: {name}")

if errors:
    raise SystemExit("\n".join(errors))

print("Repository security baseline: OK")
