#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

errors: list[str] = []

manifest = Path("android/app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
build = Path("android/app/build.gradle.kts").read_text(encoding="utf-8")
release = Path(".github/workflows/release-android.yml").read_text(encoding="utf-8")
gitignore = Path(".gitignore").read_text(encoding="utf-8")
versions = Path("gradle/libs.versions.toml").read_text(encoding="utf-8")
wrapper = Path("gradle/wrapper/gradle-wrapper.properties").read_text(encoding="utf-8")
go_mod = Path("server/go.mod").read_text(encoding="utf-8")

required_manifest = {
    'android:allowBackup="false"': "Android backups must be explicitly disabled",
    'android:dataExtractionRules="@xml/data_extraction_rules"': "Android 12+ backup and device-transfer rules must be explicit",
    'android:fullBackupContent="@xml/backup_rules"': "Android 11-and-lower backup rules must be explicit",
    'android:usesCleartextTraffic="false"': "cleartext network traffic must be explicitly disabled",
}
for needle, message in required_manifest.items():
    if needle not in manifest:
        errors.append(f"AndroidManifest.xml: {message}")

if 'android:debuggable="true"' in manifest:
    errors.append("AndroidManifest.xml: debuggable=true is forbidden")

required_backup_domains = {
    "root",
    "file",
    "database",
    "sharedpref",
    "external",
    "device_root",
    "device_file",
    "device_database",
    "device_sharedpref",
}


def validate_backup_rules(
    path: Path,
    expected_root: str,
    section_names: tuple[str, ...],
) -> None:
    if not path.is_file():
        errors.append(f"Android: {path.name} is required")
        return

    text = path.read_text(encoding="utf-8")
    if f"<{expected_root}>" not in text or f"</{expected_root}>" not in text:
        errors.append(f"Android: {path.name} root must be {expected_root}")
        return

    sections: list[tuple[str, str]] = []
    if section_names:
        for name in section_names:
            opening = f"<{name}>"
            closing = f"</{name}>"
            if opening not in text or closing not in text:
                errors.append(f"Android: missing {name} backup rules")
                continue
            sections.append((name, text.split(opening, 1)[1].split(closing, 1)[0]))
    else:
        sections.append((path.name, text))

    for name, section in sections:
        if "<include " in section:
            errors.append(f"Android: {name} must not include app data")

        missing_domains = {
            domain
            for domain in required_backup_domains
            if f'<exclude domain="{domain}" path="." />' not in section
        }
        if missing_domains:
            errors.append(
                f"Android: {name} does not exclude: "
                + ", ".join(sorted(missing_domains))
            )


validate_backup_rules(
    Path("android/app/src/main/res/xml/data_extraction_rules.xml"),
    "data-extraction-rules",
    ("cloud-backup", "device-transfer"),
)
validate_backup_rules(
    Path("android/app/src/main/res/xml/backup_rules.xml"),
    "full-backup-content",
    (),
)

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

if re.search(r'(?im)^\s*[^#\n=]+\s*=\s*"[^"]*(?:\+|latest\.|snapshot)[^"]*"', versions):
    errors.append("libs.versions.toml: dynamic dependency versions are forbidden")

if "distributionSha256Sum=" not in wrapper:
    errors.append("gradle-wrapper.properties: Gradle distribution SHA-256 is required")

if re.search(r"(?m)^\s*require\s+(?:\(|\S)", go_mod) and not Path("server/go.sum").exists():
    errors.append("server: go.sum must be committed when module dependencies are present")

required_ignores = (
    ".env",
    ".env.*",
    "*.jks",
    "*.keystore",
    "*.p12",
    "*.pfx",
    "*.pkcs12",
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
sensitive_suffixes = (".jks", ".keystore", ".p12", ".pfx", ".pkcs12", ".pem", ".key")

for name in tracked:
    path = Path(name)
    if path.name == ".env.example":
        continue
    if (
        path.name in sensitive_names
        or path.name.startswith(".env.")
        or path.name.lower().endswith(sensitive_suffixes)
    ):
        errors.append(f"tracked sensitive file is forbidden: {name}")

if errors:
    raise SystemExit("\n".join(errors))

print("Repository security baseline: OK")
