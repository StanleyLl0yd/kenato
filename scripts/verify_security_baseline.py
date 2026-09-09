#!/usr/bin/env python3
import re
import subprocess
import xml.etree.ElementTree as ET
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
    'android:usesCleartextTraffic="false"': "cleartext network traffic must be explicitly disabled",
}
for needle, message in required_manifest.items():
    if needle not in manifest:
        errors.append(f"AndroidManifest.xml: {message}")

if 'android:debuggable="true"' in manifest:
    errors.append("AndroidManifest.xml: debuggable=true is forbidden")

backup_rules_path = Path("android/app/src/main/res/xml/data_extraction_rules.xml")
if not backup_rules_path.is_file():
    errors.append("Android: data_extraction_rules.xml is required")
else:
    try:
        backup_rules = ET.parse(backup_rules_path).getroot()
    except ET.ParseError as exc:
        errors.append(f"Android: invalid data_extraction_rules.xml: {exc}")
    else:
        if backup_rules.tag != "data-extraction-rules":
            errors.append("Android: backup rules root must be data-extraction-rules")

        required_backup_domains = {"root", "file", "database", "sharedpref", "external"}
        for section_name in ("cloud-backup", "device-transfer"):
            section = backup_rules.find(section_name)
            if section is None:
                errors.append(f"Android: missing {section_name} backup rules")
                continue
            if section.findall("include"):
                errors.append(f"Android: {section_name} must not include app data")
            excluded_domains = {
                item.get("domain")
                for item in section.findall("exclude")
                if item.get("path") == "."
            }
            missing_domains = required_backup_domains - excluded_domains
            if missing_domains:
                errors.append(
                    f"Android: {section_name} does not exclude: "
                    + ", ".join(sorted(missing_domains))
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
