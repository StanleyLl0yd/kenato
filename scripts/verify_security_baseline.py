#!/usr/bin/env python3
import re
import subprocess
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
from pathlib import Path

errors: list[str] = []

manifest_path = Path("android/app/src/main/AndroidManifest.xml")
build = Path("android/app/build.gradle.kts").read_text(encoding="utf-8")
release = Path(".github/workflows/release-android.yml").read_text(encoding="utf-8")
gitignore = Path(".gitignore").read_text(encoding="utf-8")
versions = Path("gradle/libs.versions.toml").read_text(encoding="utf-8")
wrapper = Path("gradle/wrapper/gradle-wrapper.properties").read_text(encoding="utf-8")
go_mod = Path("server/go.mod").read_text(encoding="utf-8")

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_POLICY_XML_BYTES = 64 * 1024
FORBIDDEN_XML_DECLARATIONS = (b"<!DOCTYPE", b"<!ENTITY")


def parse_xml(path: Path) -> ET.Element | None:
    try:
        if path.stat().st_size > MAX_POLICY_XML_BYTES:
            errors.append(f"Android: {path} exceeds the policy XML size limit")
            return None
        raw = path.read_bytes()
    except OSError as error:
        errors.append(f"Android: unable to read {path}: {error}")
        return None

    upper = raw.upper()
    if any(marker in upper for marker in FORBIDDEN_XML_DECLARATIONS):
        errors.append(f"Android: {path} must not contain DTD or entity declarations")
        return None

    try:
        return ET.fromstring(raw)
    except ET.ParseError as error:
        errors.append(f"Android: unable to parse {path}: {error}")
        return None


manifest = parse_xml(manifest_path)
if manifest is not None:
    if manifest.tag != "manifest":
        errors.append("AndroidManifest.xml: root must be manifest")
    application_nodes = manifest.findall("application")
    if len(application_nodes) != 1:
        errors.append("AndroidManifest.xml: exactly one application element is required")
    else:
        application = application_nodes[0]
        required_manifest = {
            f"{ANDROID_NS}allowBackup": ("false", "Android backups must be explicitly disabled"),
            f"{ANDROID_NS}dataExtractionRules": (
                "@xml/data_extraction_rules",
                "Android 12+ backup and device-transfer rules must be explicit",
            ),
            f"{ANDROID_NS}fullBackupContent": (
                "@xml/backup_rules",
                "Android 11-and-lower backup rules must be explicit",
            ),
            f"{ANDROID_NS}usesCleartextTraffic": (
                "false",
                "cleartext network traffic must be explicitly disabled",
            ),
        }
        for attribute, (expected, message) in required_manifest.items():
            if application.get(attribute) != expected:
                errors.append(f"AndroidManifest.xml: {message}")

        if application.get(f"{ANDROID_NS}debuggable") == "true":
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


def validate_backup_section(path: Path, name: str, section: ET.Element) -> None:
    if any(node.tag == "include" for node in section.iter()):
        errors.append(f"Android: {path.name} {name} must not include app data")

    excluded = {
        node.attrib.get("domain")
        for node in section.findall("exclude")
        if node.attrib.get("path") == "."
    }
    missing_domains = required_backup_domains - excluded
    if missing_domains:
        errors.append(
            f"Android: {path.name} {name} does not exclude: "
            + ", ".join(sorted(missing_domains))
        )


def validate_backup_rules(
    path: Path,
    expected_root: str,
    section_names: tuple[str, ...],
) -> None:
    root = parse_xml(path)
    if root is None:
        return
    if root.tag != expected_root:
        errors.append(f"Android: {path.name} root must be {expected_root}")
        return

    if not section_names:
        validate_backup_section(path, expected_root, root)
        return

    for name in section_names:
        matching = root.findall(name)
        if len(matching) != 1:
            errors.append(f"Android: {path.name} must contain exactly one {name} section")
            continue
        validate_backup_section(path, name, matching[0])


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
    "tags:",
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

required_ignores = {
    ".env",
    ".env.*",
    ".envrc",
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
}
gitignore_patterns = {
    line.strip()
    for line in gitignore.splitlines()
    if line.strip() and not line.lstrip().startswith("#")
}
missing_ignores = required_ignores - gitignore_patterns
for pattern in sorted(missing_ignores):
    errors.append(f".gitignore: missing sensitive-file pattern {pattern}")

tracked = subprocess.run(
    ["git", "ls-files"],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()

sensitive_names = {
    ".env",
    ".envrc",
    "local.properties",
    "keystore.properties",
    "secrets.properties",
}
sensitive_suffixes = (".jks", ".keystore", ".p12", ".pfx", ".pkcs12", ".pem", ".key")

for name in tracked:
    path = Path(name)
    lower_name = path.name.lower()
    if path.name == ".env.example":
        continue
    if (
        lower_name in sensitive_names
        or lower_name.startswith(".env.")
        or lower_name.endswith(sensitive_suffixes)
    ):
        errors.append(f"tracked sensitive file is forbidden: {name}")

if errors:
    raise SystemExit("\n".join(errors))

print("Repository security baseline: OK")
