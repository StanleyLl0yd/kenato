#!/usr/bin/env python3
import re
import subprocess
import tomllib
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
native_manifest_path = Path("native/session-engine/Cargo.toml")
native_lock_path = Path("native/session-engine/Cargo.lock")
native_toolchain_path = Path("native/session-engine/rust-toolchain.toml")
jni_manifest_path = Path("native/session-jni/Cargo.toml")
jni_lock_path = Path("native/session-jni/Cargo.lock")
jni_toolchain_path = Path("native/session-jni/rust-toolchain.toml")
jni_source_path = Path("native/session-jni/src/lib.rs")

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_POLICY_XML_BYTES = 64 * 1024
FORBIDDEN_XML_DECLARATIONS = (b"<!DOCTYPE", b"<!ENTITY")
EXPECTED_JNI_EXPORTS = {
    "Java_com_sl_kenato_session_NativeSessionBridge_createAccount",
    "Java_com_sl_kenato_session_NativeSessionBridge_inspectAccount",
    "Java_com_sl_kenato_session_NativeSessionBridge_markAccountKeysPublished",
    "Java_com_sl_kenato_session_NativeSessionBridge_generateAccountOneTimeKeys",
    "Java_com_sl_kenato_session_NativeSessionBridge_createOutboundSession",
    "Java_com_sl_kenato_session_NativeSessionBridge_createInboundSession",
    "Java_com_sl_kenato_session_NativeSessionBridge_encryptSession",
    "Java_com_sl_kenato_session_NativeSessionBridge_decryptSession",
}


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

if not native_manifest_path.exists():
    errors.append("native/session-engine: Cargo.toml is required for M3")
else:
    try:
        native_manifest = tomllib.loads(native_manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors.append(f"native/session-engine: unable to parse Cargo.toml: {error}")
    else:
        package = native_manifest.get("package", {})
        if package.get("rust-version") != "1.85":
            errors.append("native/session-engine: rust-version must remain 1.85")
        if package.get("edition") != "2024":
            errors.append("native/session-engine: Rust edition must remain 2024")
        if package.get("publish") is not False:
            errors.append("native/session-engine: publishing to crates.io must remain disabled")

        dependencies = native_manifest.get("dependencies", {})
        vodozemac = dependencies.get("vodozemac")
        if not isinstance(vodozemac, dict):
            errors.append("native/session-engine: vodozemac dependency must use an explicit table")
        else:
            if vodozemac.get("version") != "=0.10.0":
                errors.append("native/session-engine: vodozemac must remain exactly pinned to =0.10.0")
            if vodozemac.get("default-features") is not False:
                errors.append("native/session-engine: vodozemac default features must remain disabled")
            if vodozemac.get("features"):
                errors.append("native/session-engine: vodozemac optional features are not approved in M3")

        rust_lints = native_manifest.get("lints", {}).get("rust", {})
        if rust_lints.get("unsafe_code") != "deny":
            errors.append("native/session-engine: unsafe Rust must remain denied in the crypto core")

if not native_toolchain_path.exists():
    errors.append("native/session-engine: rust-toolchain.toml is required")
else:
    try:
        toolchain = tomllib.loads(native_toolchain_path.read_text(encoding="utf-8")).get("toolchain", {})
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors.append(f"native/session-engine: unable to parse rust-toolchain.toml: {error}")
    else:
        if toolchain.get("channel") != "1.85.0":
            errors.append("native/session-engine: CI/toolchain channel must remain exactly 1.85.0")
        components = toolchain.get("components", [])
        if sorted(components) != ["clippy", "rustfmt"]:
            errors.append("native/session-engine: rustfmt and clippy must remain pinned toolchain components")

if not native_lock_path.exists():
    errors.append("native/session-engine: Cargo.lock must be present and committed")

if not jni_manifest_path.exists():
    errors.append("native/session-jni: Cargo.toml is required for the Android M3 boundary")
else:
    try:
        jni_manifest = tomllib.loads(jni_manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors.append(f"native/session-jni: unable to parse Cargo.toml: {error}")
    else:
        package = jni_manifest.get("package", {})
        if package.get("rust-version") != "1.85":
            errors.append("native/session-jni: rust-version must remain 1.85")
        if package.get("edition") != "2021":
            errors.append("native/session-jni: Rust edition must remain 2021 until the JNI export policy is re-reviewed")
        if package.get("publish") is not False:
            errors.append("native/session-jni: publishing to crates.io must remain disabled")
        if jni_manifest.get("lib", {}).get("crate-type") != ["cdylib", "rlib"]:
            errors.append("native/session-jni: crate types must remain cdylib and rlib")

        dependencies = jni_manifest.get("dependencies", {})
        jni_dependency = dependencies.get("jni")
        if not isinstance(jni_dependency, dict):
            errors.append("native/session-jni: jni dependency must use an explicit table")
        else:
            if jni_dependency.get("version") != "=0.21.1":
                errors.append("native/session-jni: jni must remain exactly pinned to =0.21.1")
            if jni_dependency.get("default-features") is not False:
                errors.append("native/session-jni: jni default features must remain disabled")
            if jni_dependency.get("features"):
                errors.append("native/session-jni: jni optional features are not approved in M3")

        engine_dependency = dependencies.get("kenato-session-engine")
        if not isinstance(engine_dependency, dict) or engine_dependency.get("path") != "../session-engine":
            errors.append("native/session-jni: session engine must remain a local path dependency")
        if dependencies.get("zeroize") != "=1.8.2":
            errors.append("native/session-jni: zeroize must remain exactly pinned to =1.8.2")

        rust_lints = jni_manifest.get("lints", {}).get("rust", {})
        if rust_lints.get("unsafe_code") != "allow":
            errors.append("native/session-jni: reviewed JNI export exception must remain explicit")
        clippy_lints = jni_manifest.get("lints", {}).get("clippy", {})
        for lint_name in ("all", "pedantic", "unwrap_used", "expect_used", "panic"):
            if clippy_lints.get(lint_name) != "deny":
                errors.append(f"native/session-jni: clippy {lint_name} must remain denied")

if not jni_toolchain_path.exists():
    errors.append("native/session-jni: rust-toolchain.toml is required")
else:
    try:
        toolchain = tomllib.loads(jni_toolchain_path.read_text(encoding="utf-8")).get("toolchain", {})
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors.append(f"native/session-jni: unable to parse rust-toolchain.toml: {error}")
    else:
        if toolchain.get("channel") != "1.85.0":
            errors.append("native/session-jni: toolchain channel must remain exactly 1.85.0")
        components = toolchain.get("components", [])
        if sorted(components) != ["clippy", "rustfmt"]:
            errors.append("native/session-jni: rustfmt and clippy must remain pinned toolchain components")

if not jni_lock_path.exists():
    errors.append("native/session-jni: Cargo.lock must be present and committed")

if not jni_source_path.exists():
    errors.append("native/session-jni: src/lib.rs is required")
else:
    jni_source = jni_source_path.read_text(encoding="utf-8")
    if re.search(r"\bunsafe\s+fn\b", jni_source) or re.search(r"\bunsafe\s*\{", jni_source):
        errors.append("native/session-jni: unsafe functions or blocks are forbidden")
    if "#[export_name" in jni_source or "#[link_section" in jni_source:
        errors.append("native/session-jni: alternate manual export attributes are forbidden")
    exports = set(re.findall(r'pub\s+extern\s+"system"\s+fn\s+(Java_[A-Za-z0-9_]+)', jni_source))
    if exports != EXPECTED_JNI_EXPORTS:
        errors.append("native/session-jni: JNI export set differs from the reviewed M3 boundary")
    if jni_source.count("#[no_mangle]") != len(EXPECTED_JNI_EXPORTS):
        errors.append("native/session-jni: each reviewed JNI export must have exactly one no_mangle attribute")

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

if "target/" not in gitignore_patterns:
    errors.append(".gitignore: Rust target/ output must be ignored")

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
