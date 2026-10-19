#!/usr/bin/env python3
"""Fail-closed M5 tripwire for unapproved production Android media activation.

This is a repository-source guard, NOT a resolved-classpath or binary CVE audit.
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID_NAME = "{http://schemas.android.com/apk/res/android}name"
ANDROID_FGS = "{http://schemas.android.com/apk/res/android}foregroundServiceType"
MAX_SOURCE = 4 * 1024 * 1024

BUILD_FILES = (
    "settings.gradle.kts",
    "build.gradle.kts",
    "android/app/build.gradle.kts",
    "gradle/libs.versions.toml",
)
WIRES = {
    "Makefile": "python3 scripts/verify_m5_media_boundary.py",
    ".github/workflows/ci.yml": "python3 scripts/verify_m5_media_boundary.py",
    ".github/workflows/release-android.yml": "python3 scripts/verify_m5_media_boundary.py",
}
FORBIDDEN_BUILD = re.compile(r"(?i)(?:webrtc|libjingle|livekit|jitsi)")
FORBIDDEN_SOURCE = re.compile(
    r"(?m)^\s*(?:import|package)\s+(?:org\.webrtc|livekit\.org\.webrtc)\b"
    r"|(?i:libjingle_peerconnection_so|System\.loadLibrary\s*\(\s*\"jingle)"
)
FORBIDDEN_PERMISSIONS = {
    "android.permission.RECORD_AUDIO",
    "android.permission.FOREGROUND_SERVICE_MICROPHONE",
}


def collect(root: Path) -> tuple[dict[str, bytes], list[str]]:
    """Read selected production inputs only; exclude generated build outputs."""
    selected: set[Path] = {root / relative for relative in (*BUILD_FILES, *WIRES)}
    source = root / "android/app/src"
    if source.is_dir():
        selected.update(source.rglob("AndroidManifest.xml"))
        selected.update(p for p in source.rglob("*")
                        if p.is_file() and p.suffix.lower() in {".aar", ".jar", ".so"})
    main = source / "main"
    if main.is_dir():
        selected.update(main.rglob("*.kt"))
        selected.update(main.rglob("*.java"))
    android = root / "android"
    if android.is_dir():
        selected.update(p for p in android.rglob("*.gradle.kts")
                        if "build" not in p.relative_to(android).parts)
        selected.update(p for p in android.rglob("*.gradle")
                        if "build" not in p.relative_to(android).parts)
    selected.update(root.glob("*.gradle"))
    selected.update(root.glob("*.gradle.kts"))
    snapshot: dict[str, bytes] = {}
    errors: list[str] = []
    for path in sorted(selected):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            errors.append(f"{relative}: symlink is not allowed for a policy input")
            continue
        try:
            if not path.is_file():
                if relative in (*BUILD_FILES, *WIRES):
                    errors.append(f"{relative}: required policy input missing")
                continue
            if path.stat().st_size > MAX_SOURCE:
                errors.append(f"{relative}: source exceeds safety size limit")
                continue
            snapshot[relative] = path.read_bytes()
        except OSError:
            errors.append(f"{relative}: unable to inspect policy input")
    return snapshot, errors


def inspect(snapshot: dict[str, bytes]) -> list[str]:
    errors: list[str] = []
    for name in (*BUILD_FILES, *WIRES):
        if name not in snapshot:
            errors.append(f"{name}: required boundary input missing")

    for path, raw in sorted(snapshot.items()):
        if path.endswith((".aar", ".jar", ".so")) and path.startswith("android/app/src/"):
            errors.append(f"{path}: vendored Android native/JAR/AAR binary requires review")
            continue
        if path.endswith(("AndroidManifest.xml",)) and path.startswith("android/app/src/"):
            if len(raw) > 65536 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                errors.append(f"{path}: unsafe or oversized manifest")
                continue
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                errors.append(f"{path}: malformed Android manifest")
                continue
            if root.tag != "manifest":
                errors.append(f"{path}: unexpected manifest root")
            for node in root.iter():
                if node.tag.startswith("uses-permission"):
                    permission = node.attrib.get(ANDROID_NAME)
                    if permission in FORBIDDEN_PERMISSIONS:
                        errors.append(f"{path}: unapproved microphone permission {permission}")
                foreground = node.attrib.get(ANDROID_FGS, "")
                if "microphone" in {item.strip() for item in foreground.split("|")}:
                    errors.append(f"{path}: unapproved microphone foreground service")
            continue

        if path.endswith((".gradle", ".gradle.kts", "libs.versions.toml")):
            if FORBIDDEN_BUILD.search(raw.decode("utf-8", errors="replace")):
                errors.append(f"{path}: production WebRTC/media dependency or plugin needs M5 approval")
        if path.startswith("android/app/src/main/") and path.endswith((".java", ".kt")):
            if FORBIDDEN_SOURCE.search(raw.decode("utf-8", errors="replace")):
                errors.append(f"{path}: production WebRTC/JNI source needs M5 approval")

    for path, command in WIRES.items():
        if path in snapshot:
            content = snapshot[path].decode("utf-8", errors="replace")
            if command not in content:
                errors.append(f"{path}: M5 pre-approval guard invocation removed")
    release = snapshot.get(".github/workflows/release-android.yml", b"").decode("utf-8", errors="replace")
    if release:
        check = release.find(WIRES[".github/workflows/release-android.yml"])
        signer = release.find("      - name: Restore and validate release keystore")
        if check < 0 or signer < 0 or check > signer:
            errors.append("release workflow: media gate must precede signing key restoration")
    return errors


def main() -> int:
    snapshot, read_errors = collect(Path(__file__).resolve().parent.parent)
    errors = read_errors + inspect(snapshot)
    if errors:
        for error in errors:
            print("M5 MEDIA BOUNDARY FAIL:", error, file=sys.stderr)
        return 1
    print("M5 media boundary OK: no known WebRTC activation or microphone additions in reviewed sources")
    print("Scope: source-only tripwire, not a resolved dependency, merged-manifest or CVE approval")
    return 0


if __name__ == "__main__":
    sys.exit(main())
