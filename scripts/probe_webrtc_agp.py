#!/usr/bin/env python3
"""Disposable AGP 9.4 / D8 investigation for exact WebRTC AAR snapshots.

Research only: no native execution, microphone, app dependency or vendor approval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zipfile

import collect_webrtc_candidate_evidence as evidence

# Observed on prior Kenato M5 CI, NOT independent publisher provenance.
EXPECTED = {
    "m149_maven": "d826831b6fdfae12fab3faa5405417e229f9fe837dce3adaac084c713e7b611c",
    "m150_maven": "0a1627b1a48c2bc17d9a40d62fc47bd45166f44a311e95917f147c402de379b0",
}
ABIS = frozenset(("armeabi-v7a", "arm64-v8a", "x86_64"))
NATIVE = "libjingle_peerconnection_so.so"
DESCRIPTOR = b"Lorg/webrtc/PeerConnection;"
MAX_DEX = 64 * 1024 * 1024
MAX_APK = 250 * 1024 * 1024


class ProbeError(ValueError):
    """A research probe did not establish the requested isolated property."""


def u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ProbeError("Truncated DEX table")
    return struct.unpack_from("<I", data, offset)[0]


def dex_string(data: bytes, offset: int) -> bytes:
    for _ in range(5):
        if offset >= len(data):
            raise ProbeError("Truncated DEX string length")
        value = data[offset]
        offset += 1
        if not value & 0x80:
            break
    else:
        raise ProbeError("Invalid DEX string length")
    end = data.find(b"\x00", offset)
    if end < 0 or end - offset > 1024:
        raise ProbeError("Invalid DEX descriptor")
    return data[offset:end]


def dex_defines_class(data: bytes) -> bool:
    """Read class_defs -> type_ids -> string_ids; no false raw-string PASS."""
    if len(data) < 112 or not data.startswith(b"dex\n") or data[7:8] != b"\x00":
        raise ProbeError("Invalid DEX header")
    if u32(data, 32) != len(data) or u32(data, 36) != 112:
        raise ProbeError("DEX header size mismatch")
    tables = (
        (u32(data, 56), u32(data, 60), 4),
        (u32(data, 64), u32(data, 68), 4),
        (u32(data, 96), u32(data, 100), 32),
    )
    for count, offset, unit in tables:
        if count > len(data) // unit or offset > len(data) or count * unit > len(data) - offset:
            raise ProbeError("DEX table exceeds file bounds")
    string_count, string_offset, _ = tables[0]
    type_count, type_offset, _ = tables[1]
    class_count, class_offset, _ = tables[2]
    for index in range(class_count):
        type_index = u32(data, class_offset + index * 32)
        if type_index >= type_count:
            raise ProbeError("DEX type index out of bounds")
        string_index = u32(data, type_offset + type_index * 4)
        if string_index >= string_count:
            raise ProbeError("DEX string index out of bounds")
        if dex_string(data, u32(data, string_offset + string_index * 4)) == DESCRIPTOR:
            return True
    return False


def inspect_apk(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_APK:
        raise ProbeError("Missing or oversized disposable APK")
    try:
        with zipfile.ZipFile(path) as apk:
            names = apk.namelist()
            if len(names) > evidence.audit.MAX_ENTRIES or len(names) != len(set(names)):
                raise ProbeError("Unsafe APK entry inventory")
            actual = {name for name in names if name.endswith("/" + NATIVE)}
            expected = {f"lib/{abi}/{NATIVE}" for abi in ABIS}
            if actual != expected:
                raise ProbeError("APK native ABI inventory mismatch")
            dexes = sorted(name for name in names if name.startswith("classes") and name.endswith(".dex"))
            if not dexes:
                raise ProbeError("No APK DEX files")
            found = False
            for name in dexes:
                info = apk.getinfo(name)
                if info.file_size > MAX_DEX:
                    raise ProbeError("Oversized DEX file")
                with apk.open(info) as stream:
                    payload = stream.read(MAX_DEX + 1)
                if len(payload) != info.file_size:
                    raise ProbeError("Truncated DEX file")
                found = dex_defines_class(payload) or found
            if not found:
                raise ProbeError("PeerConnection class definition absent from DEX")
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise ProbeError("Cannot inspect disposable APK") from exc
    return {
        "dex_defines_peer_connection": True,
        "dex_count": len(dexes),
        "native_apk_paths": sorted(actual),
        "apk_bytes": path.stat().st_size,
        "apk_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "jni_loader_executed": False,
    }


def write_disposable_app(root: Path, aar: Path) -> None:
    source = root / "app/src/main/java/org/kenato/research/Probe.java"
    source.parent.mkdir(parents=True, exist_ok=True)
    (root / "candidate.aar").write_bytes(aar.read_bytes())
    (root / "settings.gradle").write_text(
        "pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }\n"
        "dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); "
        "repositories { google(); mavenCentral() } }\n"
        "rootProject.name = 'KenatoM5Research'\ninclude ':app'\n",
        encoding="utf-8",
    )
    (root / "app/build.gradle").write_text(
        "plugins { id 'com.android.application' version '9.4.0' }\n"
        "android {\n"
        "  namespace 'org.kenato.research'\n"
        "  compileSdk 37\n"
        "  defaultConfig {\n"
        "    applicationId 'org.kenato.research'\n"
        "    minSdk 26\n"
        "    targetSdk 37\n"
        "    ndk { abiFilters 'armeabi-v7a', 'arm64-v8a', 'x86_64' }\n"
        "  }\n"
        "  compileOptions { sourceCompatibility JavaVersion.VERSION_17; "
        "targetCompatibility JavaVersion.VERSION_17 }\n"
        "}\n"
        "dependencies { implementation files('../candidate.aar') }\n",
        encoding="utf-8",
    )
    (root / "app/src/main/AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"/>\n',
        encoding="utf-8",
    )
    source.write_text(
        "package org.kenato.research;\n"
        "public final class Probe {\n"
        "  public String apiType() { return org.webrtc.PeerConnection.class.getName(); }\n"
        "}\n",
        encoding="utf-8",
    )


def run_disposable_build(wrapper: Path, root: Path, *, runner=subprocess.run) -> dict:
    try:
        completed = runner(
            [str(wrapper), "--no-daemon", "--stacktrace", ":app:assembleDebug"],
            cwd=root, check=False, timeout=540,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeError("AGP/D8 build timed out") from exc
    if completed.returncode != 0:
        raise ProbeError(f"AGP/D8 assembleDebug failed (exit={completed.returncode})")
    return inspect_apk(root / "app/build/outputs/apk/debug/app-debug.apk")


def collect(wrapper: Path, *, downloader=evidence.download_snapshot,
            runner=subprocess.run) -> tuple[dict, bool]:
    report = {
        "status": "RESEARCH_ONLY_NOT_VENDOR_APPROVAL",
        "agp": "9.4.0",
        "gradle": "repository wrapper 9.7.1",
        "jdk": "17",
        "compile_sdk": 37,
        "vendor_approved": False,
        "production_dependency_added": False,
        "independent_publisher_provenance": False,
        "results": {},
        "remaining_gates": [
            "independent Maven artifact provenance and source/GN build-flags audit",
            "Maven POM/transitive closure, native license/CVE review",
            "physical Android 10/13/14+ JNI load and two-phone P01-P24 acceptance",
        ],
    }
    passed = True
    with tempfile.TemporaryDirectory(prefix="kenato-m5-agp-") as temporary:
        base = Path(temporary)
        for label, url, _ in evidence.CANDIDATES:
            if label not in EXPECTED:
                continue
            result = {"vendor_approved": False}
            report["results"][label] = result
            aar = base / (label + ".aar")
            try:
                observed, size = downloader(url, aar)
                result.update(observed_sha256=observed, downloaded_bytes=size)
                if observed != EXPECTED[label]:
                    raise ProbeError("Candidate SHA-256 differs from prior isolated evidence")
                evidence.audit.audit_aar(aar, report_only=True)
                result["offline_structure_verified"] = True
                root = base / ("probe-" + label)
                write_disposable_app(root, aar)
                result.update(run_disposable_build(wrapper, root, runner=runner))
                result["status"] = "AGP_D8_PASS_NOT_VENDOR_APPROVAL"
            except (ProbeError, evidence.EvidenceError, evidence.audit.AarAuditError, OSError) as exc:
                result.update(
                    status="RESEARCH_PROBE_FAILED",
                    failure_type=type(exc).__name__,
                    failure_reason=str(exc)[:160],
                )
                passed = False
    return report, passed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradlew", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.gradlew.is_file():
        parser.error("Repository Gradle wrapper not found")
    result, passed = collect(args.gradlew.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("AGP/D8 evidence recorded. No vendor or release was approved.")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
