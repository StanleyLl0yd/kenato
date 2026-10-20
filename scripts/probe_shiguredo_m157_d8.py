#!/usr/bin/env python3
"""Disposable AGP 9.4/D8 JDK25 ARM64 integration research for pinned m157.

Never executes JNI, accesses microphone, modifies production Gradle or
publishes the vendor AAR/APK. Passing does NOT approve this vendor.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
import zipfile
from pathlib import Path

import collect_webrtc_candidate_evidence as evidence
import probe_webrtc_agp as agp
import probe_shiguredo_m157 as m157

RESEARCH_ABI = "arm64-v8a"
DEFAULT_ABIS = "abiFilters 'armeabi-v7a', 'arm64-v8a', 'x86_64'"
RESEARCH_ABIS = "abiFilters 'arm64-v8a'"


class D8ResearchError(ValueError):
    pass


def write_arm64_probe(root: Path, vendor_aar: Path) -> None:
    agp.write_disposable_app(root, vendor_aar)
    gradle = root / "app/build.gradle"
    text = gradle.read_text(encoding="utf-8")
    if text.count(DEFAULT_ABIS) != 1:
        raise D8ResearchError("Unrecognized upstream disposable ABI fixture")
    gradle.write_text(text.replace(DEFAULT_ABIS, RESEARCH_ABIS), encoding="utf-8")


def inspect_arm64_apk(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > agp.MAX_APK:
        raise D8ResearchError("Missing or oversized disposable APK")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [x.filename for x in entries]
        if len(names) > evidence.audit.MAX_ENTRIES or len(names) != len(set(names)):
            raise D8ResearchError("Unexpected APK entry inventory")
        native = sorted(name for name in names if name.startswith("lib/") and name.endswith(".so"))
        if not native or {name.split("/")[1] for name in native} != {RESEARCH_ABI}:
            raise D8ResearchError("Disposable APK contains incorrect native ABI selection")
        expected_jni = "lib/arm64-v8a/libjingle_peerconnection_so.so"
        if expected_jni not in native:
            raise D8ResearchError("ARM64 WebRTC JNI library was not packaged")
        dex_paths = sorted(name for name in names if name.startswith("classes") and name.endswith(".dex"))
        if not dex_paths:
            raise D8ResearchError("No compiled DEX files")
        found = False
        for name in dex_paths:
            info = archive.getinfo(name)
            if info.file_size > agp.MAX_DEX:
                raise D8ResearchError("Oversized DEX file")
            with archive.open(info) as stream:
                data = stream.read(agp.MAX_DEX + 1)
            if len(data) != info.file_size:
                raise D8ResearchError("Incomplete DEX file")
            found = agp.dex_defines_class(data) or found
        if not found:
            raise D8ResearchError("PeerConnection is absent from compiled DEX")
    return {
        "status": "JDK25_AGP_D8_ARM64_PASS_NOT_VENDOR_APPROVAL",
        "native_apk_paths": native,
        "dex_count": len(dex_paths),
        "dex_defines_peer_connection": True,
        "apk_bytes": path.stat().st_size,
        "jdk25_toolchain_used": True,
        "JNI_executed": False,
        "vendor_approved": False,
    }


def collect(wrapper: Path, *, downloader=evidence.download_snapshot,
            runner=subprocess.run) -> dict:
    if not wrapper.is_file():
        raise D8ResearchError("Gradle wrapper missing")
    with tempfile.TemporaryDirectory(prefix="kenato-m157-jdk25-d8-") as tmp:
        base = Path(tmp)
        vendor = base / "m157.aar"
        digest, size = downloader(m157.RELEASE_URL, vendor, max_bytes=m157.MAX_BYTES)
        m157.verify_observation(digest, size)
        m157.inspect_pinned_aar(vendor)
        root = base / "disposable"
        write_arm64_probe(root, vendor)
        try:
            result = runner([str(wrapper.resolve()), "--no-daemon", "--stacktrace",
                             ":app:assembleDebug"],
                            cwd=root, check=False, timeout=540)
        except subprocess.TimeoutExpired as error:
            raise D8ResearchError("Disposable AGP D8 build timed out") from error
        if result.returncode != 0:
            raise D8ResearchError("Disposable AGP D8 build failed")
        return inspect_arm64_apk(root / "app/build/outputs/apk/debug/app-debug.apk")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradlew", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    try:
        result = collect(options.gradlew)
    except (D8ResearchError, m157.CandidateProbeError, evidence.EvidenceError,
            evidence.audit.AarAuditError, OSError, zipfile.BadZipFile) as error:
        result = {
            "status": "JDK25_D8_RESEARCH_BLOCKED",
            "failure": type(error).__name__,
            "detail": str(error)[:160],
            "JNI_executed": False,
            "vendor_approved": False,
        }
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Shiguredo m157 JDK25 D8 research:", result["status"])
    if "failure" in result:
        print("Reason:", result["failure"], result["detail"])
    return 0 if result["status"] == "JDK25_AGP_D8_ARM64_PASS_NOT_VENDOR_APPROVAL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
