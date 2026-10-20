#!/usr/bin/env python3
"""Bounded offline-only assessment of the publisher-produced Shiguredo m157 AAR.

Research only: never load WebRTC, enable a microphone or change Android Gradle.
The pinned digest is a GitHub release asset metadata observation, not proof that
the declared source revision was compiled into this AAR or that CVEs are fixed.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import tempfile
import zipfile
from pathlib import Path

import collect_webrtc_candidate_evidence as evidence

TAG = "m157.8103.0.0"
RELEASE_URL = (
    "https://github.com/shiguredo-webrtc-build/webrtc-build/releases/"
    "download/m157.8103.0.0/libwebrtc.aar"
)
EXPECTED_SIZE = 15036224
# Observed in the publisher's GitHub Releases API on 2026-10-20.
EXPECTED_SHA256 = "b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a"
PRODUCER_TAG_SHA = "c575fdf836d1185d8cefda37197a2a489e95ffd9"
PUBLISHER_DECLARED_WEBRTC_SHA = "b321f634929af0af61a8964487fbd7894a008f12"
MAX_BYTES = 17 * 1024 * 1024


class CandidateProbeError(ValueError):
    pass


def verify_observation(digest: str, size: int) -> None:
    if not hmac.compare_digest(digest, EXPECTED_SHA256):
        raise CandidateProbeError("GitHub release asset SHA-256 mismatch")
    if size != EXPECTED_SIZE:
        raise CandidateProbeError("GitHub release asset byte count mismatch")


def inspect_pinned_aar(path: Path) -> dict:
    # Existing comprehensive AAR ZIP, ELF and Java audit, with an explicit
    # research-only ARM64 selection. Historical multi-ABI callers stay strict.
    details = evidence.audit.audit_aar(
        path, expected_sha256=EXPECTED_SHA256,
        required_abis=frozenset(("arm64-v8a",)),
        # Shiguredo m157 observed classfile major 69; this research setting is
        # NOT a claim that Kenato's JDK 17 / AGP 9.4 can consume this bytecode.
        max_classfile_major=69,
    )
    native = details["native_paths"]
    jni_path = "jni/arm64-v8a/libjingle_peerconnection_so.so"
    if jni_path not in native:
        raise CandidateProbeError("Expected ARM64 JNI lib is absent")
    if len(native) > 16:
        raise CandidateProbeError("Unexpected number of native entries")
    # Do not extract the AAR or execute any untrusted native code.
    with zipfile.ZipFile(path) as archive:
        member = archive.getinfo(details["webrtc_api_jar"])
        if member.file_size > evidence.audit.MAX_JAR_ENTRY_BYTES:
            raise CandidateProbeError("Oversized WebRTC API JAR")
        jar_data = archive.read(member)
    with zipfile.ZipFile(io.BytesIO(jar_data)) as nested:
        logging_present = "org/webrtc/LoggingJni.class" in nested.namelist()
    return {
        "status": "STRUCTURAL_PASS_NOT_VENDOR_APPROVAL",
        "tag": TAG,
        "asset_sha256": details["sha256"],
        "asset_size": details["file_bytes"],
        "asset_sha256_matches_github_release_metadata": True,
        "publisher_tag_git_sha": PRODUCER_TAG_SHA,
        "declared_upstream_webrtc_git_sha_UNVERIFIED_IN_BINARY": PUBLISHER_DECLARED_WEBRTC_SHA,
        "required_abis": details["required_abis"],
        "other_packaged_abis": details["optional_abis_present"],
        "native_paths": native,
        "api_jar_path": details["webrtc_api_jar"],
        "embedded_license_or_notice_paths": details["embedded_license_or_notice_paths"],
        "license_and_notice_binary_inventory_complete": False,
        "java_classfile_major_counts": details["java_classfile_major_counts"],
        "jdk17_compatible_classfiles": max(map(int, details["java_classfile_major_counts"])) <= 61,
        "java25_classfile_observed": "69" in details["java_classfile_major_counts"],
        "agp_d8_jdk25_compatibility_verified": False,
        "logging_jni_class_present": logging_present,
        "publisher_source_to_binary_reproducible": False,
        "native_cve_remediation_verified": False,
        "vendor_approved_for_kenato": False,
        "release_or_android_gradle_modified": False,
        "remaining_gates": [
            "verify exact upstream CVE patch plus applied publisher patches against native binary",
            "review third-party licenses and NOTICE for exact prebuilt AAR",
            "prove Java 25 classfile compatibility with AGP/D8 and app toolchain (currently JDK 17)",
            "load JNI on Android 10/13/14+ devices; then M5 P01-P24 physical acceptance",
            "review microphone/FGS policy and #116 effect runner before voice deployment",
        ],
    }


def collect(*, downloader=evidence.download_snapshot) -> dict:
    with tempfile.TemporaryDirectory(prefix="kenato-m5-shiguredo-") as temp:
        target = Path(temp) / "publisher-m157.aar"
        digest, size = downloader(RELEASE_URL, target, max_bytes=MAX_BYTES)
        verify_observation(digest, size)
        # Re-hash exactly the downloaded artifact, not a supplied checksum alone.
        if not target.is_file() or target.stat().st_size != size:
            raise CandidateProbeError("Missing or replaced AAR snapshot")
        return inspect_pinned_aar(target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = collect()
    except (CandidateProbeError, evidence.EvidenceError,
            evidence.audit.AarAuditError, OSError, zipfile.BadZipFile) as error:
        report = {
            "status": "RESEARCH_PROBE_FAILED",
            "tag": TAG,
            "failure": type(error).__name__,
            "detail": str(error)[:180],
            "vendor_approved_for_kenato": False,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Publisher-produced m157 snapshot research only; no vendor approval.")
    if report["status"] == "STRUCTURAL_PASS_NOT_VENDOR_APPROVAL":
        names = report["embedded_license_or_notice_paths"]
        print("AAR embedded license/NOTICE filenames:", ", ".join(names) if names else "NONE")
        print("Full bundled/transitive license inventory: NOT VERIFIED")
    if report["status"] == "RESEARCH_PROBE_FAILED":
        print("Research probe failed:", report["failure"], report["detail"])
    return 0 if report["status"] == "STRUCTURAL_PASS_NOT_VENDOR_APPROVAL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
