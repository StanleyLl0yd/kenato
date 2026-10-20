#!/usr/bin/env python3
"""Offline SHA-bound Shiguredo m157 producer-CI ZIP -> nested AAR identity proof.

Proves CI artifact equals published release AAR, NOT independent rebuild
reproducibility, publisher source patch application, or native CVE safety.
Never extract tar filesystem entries or run any third-party binary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path

PRODUCER_RUN = 38522776327
PRODUCER_SHA = "c575fdf836d1185d8cefda37197a2a489e95ffd9"
ARTIFACT_ID = 11876415141
OUTER_NAME = "webrtc.android_sdk.tar.gz"
OUTER_BYTES = 105467424
OUTER_SHA256 = "8b6dd31f83b78b40d1239d588f50d93fe84008b021a720c89ddc3e11081d8e53"
TARGET_AAR = "webrtc/aar/libwebrtc.aar"
TARGET_AAR_BYTES = 15036224
TARGET_AAR_SHA256 = "b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a"
TARGET_VERSIONS = "webrtc/VERSIONS"
WEBRTC_SHA = "b321f634929af0af61a8964487fbd7894a008f12"
MAX_TAR_MEMBERS = 100000
MAX_MEMBER_SIZE = 256 * 1024 * 1024


class ProducerArchiveError(ValueError):
    pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prove(path: Path, *, expected_outer_sha: str = OUTER_SHA256,
          expected_outer_size: int = OUTER_BYTES,
          expected_aar_sha: str = TARGET_AAR_SHA256,
          expected_aar_size: int = TARGET_AAR_BYTES) -> dict:
    if not path.is_file() or path.stat().st_size != expected_outer_size:
        raise ProducerArchiveError("Producer Actions artifact size mismatch")
    if file_sha256(path) != expected_outer_sha:
        raise ProducerArchiveError("Producer Actions artifact SHA256 mismatch")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if names != [OUTER_NAME]:
            raise ProducerArchiveError("Unexpected producer Actions outer ZIP inventory")
        member = archive.getinfo(OUTER_NAME)
        if member.file_size > MAX_MEMBER_SIZE:
            raise ProducerArchiveError("Oversized producer tar stream")
        found_aar = False
        found_versions = False
        count = 0
        versions = {}
        with archive.open(member) as compressed:
            with tarfile.open(fileobj=compressed, mode="r|gz") as tar:
                for entry in tar:
                    count += 1
                    if count > MAX_TAR_MEMBERS:
                        raise ProducerArchiveError("Too many tar members")
                    if entry.name not in (TARGET_AAR, TARGET_VERSIONS):
                        continue
                    if not entry.isfile() or entry.size > MAX_MEMBER_SIZE:
                        raise ProducerArchiveError("Target member missing or oversized")
                    stream = tar.extractfile(entry)
                    if stream is None:
                        raise ProducerArchiveError("Cannot read pinned target member")
                    if entry.name == TARGET_AAR:
                        if found_aar or entry.size != expected_aar_size:
                            raise ProducerArchiveError("Duplicate or wrong-sized producer AAR")
                        digest = hashlib.sha256()
                        size = 0
                        while True:
                            block = stream.read(1024 * 1024)
                            if not block:
                                break
                            size += len(block)
                            digest.update(block)
                        if size != expected_aar_size or digest.hexdigest() != expected_aar_sha:
                            raise ProducerArchiveError("CI-built AAR differs from pinned release AAR")
                        found_aar = True
                    else:
                        if found_versions or entry.size > 4096:
                            raise ProducerArchiveError("Duplicate or oversized source VERSIONS")
                        decoded = stream.read(4097).decode("utf-8")
                        for line in decoded.splitlines():
                            key, sep, value = line.partition("=")
                            if sep and key in ("WEBRTC_BUILD_VERSION", "WEBRTC_COMMIT", "WEBRTC_SRC_COMMIT"):
                                if key in versions:
                                    raise ProducerArchiveError("Duplicate pinned source version")
                                versions[key] = value
                        found_versions = True
    if not found_aar or not found_versions or versions != {
        "WEBRTC_BUILD_VERSION": "157.8103.0.0",
        "WEBRTC_COMMIT": WEBRTC_SHA,
        "WEBRTC_SRC_COMMIT": WEBRTC_SHA,
    }:
        raise ProducerArchiveError("Producer AAR or declared WebRTC source missing")
    return {
        "status": "PRODUCER_CI_AAR_EQUALS_PINNED_RELEASE_AAR",
        "producer_run": PRODUCER_RUN,
        "producer_commit": PRODUCER_SHA,
        "producer_artifact_id": ARTIFACT_ID,
        "outer_actions_zip_sha256": expected_outer_sha,
        "ci_archive_aar_sha256": expected_aar_sha,
        "published_aar_sha256": TARGET_AAR_SHA256,
        "ci_archive_aar_bytes": expected_aar_size,
        "source_commit_declared_in_ci_archive": WEBRTC_SHA,
        "source_to_ci_output_metadata_consistent": True,
        "independent_source_rebuild_reproducibility_verified": False,
        "native_cve_binary_remediation_verified": False,
        "third_party_license_inventory_complete": False,
        "vendor_approved_for_kenato": False,
        "jni_executed": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--producer-actions-zip", required=True, type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        result = prove(args.producer_actions_zip)
        code = 0
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, UnicodeError) as error:
        result = {"status": "PRODUCER_ARCHIVE_PROOF_FAILED",
                  "reason": type(error).__name__,
                  "detail": str(error)[:180],
                  "vendor_approved_for_kenato": False}
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("M5 producer artifact provenance:", result["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
