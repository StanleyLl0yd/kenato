#!/usr/bin/env python3
"""Collect bounded, offline-only evidence for two fixed WebRTC AAR candidates.

This never executes, extracts to filesystem, loads or adds vendor binaries to Kenato.
A successful evidence run does NOT approve a vendor or verify Maven provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
AUDITOR_PATH = HERE / "audit_webrtc_aar.py"
SPEC = importlib.util.spec_from_file_location("kenato_offline_aar_auditor", AUDITOR_PATH)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)

# Explicit static sources only. Never derive a fetch URL from an untrusted PR/input.
CANDIDATES = (
    ("m149_maven",
     "https://repo.maven.apache.org/maven2/im/conversations/webrtc/"
     "webrtc-android/149.0.0/webrtc-android-149.0.0.aar", None),
    ("m150_maven",
     "https://repo.maven.apache.org/maven2/io/github/webrtc-sdk/android/"
     "150.7871.01/android-150.7871.01.aar", None),
    ("m150_github_original",
     "https://github.com/webrtc-sdk/android/releases/download/v150.7871.01/libwebrtc.aar",
     # GitHub Release asset metadata, not the post-processed Maven AAR digest.
     "8ad5e5fd02f0177743ddb566bea329006bef7689b944f6351717cd1d018958c0"),
)


class EvidenceError(ValueError):
    """Evidence collection cannot be represented as a verified observation."""


def download_snapshot(url: str, destination: Path, *,
                      opener=urlopen, max_bytes: int = audit.MAX_AAR_BYTES
                      ) -> tuple[str, int]:
    """Stream to an isolated, bounded temporary file and hash the same bytes."""
    request = Request(url, headers={"User-Agent": "Kenato-M5-AAR-Evidence/1"})
    digest = hashlib.sha256()
    size = 0
    with opener(request, timeout=90) as response, destination.open("wb") as output:
        if getattr(response, "status", 200) != 200:
            raise EvidenceError("AAR download returned a non-200 response")
        while chunk := response.read(128 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise EvidenceError("AAR download exceeds size bound")
            output.write(chunk)
            digest.update(chunk)
    if size == 0:
        raise EvidenceError("Empty candidate AAR download")
    return digest.hexdigest(), size


def native_entry_inventory(path: Path) -> dict:
    """Read only ZIP directory metadata, never extract or load a native library."""
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > audit.MAX_ENTRIES:
                return {"error": "too many ZIP entries for evidence listing"}
            native = sorted(
                item.filename for item in entries
                if not item.is_dir() and item.filename.lower().endswith(".so")
            )
            return {
                "total_so_paths": len(native),
                "displayed_so_paths": [name[:180] for name in native[:64]],
                "paths_truncated": len(native) > 64 or any(len(x) > 180 for x in native[:64]),
            }
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return {"error": "native inventory ZIP parsing failed"}



def jar_entry_inventory(path: Path) -> dict:
    """Bounded Java API layout hints, without treating a nested JAR as trusted."""
    jars = []
    try:
        with zipfile.ZipFile(path) as aar:
            entries = aar.infolist()
            if len(entries) > audit.MAX_ENTRIES:
                return {"error": "too many outer AAR entries"}
            for item in entries:
                if item.is_dir() or not item.filename.lower().endswith(".jar"):
                    continue
                record = {"jar_path": item.filename[:180]}
                if item.file_size > audit.MAX_ENTRY_BYTES:
                    record["error"] = "oversized nested JAR"
                else:
                    try:
                        with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as spool:
                            transferred = 0
                            with aar.open(item) as source:
                                while chunk := source.read(128 * 1024):
                                    transferred += len(chunk)
                                    if transferred > audit.MAX_ENTRY_BYTES:
                                        raise EvidenceError("Oversized nested JAR read")
                                    spool.write(chunk)
                            spool.seek(0)
                            with zipfile.ZipFile(spool) as nested:
                                nested_files = nested.namelist()
                                if len(nested_files) > audit.MAX_JAR_ENTRIES:
                                    record["error"] = "too many nested JAR entries"
                                else:
                                    class_paths = [name for name in nested_files
                                                   if name.endswith(".class")]
                                    record["class_count"] = len(class_paths)
                                    record["exact_peer_connection_path"] = (
                                        "org/webrtc/PeerConnection.class" in class_paths
                                    )
                                    record["sample_class_paths"] = [
                                        name[:180] for name in class_paths[:6]
                                    ]
                    except (zipfile.BadZipFile, OSError, RuntimeError, EvidenceError):
                        record["error"] = "nested JAR inventory parse/size failure"
                jars.append(record)
                if len(jars) >= 16:
                    break
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return {"error": "outer AAR ZIP inventory failed"}
    return {"jars": jars, "display_limit": 16}


def reproduce_published_m150_stamping(original: Path, output: Path) -> int:
    """Model the reviewed upstream v150 tag's class-major-only ZIP rewrite.

    This checks post-processing lineage only; it does not recompile or validate
    Java 21 bytecode, reproduce WebRTC source builds, or execute vendor code.
    """
    def stamped(data: bytes) -> tuple[bytes, int]:
        if data[:4] == b"\xca\xfe\xba\xbe" and len(data) >= 8:
            major = int.from_bytes(data[6:8], "big")
            if major > 61:
                return data[:6] + (61).to_bytes(2, "big") + data[8:], 1
        return data, 0

    def rewrite_zip(source: zipfile.ZipFile, target: zipfile.ZipFile, *,
                    nested_classes: bool) -> int:
        count = 0
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename.endswith(".class"):
                data, changed = stamped(data)
                count += changed
            elif nested_classes and info.filename == "classes.jar":
                jar_input = io.BytesIO(data)
                jar_output = io.BytesIO()
                with zipfile.ZipFile(jar_input) as jar, zipfile.ZipFile(
                    jar_output, "w", zipfile.ZIP_DEFLATED
                ) as new_jar:
                    count += rewrite_zip(jar, new_jar, nested_classes=False)
                data = jar_output.getvalue()
            new_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            new_info.compress_type = info.compress_type
            new_info.external_attr = info.external_attr
            target.writestr(new_info, data)
        return count

    with zipfile.ZipFile(original) as source, zipfile.ZipFile(
        output, "w", zipfile.ZIP_DEFLATED
    ) as target:
        return rewrite_zip(source, target, nested_classes=True)


def collect_evidence(directory: Path, *, candidates=CANDIDATES,
                     downloader=download_snapshot) -> dict:
    records: dict[str, dict] = {}
    for label, url, pinned_release_digest in candidates:
        path = directory / (label + ".aar")
        observed, size = downloader(url, path)
        if pinned_release_digest and observed != pinned_release_digest:
            raise EvidenceError(f"{label}: pinned GitHub release asset SHA-256 mismatch")
        try:
            structural = audit.audit_aar(path, report_only=True)
            status = "STRUCTURAL_PASS_NOT_APPROVAL"
            details = {
                "native_paths": structural["native_paths"],
                "java_classfile_major_counts": structural["java_classfile_major_counts"],
                "embedded_license_or_notice_paths": structural[
                    "embedded_license_or_notice_paths"
                ],
            }
        except (audit.AarAuditError, OSError, ValueError) as error:
            status = "STRUCTURAL_REJECTED"
            details = {"reason": str(error)}
        records[label] = {
            "source_url": url,
            "observed_sha256": observed,
            "downloaded_bytes": size,
            "checked_against_release_asset_digest": pinned_release_digest is not None,
            "structural_status": status,
            "structural_details": details,
            "native_entry_inventory": native_entry_inventory(path),
            "jar_entry_inventory": jar_entry_inventory(path),
            "vendor_approved": False,
        }
    stamping_result = None
    if {"m150_maven", "m150_github_original"} <= records.keys():
        transformed_path = directory / "m150_transformed_probe.aar"
        try:
            changed = reproduce_published_m150_stamping(
                directory / "m150_github_original.aar", transformed_path
            )
            transformed_sha = hashlib.sha256(transformed_path.read_bytes()).hexdigest()
            stamping_result = {
                "modelled_class_major_rewrites": changed,
                "modelled_output_sha256": transformed_sha,
                "matches_maven_sha256": (
                    transformed_sha == records["m150_maven"]["observed_sha256"]
                ),
                "scope": "post-download class-major stamping only, NOT source reproducibility",
            }
        except (zipfile.BadZipFile, OSError, RuntimeError) as error:
            stamping_result = {"error": type(error).__name__}
    return {
        "status": "RESEARCH_ONLY_NOT_VENDOR_APPROVAL",
        "m150_stamping_lineage_probe": stamping_result,
        "sha256_note": (
            "Maven digests are observations from downloaded bytes, not independently "
            "pinned. GitHub asset digest applies only to the original release AAR."
        ),
        "m150_maven_matches_original_release": (
            records["m150_maven"]["observed_sha256"]
            == records["m150_github_original"]["observed_sha256"]
        ) if {"m150_maven", "m150_github_original"} <= records.keys() else None,
        "candidates": records,
        "remaining_gates": [
            "independent Maven digest and publisher/source lineage",
            "Gradle module/transitive dependencies and all native licenses/CVEs",
            "actual JDK 17/AGP 9.4/D8 behavior and Java classfile rewriting",
            "Android 10/13/14+ native JNI loader and physical two-phone evidence",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="JSON report path; never pass a vendor binary path")
    args = parser.parse_args(argv)
    try:
        with tempfile.TemporaryDirectory(prefix="kenato-m5-aar-") as tmp:
            result = collect_evidence(Path(tmp))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print("AAR evidence collected; no vendor was approved or activated.")
    except (EvidenceError, OSError) as error:
        print(f"AAR evidence collection BLOCKED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
