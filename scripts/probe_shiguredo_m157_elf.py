#!/usr/bin/env python3
"""Exact SHA-pinned m157 ARM64 ELF static inventory: research, no JNI execution."""
from __future__ import annotations

import argparse
import json
import tempfile
import zipfile
from pathlib import Path

import collect_webrtc_candidate_evidence as evidence
import probe_shiguredo_m157 as m157
import probe_webrtc_native_elf as native

LIB_PATH = "jni/arm64-v8a/libjingle_peerconnection_so.so"


class M157NativeError(ValueError):
    pass


def inventory(path: Path, *, scanner=native.scan_elf) -> dict:
    # Check exact downloaded AAR digest, ZIP+ELF structural rules and CRC first.
    baseline = m157.inspect_pinned_aar(path)
    if baseline["status"] != "STRUCTURAL_PASS_NOT_VENDOR_APPROVAL":
        raise M157NativeError("Vendor AAR structure not approved for research")
    with zipfile.ZipFile(path) as archive:
        member = archive.getinfo(LIB_PATH)
        if member.file_size < 52 or member.file_size > native.LIMIT:
            raise M157NativeError("Native ARM64 library absent or oversized")
        with archive.open(member) as source:
            payload = source.read(native.LIMIT + 1)
        if len(payload) != member.file_size:
            raise M157NativeError("Truncated native ELF")
    record = scanner(payload, "arm64-v8a")
    # Explicitly do not turn ELF flags into an arbitrary automatic approval.
    return {
        "status": "PINNED_ARM64_ELF_STATIC_INVENTORY_ONLY",
        "sha256_pinned_aar": m157.EXPECTED_SHA256,
        "aar_bytes": m157.EXPECTED_SIZE,
        "native_arm64": record,
        "native_executed": False,
        "symbol_presence_proves_cve_fix": False,
        "source_to_native_binary_reproducibility_verified": False,
        "vendor_approved_for_kenato": False,
    }


def collect(*, downloader=evidence.download_snapshot, scanner=native.scan_elf) -> dict:
    with tempfile.TemporaryDirectory(prefix="kenato-m157-arm64-elf-") as directory:
        file = Path(directory) / "m157.aar"
        digest, size = downloader(m157.RELEASE_URL, file, max_bytes=m157.MAX_BYTES)
        m157.verify_observation(digest, size)
        if not file.is_file() or file.stat().st_size != size:
            raise M157NativeError("Pinned AAR missing or size changed")
        return inventory(file, scanner=scanner)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = collect()
        code = 0
    except (OSError, ValueError, zipfile.BadZipFile, native.NativeProbeError,
            evidence.EvidenceError, evidence.audit.AarAuditError) as error:
        result = {
            "status": "PINNED_ARM64_ELF_INVENTORY_FAILED",
            "type": type(error).__name__,
            "detail": str(error)[:160],
            "vendor_approved_for_kenato": False,
        }
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Pinned Shiguredo m157 ARM64 static ELF:", result["status"])
    if code == 0:
        flags = result["native_arm64"]
        print("ARM64 ELF GNU_RELRO:", flags["gnu_relro"],
              "BIND_NOW:", flags["bind_now"],
              "executable_stack:", flags["gnu_stack_executable"],
              "JNI_OnLoad:", flags["jni_onload_exported"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
