#!/usr/bin/env python3
"""M5 research-only ELF/JNI inventory: no native execution or vendor approval."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile, BadZipFile

import collect_webrtc_candidate_evidence as evidence
import probe_webrtc_agp as agp

ABIS = {"armeabi-v7a": (1, 40), "arm64-v8a": (2, 183), "x86_64": (2, 62), "x86": (1, 3)}
REQUIRED = frozenset(("armeabi-v7a", "arm64-v8a", "x86_64"))
NATIVE = "libjingle_peerconnection_so.so"
LIMIT = 64 * 1024 * 1024
MARKERS = {
    "vp9_packetizer_type_name": b"RtpPacketizerVp9",
    "vp9_uppercase": b"VP9",
    "sctp_data_channel_type_name": b"SctpDataChannel",
    "libvpx": b"libvpx",
}

class NativeProbeError(ValueError):
    pass

def elf_header(payload: bytes, abi: str) -> None:
    cls, machine = ABIS[abi]
    if len(payload) < 52 or payload[:4] != b"\x7fELF" or payload[4] != cls:
        raise NativeProbeError("ELF magic/class mismatch")
    if payload[5:7] != b"\x01\x01" or int.from_bytes(payload[18:20], "little") != machine:
        raise NativeProbeError("ELF data/machine mismatch")
    if int.from_bytes(payload[16:18], "little") != 3:
        raise NativeProbeError("Library is not ET_DYN")

def scan_elf(payload: bytes, abi: str, *, runner=subprocess.run) -> dict:
    elf_header(payload, abi)
    if len(payload) > LIMIT:
        raise NativeProbeError("Native ELF exceeds input limit")
    with tempfile.TemporaryDirectory(prefix="kenato-m5-static-elf-") as root:
        binary = Path(root) / "candidate.so"
        binary.write_bytes(payload)
        try:
            process = runner(["readelf", "-W", "-h", "-l", "-d", "-s", str(binary)],
                             capture_output=True, check=False, timeout=25)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NativeProbeError("readelf failed to execute safely") from exc
    if process.returncode != 0 or not isinstance(process.stdout, bytes) or len(process.stdout) > 2 * 1024 * 1024:
        raise NativeProbeError("Invalid or oversized readelf output")
    text = process.stdout.decode("utf-8", errors="replace")
    names = set(re.findall(r"\b(Java_org_webrtc_[A-Za-z0-9_]+)\b", text))
    needed = sorted(set(re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]\s]{1,128})\]", text)))
    soname = sorted(set(re.findall(r"\(SONAME\)\s+Library soname: \[([^\]\s]{1,128})\]", text)))
    stack = re.findall(r"^\s*GNU_STACK\s+[^\n]+$", text, re.MULTILINE)
    relro = re.findall(r"^\s*GNU_RELRO\s+[^\n]+$", text, re.MULTILINE)
    return {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "dt_needed": needed,
        "soname": soname,
        "gnu_relro": len(relro) == 1,
        "bind_now": bool(re.search(r"\(FLAGS(?:_1)?\)\s+[^\n]*\b(?:BIND_NOW|NOW)\b", text)),
        "gnu_stack_executable": bool(re.search(r"\bRWE\b", stack[0])) if len(stack) == 1 else None,
        "jni_onload_exported": bool(re.search(r"\bJNI_OnLoad\b", text)),
        "jni_export_count": len(names),
        "jni_peer_connection_exports": sum(name.startswith("Java_org_webrtc_PeerConnection_") for name in names),
        "jni_data_channel_exports": sum(name.startswith("Java_org_webrtc_DataChannel_") for name in names),
        "binary_marker_counts_NOT_reachability": {
            name: payload.count(value) for name, value in MARKERS.items()
        },
        "native_code_executed": False,
        "cve_exploitability_established": False,
    }

def scan_aar(path: Path, *, runner=subprocess.run) -> dict:
    structural = evidence.audit.audit_aar(path, report_only=True)
    native = {}
    with ZipFile(path) as jar:
        names = set(jar.namelist())
        for abi in sorted(ABIS):
            location = f"jni/{abi}/{NATIVE}"
            if location not in names:
                if abi in REQUIRED:
                    raise NativeProbeError("Required ABI absent: " + abi)
                continue
            info = jar.getinfo(location)
            if info.file_size > LIMIT:
                raise NativeProbeError("Oversized native ELF for " + abi)
            with jar.open(info) as entry:
                raw = entry.read(LIMIT + 1)
            if len(raw) != info.file_size:
                raise NativeProbeError("Truncated native ELF for " + abi)
            native[abi] = scan_elf(raw, abi, runner=runner)
    if not REQUIRED.issubset(native):
        raise NativeProbeError("Incomplete required ABI inventory")
    return {"native": native, "webrtc_api_jar": structural["webrtc_api_jar"]}

def collect(root: Path, *, downloader=evidence.download_snapshot, runner=subprocess.run) -> tuple[dict, bool]:
    output = {
        "status": "RESEARCH_ONLY_NOT_APPROVAL",
        "vendor_approved": False,
        "jni_loader_executed": False,
        "production_dependency_changed": False,
        "source_reproducibility_verified": False,
        "candidates": {},
        "remaining_gates": [
            "publisher/source/GN/backport provenance and native CVE applicability",
            "bundled native third-party license and NOTICE completeness",
            "real Android 10/13/14+ JNI loader plus P01-P24 physical acceptance",
        ],
    }
    okay = True
    for label, url, _ in evidence.CANDIDATES:
        if label not in agp.EXPECTED:
            continue
        candidate = root / f"{label}.aar"
        record = {"vendor_approved": False}
        output["candidates"][label] = record
        try:
            digest, size = downloader(url, candidate)
            record["aar_sha256"] = digest
            record["aar_bytes"] = size
            if digest != agp.EXPECTED[label]:
                raise NativeProbeError("AAR digest changed from reviewed snapshot")
            record.update(scan_aar(candidate, runner=runner))
            record["status"] = "STATIC_INVENTORY_OK_NOT_VENDOR_APPROVAL"
        except (OSError, NativeProbeError, evidence.EvidenceError,
                evidence.audit.AarAuditError, BadZipFile) as exc:
            record["status"] = "PROBE_FAILED"
            record["failure_type"] = type(exc).__name__
            record["failure_reason"] = str(exc)[:160]
            okay = False
    return output, okay

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="kenato-m5-elf-probe-") as directory:
        result, okay = collect(Path(directory))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("Static ELF report generated; no vendor binaries loaded or approved.")
    return 0 if okay else 1

if __name__ == "__main__":
    sys.exit(main())
