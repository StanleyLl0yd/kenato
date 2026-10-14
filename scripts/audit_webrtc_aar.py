#!/usr/bin/env python3
"""Offline, bounded structural audit of an explicitly supplied Android WebRTC AAR.

No fetching, dependency resolution or app activation. Passing structural checks
does NOT approve publisher/source lineage, licenses, native CVEs or device loading.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import stat
import struct
import sys
import zipfile
from pathlib import Path, PurePosixPath

REQUIRED_ABIS = {"armeabi-v7a": (1, 40), "arm64-v8a": (2, 183), "x86_64": (2, 62)}
MAX_AAR_BYTES = 250 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_ENTRY_BYTES = 200 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_COMPRESSION_RATIO = 1000


class AarAuditError(ValueError):
    """Untrusted binary does not meet the proposed native prerequisite."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(128 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _require_name(name: str) -> None:
    path = PurePosixPath(name)
    if (not name or "\\" in name or name.startswith("/") or
            any(part in ("", ".", "..") for part in name.split("/")) or
            path.is_absolute() or "\x00" in name):
        raise AarAuditError("Archive contains unsafe entry path")


def _validate_elf(zipped: zipfile.ZipFile, info: zipfile.ZipInfo, abi: str) -> None:
    with zipped.open(info) as stream:
        header = stream.read(20)
    elf_class, expected_machine = REQUIRED_ABIS[abi]
    if (len(header) < 20 or header[:4] != b"\x7fELF" or
            header[4] != elf_class or header[5] != 1 or
            struct.unpack_from("<H", header, 18)[0] != expected_machine):
        raise AarAuditError(f"Invalid ELF class/architecture for {abi}")


def audit_aar(
    path: Path,
    *,
    expected_sha256: str | None = None,
    report_only: bool = False,
) -> dict:
    """Validate integrity + AAR layout without ever executing native code.

    A verification requires independently obtained SHA-256. Report-only mode
    prints an observed digest but deliberately never claims a verified binary.
    """
    path = Path(path)
    if not report_only and expected_sha256 is None:
        raise AarAuditError("Expected SHA-256 is required for verification")
    if expected_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise AarAuditError("Expected SHA-256 must be exactly 64 lowercase hex digits")
    if not path.is_file() or path.stat().st_size not in range(1, MAX_AAR_BYTES + 1):
        raise AarAuditError("AAR file missing, empty or exceeds disk limit")
    observed = _sha256(path)
    if expected_sha256 is not None and not hmac.compare_digest(expected_sha256, observed):
        raise AarAuditError("AAR SHA-256 does not match independently pinned digest")

    libnames: dict[str, set[str]] = {name: set() for name in REQUIRED_ABIS}
    native_paths = []
    license_paths = []
    total_size = 0
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(path) as zipped:
            entries = zipped.infolist()
            if len(entries) > MAX_ENTRIES:
                raise AarAuditError("Too many archive entries")
            for info in entries:
                _require_name(info.filename.rstrip("/") if info.is_dir() else info.filename)
                canonical = info.filename.rstrip("/").lower()
                if canonical in seen:
                    raise AarAuditError("Duplicate/case-alias archive path")
                seen.add(canonical)
                if info.flag_bits & 1:
                    raise AarAuditError("Encrypted ZIP entries are not permitted")
                mode = info.external_attr >> 16
                if stat.S_IFMT(mode) == stat.S_IFLNK:
                    raise AarAuditError("Symlink entry is not permitted")
                if info.file_size < 0 or info.file_size > MAX_ENTRY_BYTES:
                    raise AarAuditError("Archive entry exceeds size bound")
                total_size += info.file_size
                if total_size > MAX_UNCOMPRESSED_BYTES:
                    raise AarAuditError("Decompressed archive exceeds global size bound")
                if (info.file_size > 0 and
                        (info.compress_size <= 0 or
                         info.file_size / info.compress_size > MAX_COMPRESSION_RATIO)):
                    raise AarAuditError("Implausible archive compression ratio")
                if info.is_dir():
                    continue
                parts = PurePosixPath(info.filename).parts
                if info.filename.lower().endswith(".so"):
                    if (len(parts) != 3 or parts[0] != "jni" or
                            parts[1] not in REQUIRED_ABIS or
                            not parts[2].startswith("lib")):
                        raise AarAuditError("Unrecognized native library path/ABI")
                    abi = parts[1]
                    _validate_elf(zipped, info, abi)
                    libnames[abi].add(parts[2])
                    native_paths.append(info.filename)
                if ("license" in info.filename.lower() or
                        "notice" in info.filename.lower()):
                    license_paths.append(info.filename)
            if not {"classes.jar", "AndroidManifest.xml"}.issubset(
                {i.filename for i in entries if not i.is_dir()}
            ):
                raise AarAuditError("AAR is missing classes.jar or AndroidManifest.xml")
            if not all(libnames.values()) or len({frozenset(x) for x in libnames.values()}) != 1:
                raise AarAuditError("Required ABI libraries missing or inconsistent across ABIs")
            if zipped.testzip() is not None:
                raise AarAuditError("AAR entry CRC verification failed")
    except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as error:
        raise AarAuditError("AAR ZIP parsing/CRC failed") from error

    return {
        "sha256": observed,
        "verified_against_expected_sha256": expected_sha256 is not None,
        "file_bytes": path.stat().st_size,
        "uncompressed_bytes": total_size,
        "required_abis": sorted(REQUIRED_ABIS),
        "native_paths": sorted(native_paths),
        "embedded_license_or_notice_paths": sorted(license_paths),
        "remaining_reviews": [
            "source lineage and publisher",
            "full native and third-party licenses",
            "binary CVEs and dependency graph",
            "Android 10/13/14+ loader tests and microphone lifecycle",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("aar", type=Path, help="Already obtained local AAR")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--expected-sha256", help="Independently pinned lowercase SHA-256")
    group.add_argument("--report-only", action="store_true",
                       help="Inspect and print observed hash; this is NOT verification")
    args = parser.parse_args(argv)
    try:
        result = audit_aar(
            args.aar, expected_sha256=args.expected_sha256, report_only=args.report_only,
        )
    except (AarAuditError, OSError) as error:
        print(f"AAR rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
