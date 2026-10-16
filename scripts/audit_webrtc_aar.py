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
import tempfile
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
MAX_JAR_ENTRIES = 50000
MAX_JAR_UNCOMPRESSED_BYTES = 384 * 1024 * 1024
MAX_JAR_ENTRY_BYTES = 32 * 1024 * 1024
# The pinned application build runs JDK 17. Classfile major 61 is Java 17.
MAX_CLASSFILE_MAJOR = 61
# Bound decompression needed to reach ELF program headers.
MAX_PROGRAM_HEADER_OFFSET = 1024 * 1024


class AarAuditError(ValueError):
    """Untrusted binary does not meet the proposed native prerequisite."""


def _snapshot_and_sha256(path: Path, snapshot) -> tuple[str, int]:
    """Hash exactly the bytes later parsed; a path can be swapped after hashing."""
    digest = hashlib.sha256()
    copied = 0
    with path.open("rb") as stream:
        while block := stream.read(128 * 1024):
            copied += len(block)
            if copied > MAX_AAR_BYTES:
                raise AarAuditError("AAR changed size or exceeds disk limit")
            snapshot.write(block)
            digest.update(block)
    if copied == 0:
        raise AarAuditError("Empty AAR snapshot")
    snapshot.seek(0)
    return digest.hexdigest(), copied


def _require_name(name: str) -> None:
    path = PurePosixPath(name)
    if (not name or "\\" in name or name.startswith("/") or
            any(part in ("", ".", "..") for part in name.split("/")) or
            path.is_absolute() or "\x00" in name):
        raise AarAuditError("Archive contains unsafe entry path")


def _validate_elf(zipped: zipfile.ZipFile, info: zipfile.ZipInfo, abi: str) -> None:
    # Validate an entire ELF header and the bounded program-header table,
    # rather than trusting the first 20 bytes of an arbitrary file.
    with zipped.open(info) as stream:
        header = stream.read(64)
    elf_class, expected_machine = REQUIRED_ABIS[abi]
    header_size = 52 if elf_class == 1 else 64
    if (len(header) < header_size or header[:4] != b"\x7fELF" or
            header[4] != elf_class or header[5] != 1 or header[6] != 1):
        raise AarAuditError(f"Invalid ELF header for {abi}")
    e_type, e_machine, e_version = struct.unpack_from("<HHI", header, 16)
    if e_type != 3 or e_machine != expected_machine or e_version != 1:
        raise AarAuditError(f"Native library is not ELF ET_DYN for {abi}")
    if elf_class == 1:
        ph_offset = struct.unpack_from("<I", header, 28)[0]
        eh_size, ph_size, ph_count = struct.unpack_from("<HHH", header, 40)
        min_ph_size = 32
    else:
        ph_offset = struct.unpack_from("<Q", header, 32)[0]
        eh_size, ph_size, ph_count = struct.unpack_from("<HHH", header, 52)
        min_ph_size = 56
    if (eh_size != header_size or ph_offset < header_size or
            ph_size != min_ph_size or not 1 <= ph_count <= 4096 or
            ph_offset > MAX_PROGRAM_HEADER_OFFSET or
            ph_offset + ph_size * ph_count > info.file_size):
        raise AarAuditError(f"Invalid ELF program-header table for {abi}")

    # The header's offsets alone do not prove this is a loadable native ELF:
    # forged samples can point to an all-zero program-header table.
    end = ph_offset + ph_size * ph_count
    with zipped.open(info) as stream:
        prefix = stream.read(end)
    if len(prefix) != end:
        raise AarAuditError(f"Truncated ELF program-header table for {abi}")
    load_seen = False
    for index in range(ph_count):
        offset = ph_offset + index * ph_size
        if elf_class == 1:
            (kind, segment_offset, vaddr, _paddr, file_size, memory_size,
             _flags, alignment) = struct.unpack_from("<IIIIIIII", prefix, offset)
        else:
            (kind, _flags, segment_offset, vaddr, _paddr, file_size,
             memory_size, alignment) = struct.unpack_from("<IIQQQQQQ", prefix, offset)
        if kind != 1:  # PT_LOAD
            continue
        if (file_size == 0 or memory_size < file_size or
                segment_offset > info.file_size - file_size or
                (alignment not in (0, 1) and (
                    alignment & (alignment - 1) != 0 or
                    (vaddr - segment_offset) % alignment != 0
                ))):
            raise AarAuditError(f"Invalid ELF PT_LOAD segment for {abi}")
        load_seen = True
    if not load_seen:
        raise AarAuditError(f"ELF has no file-backed PT_LOAD for {abi}")


def _audit_classes_jar(zipped: zipfile.ZipFile, info: zipfile.ZipInfo) -> dict[int, int]:
    """Inspect the nested JAR, not just its ZIP signature.

    This proves bounded ZIP/classfile structure, NOT that lowering a Java 21
    major-version header to Java 17 produces valid compatible bytecode.
    """
    majors: dict[int, int] = {}
    found_webrtc_api = False
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as spool:
        with zipped.open(info) as source:
            transferred = 0
            while block := source.read(128 * 1024):
                transferred += len(block)
                if transferred > MAX_ENTRY_BYTES:
                    raise AarAuditError("Nested classes.jar exceeds bounded input")
                spool.write(block)
        spool.seek(0)
        with zipfile.ZipFile(spool) as jar:
            entries = jar.infolist()
            if len(entries) > MAX_JAR_ENTRIES:
                raise AarAuditError("Too many nested JAR entries")
            seen: set[str] = set()
            total = 0
            for item in entries:
                _require_name(item.filename[:-1] if item.is_dir() else item.filename)
                canonical = item.filename.rstrip("/").lower()
                if canonical in seen:
                    raise AarAuditError("Duplicate/case-aliased nested JAR entry")
                seen.add(canonical)
                if item.flag_bits & 1:
                    raise AarAuditError("Encrypted nested JAR entry")
                if stat.S_IFMT(item.external_attr >> 16) == stat.S_IFLNK:
                    raise AarAuditError("Symlink in nested JAR")
                if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise AarAuditError("Unsupported nested JAR compression")
                if item.file_size < 0 or item.file_size > MAX_JAR_ENTRY_BYTES:
                    raise AarAuditError("Oversized nested JAR entry")
                total += item.file_size
                if total > MAX_JAR_UNCOMPRESSED_BYTES:
                    raise AarAuditError("Nested JAR exceeds uncompressed bound")
                if item.file_size and (
                    item.compress_size <= 0 or
                    item.file_size / item.compress_size > MAX_COMPRESSION_RATIO
                ):
                    raise AarAuditError("Implausible nested JAR compression ratio")
                if not item.is_dir() and item.filename.endswith(".class"):
                    if item.file_size < 8:
                        raise AarAuditError("Truncated Java classfile")
                    with jar.open(item) as klass:
                        header = klass.read(8)
                    magic, minor, major = struct.unpack(">IHH", header)
                    if magic != 0xCAFEBABE or minor == 65535 or not 45 <= major <= MAX_CLASSFILE_MAJOR:
                        raise AarAuditError(
                            f"Unsupported Java classfile version {major}.{minor}"
                        )
                    majors[major] = majors.get(major, 0) + 1
                    # JVM/Android class paths are case-sensitive: a lowercase alias
                    # is not the actual org.webrtc.PeerConnection API.
                    if item.filename == "org/webrtc/PeerConnection.class":
                        found_webrtc_api = True
            if not majors:
                raise AarAuditError("WebRTC classes.jar contains no Java classfiles")
            if not found_webrtc_api:
                raise AarAuditError("WebRTC classes.jar has no org/webrtc/PeerConnection.class")
            if jar.testzip() is not None:
                raise AarAuditError("Nested JAR CRC verification failed")
    return majors


def _validate_required_content(
    zipped: zipfile.ZipFile, files: dict[str, zipfile.ZipInfo]
) -> dict[int, int]:
    # Names and first four signature bytes alone do not authenticate nested ZIPs.
    with zipped.open(files["classes.jar"]) as stream:
        jar_prefix = stream.read(4)
    if jar_prefix != b"PK\x03\x04":
        raise AarAuditError("AAR classes.jar is not a JAR/ZIP")
    class_versions = _audit_classes_jar(zipped, files["classes.jar"])
    with zipped.open(files["AndroidManifest.xml"]) as stream:
        manifest = stream.read(4096).lstrip(b"\xef\xbb\xbf\x09\x0a\x0d\x20")
    # Compiled Android XML starts with a RES_XML_TYPE chunk header. A magic
    # prefix alone does not prove a plausible chunk length.
    manifest_size = files["AndroidManifest.xml"].file_size
    binary_xml = (
        len(manifest) >= 8
        and manifest.startswith(b"\x03\x00\x08\x00")
        and manifest_size >= 16
        and manifest_size % 4 == 0
        and struct.unpack_from("<I", manifest, 4)[0] == manifest_size
    )
    # Common source-form manifests can have an XML declaration or comments,
    # but the first document element must still be <manifest>.
    text_xml = bool(re.match(
        rb"(?:<\?xml\s[^>]*\?>\s*)?(?:<!--.*?-->\s*)*<manifest(?=[\s/>])",
        manifest, re.DOTALL,
    ))
    if not binary_xml and not text_xml:
        raise AarAuditError("AAR manifest is not plausible XML")
    return class_versions


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
    # Keep the snapshot open through ZIP/classfile validation. Hash verification
    # of path A followed by reopening path B would allow an artifact-swap race.
    with tempfile.TemporaryFile() as snapshot:
        return _audit_aar_snapshot(
            Path(path), snapshot,
            expected_sha256=expected_sha256,
            report_only=report_only,
        )


def _audit_aar_snapshot(
    path: Path,
    snapshot,
    *,
    expected_sha256: str | None,
    report_only: bool,
) -> dict:
    if not report_only and expected_sha256 is None:
        raise AarAuditError("Expected SHA-256 is required for verification")
    if expected_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise AarAuditError("Expected SHA-256 must be exactly 64 lowercase hex digits")
    if not path.is_file() or path.stat().st_size not in range(1, MAX_AAR_BYTES + 1):
        raise AarAuditError("AAR file missing, empty or exceeds disk limit")
    observed, snapshot_bytes = _snapshot_and_sha256(path, snapshot)
    if expected_sha256 is not None and not hmac.compare_digest(expected_sha256, observed):
        raise AarAuditError("AAR SHA-256 does not match independently pinned digest")

    libnames: dict[str, set[str]] = {name: set() for name in REQUIRED_ABIS}
    native_paths = []
    license_paths = []
    class_versions: dict[int, int] = {}
    total_size = 0
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(snapshot) as zipped:
            entries = zipped.infolist()
            if len(entries) > MAX_ENTRIES:
                raise AarAuditError("Too many archive entries")
            for info in entries:
                _require_name(info.filename[:-1] if info.is_dir() else info.filename)
                canonical = info.filename.rstrip("/").lower()
                if canonical in seen:
                    raise AarAuditError("Duplicate/case-alias archive path")
                seen.add(canonical)
                if info.flag_bits & 1:
                    raise AarAuditError("Encrypted ZIP entries are not permitted")
                # Android AAR tooling expects stored/deflated ZIP entries; Python
                # can decode BZIP2/LZMA but accepting them would be misleading.
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise AarAuditError("Unsupported AAR ZIP compression method")
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
            files = {i.filename: i for i in entries if not i.is_dir()}
            if not {"classes.jar", "AndroidManifest.xml"}.issubset(files):
                raise AarAuditError("AAR is missing classes.jar or AndroidManifest.xml")
            class_versions = _validate_required_content(zipped, files)
            if not all(libnames.values()) or len({frozenset(x) for x in libnames.values()}) != 1:
                raise AarAuditError("Required ABI libraries missing or inconsistent across ABIs")
            if zipped.testzip() is not None:
                raise AarAuditError("AAR entry CRC verification failed")
    except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as error:
        raise AarAuditError("AAR ZIP parsing/CRC failed") from error

    return {
        "sha256": observed,
        "verified_against_expected_sha256": expected_sha256 is not None,
        "file_bytes": snapshot_bytes,
        "uncompressed_bytes": total_size,
        "required_abis": sorted(REQUIRED_ABIS),
        "native_paths": sorted(native_paths),
        "java_classfile_major_counts": {str(k): class_versions[k] for k in sorted(class_versions)},
        "embedded_license_or_notice_paths": sorted(license_paths),
        "remaining_reviews": [
            "source lineage and publisher",
            "classfile major-version rewriting versus actual JVM/D8 compatibility",
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
