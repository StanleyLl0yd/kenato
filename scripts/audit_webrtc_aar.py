#!/usr/bin/env python3
"""Offline, bounded structural audit of an explicitly supplied Android WebRTC AAR.

No fetching, dependency resolution or app activation. Passing structural checks
does NOT approve publisher/source lineage, licenses, native CVEs or device loading.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left
import hashlib
import hmac
import json
import re
import stat
import tempfile
import struct
import sys
import zipfile
import pyexpat
from pathlib import Path, PurePosixPath

REQUIRED_ABIS = {"armeabi-v7a": (1, 40), "arm64-v8a": (2, 183), "x86_64": (2, 62)}
# A vendor may also include 32-bit x86; Kenato's ABI filters do not package it.
OPTIONAL_ABIS = {"x86": (1, 3)}
SUPPORTED_ABIS = {**REQUIRED_ABIS, **OPTIONAL_ABIS}
MAX_AAR_BYTES = 250 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_ENTRY_BYTES = 200 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_COMPRESSION_RATIO = 1000
MAX_JAR_ENTRIES = 50000
MAX_JAR_UNCOMPRESSED_BYTES = 384 * 1024 * 1024
MAX_JAR_ENTRY_BYTES = 32 * 1024 * 1024
# Bound path normalization and file-parent checks even for hostile ZIP filenames.
MAX_ARCHIVE_PATH_CHARS = 4096
MAX_ARCHIVE_PATH_COMPONENTS = 128
# The pinned application build runs JDK 17. Classfile major 61 is Java 17.
MAX_CLASSFILE_MAJOR = 61
MAX_SOURCE_MANIFEST_BYTES = 1024 * 1024
MAX_BINARY_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_SOURCE_MANIFEST_DEPTH = 128
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
    if len(name) > MAX_ARCHIVE_PATH_CHARS:
        raise AarAuditError("Archive entry path exceeds length bound")
    parts = name.split("/")
    if len(parts) > MAX_ARCHIVE_PATH_COMPONENTS:
        raise AarAuditError("Archive entry path exceeds component bound")
    if (not name or "\\" in name or name.startswith("/") or
            any(part in ("", ".", "..") for part in parts) or
            PurePosixPath(name).is_absolute() or "\x00" in name):
        raise AarAuditError("Archive contains unsafe entry path")


def _require_regular_archive_type(info: zipfile.ZipInfo) -> None:
    """Fail closed on Unix FIFO/device/socket entries and inconsistent types."""
    kind = stat.S_IFMT(info.external_attr >> 16)
    if kind == stat.S_IFLNK:
        raise AarAuditError("Symlink entry is not permitted")
    allowed = (0, stat.S_IFDIR) if info.is_dir() else (0, stat.S_IFREG)
    if kind not in allowed:
        raise AarAuditError("Non-regular or inconsistent ZIP entry type")


def _reject_file_parent_collisions(entries: list[zipfile.ZipInfo]) -> None:
    """Detect file-as-parent with bounded sorted-prefix searches."""
    files = sorted(item.filename.lower() for item in entries if not item.is_dir())
    for name in files:
        prefix = name + "/"
        pos = bisect_left(files, prefix)
        if pos < len(files) and files[pos].startswith(prefix):
            raise AarAuditError("Archive file/directory path collision")


def _validate_elf(zipped: zipfile.ZipFile, info: zipfile.ZipInfo, abi: str) -> None:
    # Validate an entire ELF header and the bounded program-header table,
    # rather than trusting the first 20 bytes of an arbitrary file.
    with zipped.open(info) as stream:
        header = stream.read(64)
    elf_class, expected_machine = SUPPORTED_ABIS[abi]
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



def _require_webrtc_class_identity(contents: bytes) -> None:
    """Confirm the named API class declares the same internal JVM class name.

    This is a bounded constant-pool identity check, NOT full JVM/D8
    verification, source provenance or proof of executable bytecode safety.
    """
    view = memoryview(contents)
    size = len(view)
    if size < 18:
        raise AarAuditError("Truncated WebRTC Java class structure")

    def take_u2(offset: int) -> int:
        if offset + 2 > size:
            raise AarAuditError("Truncated WebRTC Java constant pool")
        return struct.unpack_from(">H", view, offset)[0]

    pool_size = take_u2(8)
    if pool_size < 5:
        raise AarAuditError("Invalid WebRTC Java constant pool count")
    strings: dict[int, bytes] = {}
    classes: dict[int, int] = {}
    index = 1
    offset = 10
    while index < pool_size:
        if offset >= size:
            raise AarAuditError("Truncated WebRTC Java constant pool")
        tag = view[offset]
        offset += 1
        if tag == 1:  # CONSTANT_Utf8
            length = take_u2(offset)
            offset += 2
            if offset + length > size:
                raise AarAuditError("Truncated WebRTC Java UTF8 constant")
            strings[index] = bytes(view[offset:offset + length])
            offset += length
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            length = 4
            if offset + length > size:
                raise AarAuditError("Truncated WebRTC Java constant pool")
            offset += length
        elif tag in (5, 6):  # Long/Double occupy two constant-pool slots
            if offset + 8 > size or index + 1 >= pool_size:
                raise AarAuditError("Invalid WebRTC Java long/double constant")
            offset += 8
            index += 1
        elif tag in (7, 8, 16, 19, 20):
            value = take_u2(offset)
            if tag == 7:
                classes[index] = value
            offset += 2
        elif tag == 15:
            if offset + 3 > size:
                raise AarAuditError("Truncated WebRTC Java method handle")
            offset += 3
        else:
            raise AarAuditError("Invalid WebRTC Java constant pool tag")
        index += 1
    if offset + 8 > size:
        raise AarAuditError("Truncated WebRTC Java class declaration")
    this_class = take_u2(offset + 2)
    declared = strings.get(classes.get(this_class, -1))
    if declared != b"org/webrtc/PeerConnection":
        raise AarAuditError("WebRTC PeerConnection.class declares another class identity")


def _audit_classes_jar(zipped: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[dict[int, int], bool]:
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
                    raise AarAuditError("Nested JAR exceeds bounded input")
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
                _require_regular_archive_type(item)
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
                        with jar.open(item) as klass:
                            class_bytes = klass.read(MAX_JAR_ENTRY_BYTES + 1)
                        if len(class_bytes) != item.file_size:
                            raise AarAuditError("Incomplete WebRTC classfile read")
                        _require_webrtc_class_identity(class_bytes)
                        found_webrtc_api = True
            if not majors:
                raise AarAuditError("Nested JAR contains no Java classfiles")
            _reject_file_parent_collisions(entries)
            if jar.testzip() is not None:
                raise AarAuditError("Nested JAR CRC verification failed")
    return majors, found_webrtc_api


def _validate_source_manifest_xml(manifest_xml: bytes) -> None:
    """Parse untrusted XML without loading an element tree or expanding DTDs."""
    parser = pyexpat.ParserCreate()
    parser.SetParamEntityParsing(pyexpat.XML_PARAM_ENTITY_PARSING_NEVER)
    depth = 0
    has_root = False

    def start(name: str, _attributes: dict) -> None:
        nonlocal depth, has_root
        if not has_root:
            if name != "manifest":
                raise AarAuditError("Source-form AAR manifest root is not <manifest>")
            has_root = True
        depth += 1
        if depth > MAX_SOURCE_MANIFEST_DEPTH:
            raise AarAuditError("Source-form AAR manifest nesting depth exceeded")

    def end(_name: str) -> None:
        nonlocal depth
        depth -= 1

    def reject_declaration(*_args) -> None:
        raise AarAuditError("DTD or entity declarations in AAR manifest")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    try:
        parser.Parse(manifest_xml, True)
    except pyexpat.ExpatError as error:
        raise AarAuditError("Malformed source-form AAR manifest XML") from error
    if not has_root or depth != 0:
        raise AarAuditError("Malformed source-form AAR manifest XML")



def _validate_binary_manifest_chunks(zipped: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
    """Check compiled Android XML chunk boundaries, not full XML semantics.

    This does not validate ResStringPool encoding, attribute values, Android
    resource references, JNI/D8 loading or any vendor binary provenance.
    """
    if info.file_size > MAX_BINARY_MANIFEST_BYTES:
        raise AarAuditError("Binary AAR manifest exceeds XML size bound")
    with zipped.open(info) as stream:
        data = stream.read(MAX_BINARY_MANIFEST_BYTES + 1)
    if len(data) != info.file_size:
        raise AarAuditError("Incomplete binary AAR manifest")
    if len(data) < 8 or struct.unpack_from("<HHI", data, 0) != (3, 8, len(data)):
        raise AarAuditError("Invalid compiled Android XML document header")

    offset = 8
    seen_strings = False
    element_depth = 0
    start_seen = False
    end_seen = False
    while offset < len(data):
        if len(data) - offset < 8:
            raise AarAuditError("Truncated compiled Android XML chunk header")
        kind, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if (header_size < 8 or chunk_size < header_size or chunk_size % 4 or
                offset + chunk_size > len(data)):
            raise AarAuditError("Invalid compiled Android XML chunk bounds")
        if not seen_strings:
            if kind != 1 or header_size < 28:
                raise AarAuditError("Compiled Android XML missing first string pool")
            seen_strings = True
        elif kind == 1:
            raise AarAuditError("Duplicate compiled Android XML string pool")
        elif kind == 0x0102:  # RES_XML_START_ELEMENT_TYPE
            if header_size < 16 or chunk_size < header_size + 20:
                raise AarAuditError("Invalid compiled Android XML start element")
            start_seen = True
            element_depth += 1
            if element_depth > MAX_SOURCE_MANIFEST_DEPTH:
                raise AarAuditError("Compiled Android XML element nesting exceeded")
        elif kind == 0x0103:  # RES_XML_END_ELEMENT_TYPE
            if header_size < 16 or chunk_size < header_size + 8 or element_depth == 0:
                raise AarAuditError("Invalid compiled Android XML end element")
            element_depth -= 1
            end_seen = True
        elif kind in (0x0180, 0x0100, 0x0101, 0x0104):
            # Resource IDs, namespace start/end, and CDATA are permitted.
            if kind != 0x0180 and header_size < 16:
                raise AarAuditError("Truncated compiled Android XML node header")
        else:
            raise AarAuditError("Unexpected compiled Android XML chunk type")
        offset += chunk_size

    if not (seen_strings and start_seen and end_seen) or element_depth != 0:
        raise AarAuditError("Compiled Android XML has no balanced element tree")


def _validate_required_content(
    zipped: zipfile.ZipFile, files: dict[str, zipfile.ZipInfo]
) -> tuple[dict[int, int], str]:
    # Some valid Android AARs keep the public WebRTC API in libs/libwebrtc.jar
    # while classes.jar holds wrapper metadata. Do not accept arbitrary JAR paths.
    allowed_jars = {"classes.jar", "libs/libwebrtc.jar"}
    if any(name.lower().endswith(".jar") and name not in allowed_jars for name in files):
        raise AarAuditError("Unreviewed nested AAR JAR path")
    class_versions: dict[int, int] = {}
    api_jar_paths: list[str] = []
    for jar_path in ("classes.jar", "libs/libwebrtc.jar"):
        if jar_path not in files:
            continue
        with zipped.open(files[jar_path]) as stream:
            if stream.read(4) != b"PK\x03\x04":
                raise AarAuditError("AAR nested Java library is not a JAR/ZIP")
        jar_versions, has_api = _audit_classes_jar(zipped, files[jar_path])
        for major, count in jar_versions.items():
            class_versions[major] = class_versions.get(major, 0) + count
        if has_api:
            api_jar_paths.append(jar_path)
    if len(api_jar_paths) != 1:
        raise AarAuditError("WebRTC org/webrtc/PeerConnection.class missing or duplicated across JARs")
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
    if binary_xml:
        _validate_binary_manifest_chunks(zipped, files["AndroidManifest.xml"])
        return class_versions, api_jar_paths[0]
    if not text_xml:
        raise AarAuditError("AAR manifest is not plausible XML")

    # A matching <manifest prefix is insufficient: malformed closing tags,
    # incomplete XML and trailing data must not count as valid source XML.
    # Keep parsing bounded and reject DTD/entity declarations up front.
    if manifest_size > MAX_SOURCE_MANIFEST_BYTES:
        raise AarAuditError("Source-form AAR manifest exceeds XML size bound")
    with zipped.open(files["AndroidManifest.xml"]) as stream:
        manifest_xml = stream.read(MAX_SOURCE_MANIFEST_BYTES + 1)
    if len(manifest_xml) > MAX_SOURCE_MANIFEST_BYTES:
        raise AarAuditError("Source-form AAR manifest exceeds XML size bound")
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", manifest_xml, re.IGNORECASE):
        raise AarAuditError("DTD or entity declarations in AAR manifest")
    _validate_source_manifest_xml(manifest_xml)
    return class_versions, api_jar_paths[0]


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

    libnames: dict[str, set[str]] = {name: set() for name in SUPPORTED_ABIS}
    native_paths = []
    license_paths = []
    class_versions: dict[int, int] = {}
    api_jar_path = ""
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
                _require_regular_archive_type(info)
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
                            parts[1] not in SUPPORTED_ABIS or
                            not parts[2].startswith("lib")):
                        raise AarAuditError("Unrecognized native library path/ABI")
                    abi = parts[1]
                    _validate_elf(zipped, info, abi)
                    libnames[abi].add(parts[2])
                    native_paths.append(info.filename)
                if ("license" in info.filename.lower() or
                        "notice" in info.filename.lower()):
                    license_paths.append(info.filename)
            _reject_file_parent_collisions(entries)
            files = {i.filename: i for i in entries if not i.is_dir()}
            if not {"classes.jar", "AndroidManifest.xml"}.issubset(files):
                raise AarAuditError("AAR is missing classes.jar or AndroidManifest.xml")
            class_versions, api_jar_path = _validate_required_content(zipped, files)
            required_names = [libnames[abi] for abi in REQUIRED_ABIS]
            if not all(required_names) or len({frozenset(x) for x in required_names}) != 1:
                raise AarAuditError("Required ABI libraries missing or inconsistent across ABIs")
            canonical_names = required_names[0]
            for abi in OPTIONAL_ABIS:
                if libnames[abi] and libnames[abi] != canonical_names:
                    raise AarAuditError(f"Optional ABI libraries inconsistent for {abi}")
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
        "optional_abis_present": sorted(abi for abi in OPTIONAL_ABIS if libnames[abi]),
        "native_paths": sorted(native_paths),
        "webrtc_api_jar": api_jar_path,
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
