#!/usr/bin/env python3
"""Offline synthetic fixture tests; never fetch or execute third-party binaries."""
from __future__ import annotations

import importlib.util
import hashlib
import io
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).with_name("audit_webrtc_aar.py")
SPEC = importlib.util.spec_from_file_location("kenato_aar_audit", SOURCE)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def elf(elf_class: int, machine: int, *, truncated: bool = False,
        malformed_segment: str | None = None) -> bytes:
    hdr_size = 52 if elf_class == 1 else 64
    ph_size = 32 if elf_class == 1 else 56
    header = bytearray(hdr_size + ph_size)
    header[:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHI", header, 16, 3, machine, 1)
    if elf_class == 1:
        struct.pack_into("<I", header, 28, hdr_size)
        struct.pack_into("<HHH", header, 40, hdr_size, ph_size, 1)
    else:
        struct.pack_into("<Q", header, 32, hdr_size)
        struct.pack_into("<HHH", header, 52, hdr_size, ph_size, 1)
    segment_size = len(header) + (1 if malformed_segment == "out_of_bounds" else 0)
    segment_memory_size = segment_size - (1 if malformed_segment == "short_memory" else 0)
    kind = 4 if malformed_segment == "no_load" else 1
    alignment = 3 if malformed_segment == "invalid_alignment" else 1
    if elf_class == 1:
        struct.pack_into("<IIIIIIII", header, hdr_size,
                         kind, 0, 0, 0, segment_size, segment_memory_size, 5, alignment)
    else:
        struct.pack_into("<IIQQQQQQ", header, hdr_size,
                         kind, 5, 0, 0, 0, segment_size, segment_memory_size, alignment)
    if malformed_segment == "noncanonical_stride":
        header.extend(bytes(4))
        struct.pack_into("<H", header, 42 if elf_class == 1 else 54, ph_size + 4)
    return bytes(header[:20] if truncated else header)


def aar_file(folder: Path, *, missing: str | None = None,
             tampered_elf: bool = False, truncated_elf: bool = False,
             fake_jar: bool = False, fake_manifest: bool = False,
             traversal: bool = False,
             symlink: bool = False, duplicates: bool = False,
             class_major: int = 61, fake_class: bool = False,
             non_webrtc_class: bool = False,
             incorrect_api_case: bool = False,
             preview_class: bool = False, nested_traversal: bool = False,
             nested_duplicates: bool = False, nested_symlink: bool = False,
             empty_classes: bool = False, corrupt_jar: bool = False,
             malformed_segment: str | None = None,
             malformed_abi: str = "arm64-v8a",
             outer_compression: int = zipfile.ZIP_DEFLATED) -> Path:
    path = folder / "sample.aar"
    with zipfile.ZipFile(path, "w", compression=outer_compression) as output:
        jar_output = io.BytesIO()
        with zipfile.ZipFile(jar_output, "w") as jar:
            jar.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            if not empty_classes:
                klass = (b"badclass" if fake_class else
                         struct.pack(">IHH", 0xCAFEBABE,
                                     65535 if preview_class else 0, class_major))
                jar.writestr(
                    "org/example/Dummy.class" if non_webrtc_class else
                    "org/webrtc/peerconnection.class" if incorrect_api_case else
                    "org/webrtc/PeerConnection.class", klass
                )
            if nested_traversal:
                jar.writestr("../escape.class", b"forbidden")
            if nested_duplicates:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    jar.writestr("org/webrtc/PeerConnection.class", b"duplicate")
            if nested_symlink:
                entry = zipfile.ZipInfo("META-INF/link")
                entry.create_system = 3
                entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                jar.writestr(entry, b"elsewhere")
        jar_bytes = jar_output.getvalue()
        if corrupt_jar:
            jar_bytes = jar_bytes[:24]
        output.writestr("classes.jar", b"fake jar payload" if fake_jar else jar_bytes)
        output.writestr(
            "AndroidManifest.xml",
            b"manifest" if fake_manifest else b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"/>',
        )
        output.writestr("LICENSE", b"test fixture; no upstream license claims")
        for abi, (kind, machine) in audit.REQUIRED_ABIS.items():
            if abi != missing:
                value = elf(
                    kind, machine, truncated=truncated_elf and abi == "arm64-v8a",
                    malformed_segment=malformed_segment if abi == malformed_abi else None,
                )
                if tampered_elf and abi == "arm64-v8a":
                    value = b"not-elf"
                output.writestr(f"jni/{abi}/libjingle_peerconnection_so.so", value)
        if traversal:
            output.writestr("../escape.so", b"forbidden")
        if symlink:
            item = zipfile.ZipInfo("jni/link")
            item.create_system = 3
            item.external_attr = (stat.S_IFLNK | 0o777) << 16
            output.writestr(item, b"somewhere")
        if duplicates:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                output.writestr("classes.jar", b"malicious duplicate")
    return path


class AarAuditTests(unittest.TestCase):
    def test_independently_pinned_hash_and_expected_abis(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = aar_file(Path(tmp))
            report = audit.audit_aar(path, report_only=True)
            self.assertFalse(report["verified_against_expected_sha256"])
            self.assertEqual(3, len(report["native_paths"]))
            verified = audit.audit_aar(path, expected_sha256=report["sha256"])
            self.assertTrue(verified["verified_against_expected_sha256"])
            self.assertEqual(4, len(verified["sha256"]) // 16)

    def test_hash_and_validation_use_same_snapshot_after_path_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original_dir, replacement_dir = root / "original", root / "replacement"
            original_dir.mkdir()
            replacement_dir.mkdir()
            path = aar_file(original_dir)
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            replacement_bytes = aar_file(replacement_dir, class_major=60).read_bytes()
            self.assertNotEqual(expected, hashlib.sha256(replacement_bytes).hexdigest())

            original_snapshot = audit._snapshot_and_sha256

            def swap_source_path_after_hash(source: Path, snapshot):
                result = original_snapshot(source, snapshot)
                source.write_bytes(replacement_bytes)
                return result

            with mock.patch.object(
                audit, "_snapshot_and_sha256", side_effect=swap_source_path_after_hash
            ):
                report = audit.audit_aar(path, expected_sha256=expected)
            self.assertTrue(report["verified_against_expected_sha256"])
            self.assertEqual(expected, report["sha256"])
            self.assertEqual({"61": 1}, report["java_classfile_major_counts"])
            self.assertNotEqual(expected, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_missing_digest_is_never_a_valid_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = aar_file(Path(tmp))
            with self.assertRaises(audit.AarAuditError):
                audit.audit_aar(path)
            with self.assertRaises(audit.AarAuditError):
                audit.audit_aar(path, expected_sha256="0" * 64)

    def test_missing_abi_and_invalid_native_elf_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kwargs in ({"missing": "x86_64"}, {"tampered_elf": True}):
                path = aar_file(Path(tmp), **kwargs)
                with self.assertRaises(audit.AarAuditError):
                    audit.audit_aar(path, report_only=True)

    def test_program_header_forgery_and_invalid_load_segments_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            for abi in audit.REQUIRED_ABIS:
                for fault in ("no_load", "out_of_bounds", "short_memory",
                              "invalid_alignment", "noncanonical_stride"):
                    path = aar_file(Path(tmp), malformed_segment=fault, malformed_abi=abi)
                    with self.subTest(abi=abi, fault=fault), self.assertRaises(audit.AarAuditError):
                        audit.audit_aar(path, report_only=True)

    def test_placeholder_elf_jar_and_manifest_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kwargs in (
                {"truncated_elf": True},
                {"fake_jar": True},
                {"fake_manifest": True},
            ):
                path = aar_file(Path(tmp), **kwargs)
                with self.assertRaises(audit.AarAuditError):
                    audit.audit_aar(path, report_only=True)

    def test_outer_aar_zip_requires_android_compatible_compression(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = aar_file(Path(tmp), outer_compression=zipfile.ZIP_STORED)
            self.assertEqual(3, len(audit.audit_aar(path, report_only=True)["native_paths"]))
            for method in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
                path = aar_file(Path(tmp), outer_compression=method)
                with self.subTest(method=method), self.assertRaisesRegex(
                    audit.AarAuditError, "Unsupported AAR ZIP compression method"
                ):
                    audit.audit_aar(path, report_only=True)

    def test_traversal_symlink_and_duplicate_zip_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kwargs in ({"traversal": True}, {"symlink": True}, {"duplicates": True}):
                path = aar_file(Path(tmp), **kwargs)
                with self.assertRaises(audit.AarAuditError):
                    audit.audit_aar(path, report_only=True)

    def test_java_17_nested_classfile_gate_and_major_version_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = aar_file(Path(tmp), class_major=61)
            result = audit.audit_aar(path, report_only=True)
            self.assertEqual({"61": 1}, result["java_classfile_major_counts"])
            for kwargs in (
                {"class_major": 65},
                {"class_major": 44},
                {"fake_class": True},
                {"preview_class": True},
                {"empty_classes": True},
            ):
                path = aar_file(Path(tmp), **kwargs)
                with self.subTest(kwargs=kwargs), self.assertRaises(audit.AarAuditError):
                    audit.audit_aar(path, report_only=True)

    def test_unrelated_java_class_cannot_impersonate_webrtc_aar(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kwargs in ({"non_webrtc_class": True}, {"incorrect_api_case": True}):
                path = aar_file(Path(tmp), **kwargs)
                with self.subTest(kwargs=kwargs), self.assertRaisesRegex(
                    audit.AarAuditError, "org/webrtc/PeerConnection.class"
                ):
                    audit.audit_aar(path, report_only=True)

    def test_nested_jar_path_alias_symlink_and_truncation_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kwargs in (
                {"nested_traversal": True},
                {"nested_duplicates": True},
                {"nested_symlink": True},
                {"corrupt_jar": True},
            ):
                path = aar_file(Path(tmp), **kwargs)
                with self.subTest(kwargs=kwargs), self.assertRaises(audit.AarAuditError):
                    audit.audit_aar(path, report_only=True)

    def test_truncated_archive_and_unknown_format_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = aar_file(Path(tmp))
            raw = path.read_bytes()
            path.write_bytes(raw[:50])
            with self.assertRaises(audit.AarAuditError):
                audit.audit_aar(path, report_only=True)


if __name__ == "__main__":
    unittest.main()
