#!/usr/bin/env python3
"""Offline synthetic fixture tests; never fetch or execute third-party binaries."""
from __future__ import annotations

import importlib.util
import io
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

SOURCE = Path(__file__).with_name("audit_webrtc_aar.py")
SPEC = importlib.util.spec_from_file_location("kenato_aar_audit", SOURCE)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def elf(elf_class: int, machine: int, *, truncated: bool = False) -> bytes:
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
    return bytes(header[:20] if truncated else header)


def aar_file(folder: Path, *, missing: str | None = None,
             tampered_elf: bool = False, truncated_elf: bool = False,
             fake_jar: bool = False, fake_manifest: bool = False,
             traversal: bool = False,
             symlink: bool = False, duplicates: bool = False) -> Path:
    path = folder / "sample.aar"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as output:
        jar_output = io.BytesIO()
        with zipfile.ZipFile(jar_output, "w") as jar:
            jar.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        output.writestr("classes.jar", b"fake jar payload" if fake_jar else jar_output.getvalue())
        output.writestr(
            "AndroidManifest.xml",
            b"manifest" if fake_manifest else b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"/>',
        )
        output.writestr("LICENSE", b"test fixture; no upstream license claims")
        for abi, (kind, machine) in audit.REQUIRED_ABIS.items():
            if abi != missing:
                value = elf(kind, machine, truncated=truncated_elf and abi == "arm64-v8a")
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

    def test_traversal_symlink_and_duplicate_zip_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kwargs in ({"traversal": True}, {"symlink": True}, {"duplicates": True}):
                path = aar_file(Path(tmp), **kwargs)
                with self.assertRaises(audit.AarAuditError):
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
