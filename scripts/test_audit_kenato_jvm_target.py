#!/usr/bin/env python3
"""Positive/negative cases for bytecode target policy."""
from __future__ import annotations

import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from audit_kenato_jvm_target import TargetAuditError, audit, check_classfile


def header(major: int) -> bytes:
    return b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, major)


class AuditTests(unittest.TestCase):
    def test_loose_java17_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "intermediates" / "kotlin" / "com/sl/kenato/MainActivity.class"
            path.parent.mkdir(parents=True)
            path.write_bytes(header(61))
            self.assertEqual(audit(Path(directory)), (1, 1))

    def test_loose_java25_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tmp" / "kotlin" / "com/sl/kenato/MainActivity.class"
            path.parent.mkdir(parents=True)
            path.write_bytes(header(69))
            with self.assertRaisesRegex(TargetAuditError, "exceeds allowed"):
                audit(Path(directory))

    def test_java25_in_generated_jar_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / "intermediates" / "classes.jar"
            jar.parent.mkdir(parents=True)
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("com/sl/kenato/MainActivity.class", header(69))
            with self.assertRaisesRegex(TargetAuditError, "exceeds allowed"):
                audit(Path(directory))

    def test_java17_in_generated_jar_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / "intermediates" / "classes.jar"
            jar.parent.mkdir(parents=True)
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("com/sl/kenato/MainActivity.class", header(61))
            self.assertEqual(audit(Path(directory)), (1, 1))

    def test_missing_main_activity_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "intermediates").mkdir()
            with self.assertRaisesRegex(TargetAuditError, "MainActivity.class missing"):
                audit(Path(directory))

    def test_corrupt_class_fails_closed(self):
        with self.assertRaisesRegex(TargetAuditError, "invalid Java classfile"):
            check_classfile("com/sl/kenato/MainActivity.class", b"bad", 61)

    def test_bad_jar_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / "intermediates" / "broken.jar"
            jar.parent.mkdir(parents=True)
            jar.write_bytes(b"bad")
            with self.assertRaises(zipfile.BadZipFile):
                audit(Path(directory))

    def test_dependency_namespace_is_not_our_target(self):
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / "intermediates" / "vendor.jar"
            jar.parent.mkdir(parents=True)
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("org/webrtc/PeerConnection.class", header(69))
                archive.writestr("com/sl/kenato/MainActivity.class", header(61))
            self.assertEqual(audit(Path(directory)), (1, 1))


if __name__ == "__main__":
    unittest.main()
