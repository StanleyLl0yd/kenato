#!/usr/bin/env python3
"""Offline negative tests for manual, nonproduction JNI device APK."""
from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch
import probe_shiguredo_m157_device as probe

class DeviceTests(unittest.TestCase):
    def test_no_permissions_capture_network_or_auto_execution(self):
        self.assertNotIn("uses-permission", probe.MANIFEST)
        self.assertNotIn("RECORD_AUDIO", probe.MANIFEST)
        self.assertNotIn("INTERNET", probe.MANIFEST)
        self.assertIn("NOT_EXECUTED", probe.JAVA)
        self.assertIn("PASS_JNI_FACTORY_DISPOSE", probe.JAVA)
        self.assertNotIn("createAudioSource(", probe.JAVA)

    def test_isolated_gradle_and_java17_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "dummy.aar"
            file.write_bytes(b"synthetic")
            probe.write_device_probe(root / "app1", file)
            text = (root / "app1/app/build.gradle").read_text()
            self.assertIn(probe.PACKAGE, text)
            self.assertIn("abiFilters 'arm64-v8a'", text)
            self.assertIn("VERSION_17", text)

    def test_sdk_inspection_missing_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(probe.DeviceProbeError, "aapt2 unavailable"):
                probe.audit_manifest(Path(directory) / "app.apk", sdk=directory)

    def test_merged_permission_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / "build-tools/37.0.0/aapt2"
            tool.parent.mkdir(parents=True)
            tool.touch()
            fake = CompletedProcess([], 0, b"E: manifest\n E: uses-permission\n", b"")
            with self.assertRaisesRegex(probe.DeviceProbeError, "permissions"):
                probe.audit_manifest(Path(directory) / "app.apk", sdk=directory,
                                     runner=lambda *a, **k: fake)

    def test_missing_activity_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / "build-tools/37.0.0/aapt2"
            tool.parent.mkdir(parents=True)
            tool.touch()
            fake = CompletedProcess([], 0, b"E: manifest\n", b"")
            with self.assertRaisesRegex(probe.DeviceProbeError, "activity missing"):
                probe.audit_manifest(Path(directory) / "app.apk", sdk=directory,
                                     runner=lambda *a, **k: fake)

    def test_zipalign_absent_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(probe.DeviceProbeError, "zipalign unavailable"):
                probe.audit_apk_16k_zip_alignment(Path(directory) / "app.apk", sdk=directory)

    def test_zipalign_rejects_native_page_misalignment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-tools/37.0.0/zipalign"
            path.parent.mkdir(parents=True)
            path.touch()
            result = CompletedProcess([], 1, b"Verification FAILED", b"")
            with self.assertRaisesRegex(probe.DeviceProbeError, "not 16KiB aligned"):
                probe.audit_apk_16k_zip_alignment(Path(directory) / "app.apk",
                                                 sdk=directory, runner=lambda *a, **k: result)

    def test_zipalign_verifies_without_modifying_apk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-tools/37.0.0/zipalign"
            path.parent.mkdir(parents=True)
            path.touch()
            apk = Path(directory) / "sample.apk"
            args_seen = []
            def fake_run(args, **kwargs):
                args_seen.extend(args)
                return CompletedProcess(args, 0, b"Verification successful\n", b"")
            probe.audit_apk_16k_zip_alignment(apk, sdk=directory, runner=fake_run)
            self.assertEqual(args_seen[1:-1], ["-c", "-P", "16", "-v", "4"])
            self.assertEqual(args_seen[-1], str(apk))

    def test_zipalign_no_success_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / "build-tools/37.0.0/zipalign"
            tool.parent.mkdir(parents=True)
            tool.touch()
            ok_but_incomplete = CompletedProcess([], 0, b"", b"")
            with self.assertRaisesRegex(probe.DeviceProbeError, "not 16KiB aligned"):
                probe.audit_apk_16k_zip_alignment(Path(directory) / "app.apk",
                           sdk=directory, runner=lambda *a, **k: ok_but_incomplete)

    def test_corrupt_vendor_digest_blocks_build(self):
        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory) / "gradlew"
            wrapper.write_text("#!/bin/sh\n")
            def broken(_url, path, *, max_bytes):
                path.write_bytes(b"bad")
                return "0" * 64, 3
            with patch.object(probe, "write_device_probe") as make:
                with self.assertRaises(probe.vendor.CandidateProbeError):
                    probe.build(wrapper, None, downloader=broken)
                make.assert_not_called()

if __name__ == "__main__":
    unittest.main()
