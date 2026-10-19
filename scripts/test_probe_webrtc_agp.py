#!/usr/bin/env python3
"""No-network regression tests for the disposable M5 Android build probe."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zipfile

import probe_webrtc_agp as probe


def dex_fixture(*, defined=True):
    descriptor = probe.DESCRIPTOR
    data = bytearray(112 + 4 + 4 + 32 + 4 + len(descriptor) + 1)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 32, len(data))
    struct.pack_into("<I", data, 36, 112)
    struct.pack_into("<II", data, 56, 1, 112)
    struct.pack_into("<II", data, 64, 1, 116)
    struct.pack_into("<II", data, 96, 1 if defined else 0, 120)
    struct.pack_into("<I", data, 112, 152)
    struct.pack_into("<I", data, 116, 0)
    struct.pack_into("<I", data, 120, 0)
    data[152] = len(descriptor)
    data[153:153 + len(descriptor)] = descriptor
    return bytes(data)


def apk_fixture(path, *, defined=True, x86=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", dex_fixture(defined=defined))
        for abi in probe.ABIS:
            archive.writestr(f"lib/{abi}/{probe.NATIVE}", b"fake ELF")
        if x86:
            archive.writestr(f"lib/x86/{probe.NATIVE}", b"fake ELF")


class AgpProbeTests(unittest.TestCase):
    def test_dex_definition_not_raw_string_search(self):
        self.assertTrue(probe.dex_defines_class(dex_fixture()))
        self.assertFalse(probe.dex_defines_class(dex_fixture(defined=False)))
        with self.assertRaisesRegex(probe.ProbeError, "header"):
            probe.dex_defines_class(b"wrong")
        corrupt = bytearray(dex_fixture())
        struct.pack_into("<I", corrupt, 96, 0xffffffff)
        with self.assertRaisesRegex(probe.ProbeError, "DEX table"):
            probe.dex_defines_class(bytes(corrupt))

    def test_apk_inventory_accepts_only_three_expected_abis(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "test.apk"
            apk_fixture(apk)
            self.assertEqual(3, len(probe.inspect_apk(apk)["native_apk_paths"]))
            self.assertFalse(probe.inspect_apk(apk)["jni_loader_executed"])
            apk_fixture(apk, x86=True)
            with self.assertRaisesRegex(probe.ProbeError, "ABI inventory"):
                probe.inspect_apk(apk)
            apk_fixture(apk, defined=False)
            with self.assertRaisesRegex(probe.ProbeError, "definition absent"):
                probe.inspect_apk(apk)

    def test_disposable_app_is_not_kenato_app(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            aar = path / "fixture.aar"
            aar.write_bytes(b"fixture")
            project = path / "isolate"
            probe.write_disposable_app(project, aar)
            script = (project / "app/build.gradle").read_text()
            self.assertIn("9.4.0", script)
            self.assertIn("implementation files('../candidate.aar')", script)
            self.assertEqual(b"fixture", (project / "candidate.aar").read_bytes())
            self.assertIn("PeerConnection.class", (
                project / "app/src/main/java/org/kenato/research/Probe.java"
            ).read_text())

    def test_runner_requires_success_and_real_dex_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def good_runner(command, **kwargs):
                self.assertEqual(":app:assembleDebug", command[-1])
                apk_fixture(kwargs["cwd"] / "app/build/outputs/apk/debug/app-debug.apk")
                return type("Result", (), {"returncode": 0})()
            self.assertTrue(probe.run_disposable_build(root / "gradlew", root, runner=good_runner)[
                "dex_defines_peer_connection"])
            def bad_runner(*_args, **_kwargs):
                return type("Result", (), {"returncode": 1})()
            with self.assertRaisesRegex(probe.ProbeError, "assembleDebug failed"):
                probe.run_disposable_build(root / "gradlew", root, runner=bad_runner)

    def test_wrong_digest_fails_before_structural_audit_or_gradle(self):
        def wrong(_url, path):
            data = b"not the observed candidate"
            path.write_bytes(data)
            return hashlib.sha256(data).hexdigest(), len(data)
        with mock.patch.object(probe.evidence.audit, "audit_aar") as audit:
            report, passed = probe.collect(Path("/repo/gradlew"), downloader=wrong)
        self.assertFalse(passed)
        self.assertFalse(audit.called)
        self.assertFalse(report["vendor_approved"])
        self.assertEqual(set(report["results"]), set(probe.EXPECTED))
        self.assertTrue(all(
            item["status"] == "RESEARCH_PROBE_FAILED" for item in report["results"].values()
        ))


if __name__ == "__main__":
    unittest.main()
