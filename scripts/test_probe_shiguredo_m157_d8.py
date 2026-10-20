#!/usr/bin/env python3
"""No network or Gradle execution: synthetic m157 ARM64 D8 probe tests."""
from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import probe_shiguredo_m157_d8 as d8


class ShiguredoD8ResearchTests(unittest.TestCase):
    def test_disposable_gradle_selects_arm64_without_touching_production(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = root / "candidate.aar"
            fixture.write_bytes(b"fake unsigned test fixture")
            d8.write_arm64_probe(root / "probe", fixture)
            script = (root / "probe/app/build.gradle").read_text(encoding="utf-8")
            self.assertIn(d8.RESEARCH_ABIS, script)
            self.assertNotIn(d8.DEFAULT_ABIS, script)
            self.assertIn("compileSdk 37", script)
            self.assertIn("VERSION_17", script)

    def test_disposable_apk_fails_closed_without_dex(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "app.apk"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("lib/arm64-v8a/libjingle_peerconnection_so.so", b"elf-fixture")
            with self.assertRaisesRegex(d8.D8ResearchError, "DEX"):
                d8.inspect_arm64_apk(path)

    def test_unexpected_x86_packaging_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "app.apk"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("lib/arm64-v8a/libjingle_peerconnection_so.so", b"fixture")
                z.writestr("lib/x86_64/libjingle_peerconnection_so.so", b"fixture")
            with self.assertRaisesRegex(d8.D8ResearchError, "ABI"):
                d8.inspect_arm64_apk(path)

    def test_wrong_release_digest_never_starts_gradle(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "gradlew"
            p.write_text("#!/bin/sh\n")
            def invalid(_url, target, *, max_bytes):
                target.write_bytes(b"wrong")
                return "0" * 64, len(b"wrong")
            with mock.patch.object(d8, "subprocess") as process:
                with self.assertRaises(d8.m157.CandidateProbeError):
                    d8.collect(p, downloader=invalid)
                process.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
