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
            self.assertIn("versionCode 1", script)
            self.assertIn("versionName '0.0.0-research'", script)

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

    def test_explicit_notice_asset_requires_verified_original_bytes(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = root / "vendor.aar"
            data = (b"Copyright x" * 32)
            with zipfile.ZipFile(candidate, "w") as archive:
                archive.writestr("META-INF/NOTICE", data)
            with mock.patch.object(d8, "NOTICE_BYTES", len(data)), mock.patch.object(
                    d8, "NOTICE_SHA256", hashlib.sha256(data).hexdigest()):
                d8.include_reviewed_notice_asset(root / "app_fixture", candidate)
                self.assertEqual((root / "app_fixture" / d8.NOTICE_ASSET).read_bytes(), data)
            with self.assertRaisesRegex(d8.D8ResearchError, "SHA-256"):
                with mock.patch.object(d8, "NOTICE_BYTES", len(data)):
                    d8.include_reviewed_notice_asset(root / "wrong", candidate)

    def test_explicit_notice_rejects_missing_archive_member(self):
        with tempfile.TemporaryDirectory() as temp:
            vendor = Path(temp) / "vendor.aar"
            with zipfile.ZipFile(vendor, "w") as archive:
                archive.writestr("classes.jar", b"fake")
            with self.assertRaisesRegex(d8.D8ResearchError, "NOTICE"):
                d8.include_reviewed_notice_asset(Path(temp) / "fixture", vendor)

    def test_newer_patch_uses_independent_pinned_asset_and_never_builds_on_old_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            wrapper = Path(temp) / "gradlew"
            wrapper.write_text("#!/bin/sh\n")

            def stale_download(url, target, *, max_bytes):
                self.assertEqual(url, d8.m157.PATCH_RELEASE_URL)
                target.write_bytes(b"wrong candidate")
                return d8.m157.EXPECTED_SHA256, d8.m157.EXPECTED_SIZE

            with mock.patch.object(d8, "subprocess") as process:
                with self.assertRaises(d8.m157.CandidateProbeError):
                    d8.collect(wrapper, downloader=stale_download, tag=d8.m157.PATCH_TAG)
                process.run.assert_not_called()

    def test_newer_patch_rejects_unreviewed_tag_before_download(self):
        with tempfile.TemporaryDirectory() as temp:
            wrapper = Path(temp) / "gradlew"
            wrapper.write_text("#!/bin/sh\n")
            with mock.patch.object(d8, "subprocess") as process:
                with self.assertRaises(d8.m157.CandidateProbeError):
                    d8.collect(wrapper, tag="m158.unreviewed")
                process.run.assert_not_called()

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


    def test_disposable_aab_notice_bound_to_exact_hash_and_arm64(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp) / "app-debug.aab"
            notice = b"publisher NOTICE exact binary fixture"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr(d8.AAB_JNI_ENTRY, b"elf-fixture")
                archive.writestr("base/dex/classes.dex", b"dex-fixture")
                archive.writestr(d8.AAB_NOTICE_ENTRY, notice)
            with mock.patch.object(d8, "NOTICE_BYTES", len(notice)), mock.patch.object(
                    d8, "NOTICE_SHA256", hashlib.sha256(notice).hexdigest()):
                result = d8.inspect_arm64_bundle(bundle)
                self.assertEqual(result["verified_notice_aab_path"], d8.AAB_NOTICE_ENTRY)
                self.assertEqual(result["native_aab_paths"], [d8.AAB_JNI_ENTRY])
                self.assertFalse(result["JNI_executed"])
            with mock.patch.object(d8, "NOTICE_BYTES", len(notice)):
                with self.assertRaisesRegex(d8.D8ResearchError, "SHA-256"):
                    d8.inspect_arm64_bundle(bundle)

    def test_disposable_aab_rejects_missing_notice_and_wrong_abi(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp) / "app-debug.aab"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr(d8.AAB_JNI_ENTRY, b"elf-fixture")
                archive.writestr("base/dex/classes.dex", b"dex-fixture")
            with self.assertRaisesRegex(d8.D8ResearchError, "NOTICE"):
                d8.inspect_arm64_bundle(bundle)
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("base/lib/x86_64/libjingle_peerconnection_so.so", b"elf-fixture")
                archive.writestr("base/dex/classes.dex", b"dex-fixture")
                archive.writestr(d8.AAB_NOTICE_ENTRY, b"fixture")
            with self.assertRaisesRegex(d8.D8ResearchError, "ABI"):
                d8.inspect_arm64_bundle(bundle)

    def test_disposable_aab_rejects_duplicate_entries_and_missing_dex(self):
        import warnings
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp) / "app-debug.aab"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr(d8.AAB_JNI_ENTRY, b"elf-fixture")
                archive.writestr(d8.AAB_NOTICE_ENTRY, b"fixture")
            with self.assertRaisesRegex(d8.D8ResearchError, "DEX"):
                d8.inspect_arm64_bundle(bundle)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(bundle, "w") as archive:
                    archive.writestr(d8.AAB_JNI_ENTRY, b"elf-fixture")
                    archive.writestr("base/dex/classes.dex", b"dex-fixture")
                    archive.writestr(d8.AAB_NOTICE_ENTRY, b"fixture")
                    archive.writestr(d8.AAB_NOTICE_ENTRY, b"duplicate")
            with self.assertRaisesRegex(d8.D8ResearchError, "inventory"):
                d8.inspect_arm64_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
