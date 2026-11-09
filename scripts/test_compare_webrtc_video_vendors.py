#!/usr/bin/env python3
"""Offline negatives for exact-vendor video AAR comparator."""
from __future__ import annotations

import io
import unittest
import zipfile
from unittest import mock

import compare_webrtc_video_vendors as target

class VideoCompareTests(unittest.TestCase):
    def test_exact_pins(self):
        for label, (_url, digest, size) in target.VENDORS.items():
            target.verify_pinned(label, digest, size)
            with self.assertRaises(target.CompareError):
                target.verify_pinned(label, "0" * 64, size)
            with self.assertRaises(target.CompareError):
                target.verify_pinned(label, digest, size + 1)
        with self.assertRaises(target.CompareError):
            target.verify_pinned("unknown", "0" * 64, 1)

    def jar(self, classes):
        mem = io.BytesIO()
        with zipfile.ZipFile(mem, "w") as z:
            for name in classes:
                z.writestr(target.VIDEO_CLASSES + name + ".class", b"synthetic")
        return mem.getvalue()

    def test_video_api_full_and_missing(self):
        result = target.video_class_inventory(self.jar(target.REQUIRED_VIDEO_API))
        self.assertTrue(result["required_video_api_all_present"])
        self.assertFalse(result["optional_video_class_present"]["Camera1Enumerator"])
        result = target.video_class_inventory(self.jar(("VideoTrack",)))
        self.assertFalse(result["required_video_api_all_present"])
        self.assertTrue(result["required_video_class_present"]["VideoTrack"])
        self.assertFalse(result["required_video_class_present"]["Camera2Enumerator"])

    def test_duplicate_jar_paths_fail(self):
        mem = io.BytesIO()
        with zipfile.ZipFile(mem, "w") as archive:
            with mock.patch("warnings.warn"):
                archive.writestr("org/webrtc/VideoTrack.class", b"one")
                archive.writestr("org/webrtc/VideoTrack.class", b"two")
        with self.assertRaises(target.CompareError):
            target.video_class_inventory(mem.getvalue())

    def test_truncated_jar_fails(self):
        with self.assertRaises(target.CompareError):
            target.video_class_inventory(b"bad zip")

    def test_no_implicit_execution_or_approval(self):
        report = target.video_class_inventory(self.jar(("VideoTrack",)))
        self.assertTrue(report["java_api_presence_is_not_video_codec_availability"])
        self.assertEqual(set(target.VENDORS), {
            "shiguredo_m157_8103_4_0", "webrtc_sdk_v150_7871_04_full"
        })
        self.assertNotIn("stripped", " ".join(url for url, _, _ in target.VENDORS.values()))

if __name__ == "__main__":
    unittest.main()
