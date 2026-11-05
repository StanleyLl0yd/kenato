#!/usr/bin/env python3
"""No-network fail-closed tests for exact Shiguredo m158 research evidence."""
from __future__ import annotations

import hashlib
import unittest
from unittest import mock

import probe_shiguredo_m158_patch_security as target


class M158PinnedEvidenceTests(unittest.TestCase):
    def test_exact_sources_only(self):
        self.assertEqual(target.allowed_url(target.PRODUCER_ROOT + "VERSION")[0],
                         "raw.githubusercontent.com")
        self.assertEqual(target.allowed_url(
            target.SOURCE_ROOT + target.SOURCE_PATHS[0] + "?format=TEXT")[0],
            "webrtc.googlesource.com")
        for source in (
            target.PRODUCER_ROOT + "patches/logging_sink_min_severity.patch",
            target.SOURCE_ROOT + "../HEAD?format=TEXT",
            target.PRODUCER_ROOT.replace(target.PRODUCER_SHA, "0"*40) + "VERSION",
            "http://webrtc.googlesource.com/src/HEAD",
        ):
            with self.assertRaises(target.M158EvidenceError):
                target.allowed_url(source)

    def test_exact_status_retry_and_no_redirect(self):
        url = target.PRODUCER_ROOT + "VERSION"
        calls = []
        sleep = []
        def runner(argv, **kwargs):
            calls.append(list(argv))
            status = b"503" if len(calls) == 1 else b"200"
            return mock.Mock(returncode=0, stdout=(
                b"WEBRTC_BUILD_VERSION=158.8127.1.0" +
                b"\n@@KENATO_STATUS:" + status
            ))
        self.assertEqual(target.fetch_exact(
            url, runner=runner, sleeper=sleep.append),
            b"WEBRTC_BUILD_VERSION=158.8127.1.0")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])
        self.assertNotIn("--location", calls[0])
        self.assertEqual(calls[0][-1], url)
        self.assertEqual(sleep, [1])

        def not_found(argv, **kwargs):
            return mock.Mock(returncode=0, stdout=b"missing\n@@KENATO_STATUS:404")
        with self.assertRaises(target.M158EvidenceError):
            target.fetch_exact(url, runner=not_found,
                               sleeper=lambda _: self.fail("404 should not retry"))

    def test_patch_chain_and_source_cve_conflict_refusal(self):
        sample = ("WEBRTC_BUILD_VERSION=158.8127.1.0\nWEBRTC_COMMIT=" +
                  target.SOURCE_SHA)
        run = ("COMMON_GN_ARGS = ['rtc_use_h264=false']\n" +
               'os.path.join("tools_webrtc", "libs", "generate_licenses.py")\n' +
               "PATCHES = {'android': [" +
               ", ".join(repr(x) for x in target.PATCHES) +
               "], 'android_sdk': [" +
               ", ".join(repr(x) for x in target.PATCHES) + "]}")
        patches = {name: "diff --git a/fixture/" + name + " b/fixture/" + name
                   for name in target.PATCHES}
        new = target.PATCHES[-1]
        patches[new] = (
            "diff --git a/sdk/android/api/org/webrtc/YuvConverter.java "
            "b/sdk/android/api/org/webrtc/YuvConverter.java\n"
            + "\n".join("+" + line for line in (
                "    } catch (RuntimeException e) {",
                "      i420TextureFrameBuffer.release();",
                "    boolean bufferOwnershipTransferred = false;",
                "    ByteBuffer i420ByteBuffer = null;",
                "    final ByteBuffer allocatedBuffer = JniCommon.nativeAllocateByteBuffer(stride * totalHeight);",
                "    i420ByteBuffer = allocatedBuffer;",
                "    I420Buffer i420Buffer = JavaI420Buffer.wrap(frameWidth, frameHeight, dataY, stride, dataU,",
                "    bufferOwnershipTransferred = true;",
                "    } finally {",
                "      preparedBuffer.release();",
                "      if (!bufferOwnershipTransferred && i420ByteBuffer != null) {",
                "        JniCommon.nativeFreeByteBuffer(i420ByteBuffer);",
            ))
            + "\ndiff --git a/sdk/android/src/jni/android_video_track_source.cc "
            "b/sdk/android/src/jni/android_video_track_source.cc\n"
            + "\n".join("+" + line for line in (
                "  if (apply_rotation() && rotation != kVideoRotation_0) {",
                "    if (!buffer) {",
                '      RTC_LOG(LS_ERROR) << "Failed to convert the frame to I420. Dropping it.";',
                "      OnFrameDropped();",
                "      return;",
            ))
        )
        result = target.verify_producer(sample, run, patches)
        self.assertEqual(result["patch_count"], 21)
        self.assertFalse(result["rtc_use_h264"])
        self.assertFalse(result["native_source_equivalence_or_patch_reachability_verified"])
        self.assertEqual(result["patch_sha256"][new],
                         hashlib.sha256(patches[new].encode()).hexdigest())

        with self.assertRaises(target.M158EvidenceError):
            target.verify_producer(sample.replace(target.SOURCE_SHA, "0"*40),
                                   run, patches)
        with self.assertRaises(target.M158EvidenceError):
            target.verify_producer(sample.replace("158.8127.1.0", "157.8103.4.0"),
                                   run, patches)
        with self.assertRaises(target.M158EvidenceError):
            target.verify_producer(sample, run.replace(
                "android_toi420_failure_handling.patch",
                "logging_sink_min_severity.patch", 1), patches)
        tampered = dict(patches)
        tampered[new] += ("\ndiff --git a/" + target.SOURCE_PATHS[0] +
                          " b/" + target.SOURCE_PATHS[0])
        with self.assertRaises(target.M158EvidenceError):
            target.verify_producer(sample, run, tampered)
        tampered = dict(patches)
        tampered[new] = patches[new].replace("YuvConverter.java", "Other.java")
        with self.assertRaises(target.M158EvidenceError):
            target.verify_producer(sample, run, tampered)


    def test_to_i420_memory_ownership_and_null_frame_drop_fail_closed(self):
        java = [
            "    } catch (RuntimeException e) {",
            "      i420TextureFrameBuffer.release();",
            "    boolean bufferOwnershipTransferred = false;",
            "    ByteBuffer i420ByteBuffer = null;",
            "    final ByteBuffer allocatedBuffer = JniCommon.nativeAllocateByteBuffer(stride * totalHeight);",
            "    i420ByteBuffer = allocatedBuffer;",
            "    I420Buffer i420Buffer = JavaI420Buffer.wrap(frameWidth, frameHeight, dataY, stride, dataU,",
            "    bufferOwnershipTransferred = true;",
            "    } finally {",
            "      preparedBuffer.release();",
            "      if (!bufferOwnershipTransferred && i420ByteBuffer != null) {",
            "        JniCommon.nativeFreeByteBuffer(i420ByteBuffer);",
        ]
        native = [
            "  if (apply_rotation() && rotation != kVideoRotation_0) {",
            "    if (!buffer) {",
            '      RTC_LOG(LS_ERROR) << "Failed to convert the frame to I420. Dropping it.";',
            "      OnFrameDropped();",
            "      return;",
        ]
        scope_java = ("diff --git a/sdk/android/api/org/webrtc/YuvConverter.java "
                      "b/sdk/android/api/org/webrtc/YuvConverter.java\n")
        scope_jni = ("diff --git a/sdk/android/src/jni/android_video_track_source.cc "
                     "b/sdk/android/src/jni/android_video_track_source.cc\n")
        sample = (scope_java + "\n".join("+" + x for x in java) + "\n" +
                  scope_jni + "\n".join("+" + x for x in native))
        result = target.inspect_to_i420_failure_patch(sample)
        self.assertTrue(result["java_exception_handling_and_native_buffer_transfer_markers_present"])
        self.assertFalse(result["video_jni_runtime_approved"])
        for prefix, markers in ((scope_java, java), (scope_jni, native)):
            for token in markers:
                broken = sample.replace("+" + token, "+unsafe()", 1)
                with self.subTest(fragment=token):
                    with self.assertRaises(target.M158EvidenceError):
                        target.inspect_to_i420_failure_patch(broken)
        with self.assertRaises(target.M158EvidenceError):
            target.inspect_to_i420_failure_patch(sample.replace(scope_jni, ""))
        with self.assertRaises(target.M158EvidenceError):
            target.inspect_to_i420_failure_patch(sample.replace(
                "+" + java[-1], "+unsafe_cleanup()"
            ))

    def test_unverified_source_snapshot_never_approves(self):
        with self.assertRaises((target.base.SourceEvidenceError,
                                target.base.old.SourceProbeError, KeyError)):
            target.base.check_snapshots({})

    def test_exact_generation_profile_is_distinct_from_m157(self):
        self.assertEqual(len(target.PATCHES), 21)
        self.assertIn("android_toi420_failure_handling.patch", target.PATCHES)
        self.assertNotIn("logging_sink_min_severity.patch", target.PATCHES)
        self.assertNotEqual(target.SOURCE_SHA, target.base.SOURCE_SHA)
        self.assertNotEqual(target.PRODUCER_SHA, target.base.PRODUCER_SHA)
        for path in target.SCTP_OWNER_PATHS:
            self.assertEqual(target.allowed_url(
                target.SOURCE_ROOT + path + "?format=TEXT")[0],
                "webrtc.googlesource.com")
        self.assertFalse(target.RELEASE_AAR_SHA256 == target.base.vendor.PATCH_EXPECTED_SHA256)


if __name__ == "__main__":
    unittest.main()
