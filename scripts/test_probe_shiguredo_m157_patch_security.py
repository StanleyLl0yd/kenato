#!/usr/bin/env python3
"""Defensive source-identity and CVE-negative tests, no external network."""
from __future__ import annotations
import unittest

import probe_shiguredo_m157_patch_security as target

class PatchSecurityTests(unittest.TestCase):
    def test_exact_allowlist(self):
        self.assertEqual(target.allowed_url(
            target.SOURCE_ROOT + target.SOURCE_PATHS[0] + "?format=TEXT"
        )[0], "webrtc.googlesource.com")
        self.assertEqual(target.allowed_url(target.PRODUCER_ROOT + "VERSION")[0],
                         "raw.githubusercontent.com")
        for url in ("http://webrtc.googlesource.com/",
                    target.SOURCE_ROOT + "../HEAD?format=TEXT",
                    target.PRODUCER_ROOT + "patches/unreviewed.patch"):
            with self.assertRaises(target.SourceEvidenceError):
                target.allowed_url(url)

    def test_patched_fec_is_fail_closed(self):
        source = """
        InsertZerosInPacketMasks(
          if (new_bit_index >= max_media_packets) {
             return -1;
          }
          new_bit_index += num_zeros_to_insert;
          if (new_bit_index >= max_media_packets) {
             return -1;
          }
          internal::CopyColumn(...);
        }
        """
        header = "std::span<const uint8_t> LookUp(int packets, int fec);"
        internal = "std::span<const uint8_t> PacketMaskTable::LookUp(...)"
        target.validate_fec_fixes(source, header, internal)
        bad = source.replace(">=", "==", 1)
        with self.assertRaises(target.SourceEvidenceError):
            target.validate_fec_fixes(bad, header, internal)
        with self.assertRaises(target.SourceEvidenceError):
            target.validate_fec_fixes(
                source.replace("return -1;", "break;", 1), header, internal
            )
        with self.assertRaises(target.SourceEvidenceError):
            target.validate_fec_fixes(source, "", internal)

    def test_patch_targets_fail_closed(self):
        producer = "WEBRTC_BUILD_VERSION=157.8103.4.0\nWEBRTC_COMMIT=" + target.SOURCE_SHA
        run = ("PATCHES = {'android': [" +
               ", ".join(repr(p) for p in target.PATCHES) +
               "], 'android_sdk': [" +
               ", ".join(repr(p) for p in target.PATCHES) +
               "]}\nrtc_use_h264=false")
        patches = {p: f"diff --git a/fixture/{p} b/fixture/{p}\n"
                   for p in target.PATCHES}
        self.assertEqual(target.validate_producer(producer,run,patches)["patch_count"],21)
        tampered = dict(patches)
        tampered[target.PATCHES[0]] = (
            "diff --git a/modules/rtp_rtcp/source/rtp_format.cc "
            "b/modules/rtp_rtcp/source/rtp_format.cc\n"
        )
        with self.assertRaises(target.SourceEvidenceError):
            target.validate_producer(producer,run,tampered)
        with self.assertRaises(target.SourceEvidenceError):
            target.validate_producer(producer.replace(target.SOURCE_SHA,"0"*40),
                                     run,patches)

    def test_cve_results_require_sources(self):
        with self.assertRaises(KeyError):
            target.check_snapshots({})

if __name__ == "__main__":
    unittest.main()
