#!/usr/bin/env python3
"""Defensive source-identity and CVE-negative tests, no external network."""
from __future__ import annotations
import unittest
import hashlib

import probe_shiguredo_m157_patch_security as target

class PatchSecurityTests(unittest.TestCase):
    def test_exact_allowlist(self):
        self.assertEqual(target.allowed_url(
            target.SOURCE_ROOT + target.SOURCE_PATHS[0] + "?format=TEXT"
        )[0], "webrtc.googlesource.com")
        self.assertEqual(target.allowed_url(target.PRODUCER_ROOT + "VERSION")[0],
                         "raw.githubusercontent.com")
        self.assertEqual(target.allowed_url(
            target.SOURCE_ROOT + "LICENSE?format=TEXT")[0],
            "webrtc.googlesource.com")
        self.assertEqual(target.allowed_url(
            target.PRODUCER_ROOT + "LICENSE")[0],
            "raw.githubusercontent.com")
        for url in ("http://webrtc.googlesource.com/",
                    target.SOURCE_ROOT + "../HEAD?format=TEXT",
                    target.PRODUCER_ROOT + "patches/unreviewed.patch"):
            with self.assertRaises(target.SourceEvidenceError):
                target.allowed_url(url)

    def test_pinned_root_license_patterns_never_grant_spdx_clearance(self):
        upstream = (b"Copyright (c) 2011. Redistribution and use in source and "
                    b"binary forms, with or without modification, are permitted. "
                    b"Redistributions of source code must retain the notice. "
                    b"Redistributions in binary form must reproduce the notice. "
                    b"Neither the name of Google nor its contributors may be used.")
        publisher = (b"Apache License Version 2.0, January 2004. "
                     b"TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION. "
                     b"Grant of Patent License. Redistribution. "
                     b"Copyright. " + b"Some additional terms. " * 4)
        for origin, body, expected in (
            ("webrtc_source", upstream, "BSD-3-Clause"),
            ("publisher_build_project", publisher, "Apache-2.0"),
        ):
            record = target.check_root_license(body, origin=origin)
            self.assertEqual(record["sha256"],
                             hashlib.sha256(body).hexdigest())
            self.assertEqual(record["textual_license_pattern_candidate"], expected)
            self.assertFalse(record["complete_license_spdx_audit"])
            self.assertFalse(record["actual_linked_component_license_verified"])
            self.assertFalse(record["independent_legal_clearance"])
            with self.assertRaises(target.SourceEvidenceError):
                target.check_root_license(body.replace(b"Redistribution",
                                     b"Distribution", 1), origin=origin)
            with self.assertRaises(target.SourceEvidenceError):
                target.check_root_license(body, origin="unknown")
        with self.assertRaises(target.SourceEvidenceError):
            target.check_root_license(b"Apache License",
                                      origin="publisher_build_project")

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
