#!/usr/bin/env python3
"""Defensive source-identity and CVE-negative tests, no external network."""
from __future__ import annotations
import unittest
import hashlib
from unittest import mock

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
            target.SOURCE_ROOT + target.SOURCE_LICENSE_GENERATOR_PATH + "?format=TEXT")[0],
            "webrtc.googlesource.com")
        self.assertEqual(target.allowed_url(
            target.PRODUCER_ROOT + "LICENSE")[0],
            "raw.githubusercontent.com")
        for url in ("http://webrtc.googlesource.com/",
                    target.SOURCE_ROOT + "../HEAD?format=TEXT",
                    target.PRODUCER_ROOT + "patches/unreviewed.patch"):
            with self.assertRaises(target.SourceEvidenceError):
                target.allowed_url(url)

    def test_curl_status_marker_is_real_newline_not_literal_escape(self):
        url = target.PRODUCER_ROOT + "VERSION"
        def runner(argv, **kwargs):
            return mock.Mock(
                returncode=0,
                stdout=b"WEBRTC_BUILD_VERSION=157.8103.4.0" +
                       bytes([10]) + b"@@KENATO_STATUS:200")
        self.assertEqual(target.fetch_exact(
            url, runner=runner,
            sleeper=lambda _: self.fail("Valid response must not retry")),
            b"WEBRTC_BUILD_VERSION=157.8103.4.0")

    def test_gitiles_transient_retry_preserves_exact_url(self):
        url = target.SOURCE_ROOT + target.SOURCE_PATHS[0] + "?format=TEXT"
        calls = []
        sleeps = []

        def runner(argv, **kwargs):
            calls.append(tuple(argv))
            status = b"503" if len(calls) < 3 else b"200"
            return mock.Mock(returncode=0, stdout=(
                b"valid-source-content" if status == b"200" else b"temporary"
            ) + b"\n@@KENATO_STATUS:" + status)

        self.assertEqual(target.fetch_exact(url, runner=runner,
                                            sleeper=sleeps.append),
                         b"valid-source-content")
        self.assertEqual(sleeps, [1, 2])
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(call == calls[0] for call in calls))
        self.assertTrue(all(call[-1] == url for call in calls))
        self.assertNotIn("--location", calls[0])

        def always_503(argv, **kwargs):
            return mock.Mock(returncode=0,
                             stdout=b"temporary\n@@KENATO_STATUS:503")

        with self.assertRaises(target.SourceEvidenceError):
            target.fetch_exact(url, runner=always_503,
                               sleeper=sleeps.append)
        self.assertEqual(sleeps[-3:], [1, 2, 4])

        attempted = []
        def never_retry_404(argv, **kwargs):
            attempted.append(1)
            return mock.Mock(returncode=0,
                             stdout=b"not found\n@@KENATO_STATUS:404")
        with self.assertRaises(target.SourceEvidenceError):
            target.fetch_exact(url, runner=never_retry_404,
                               sleeper=lambda _: self.fail("404 must not retry"))
        self.assertEqual(len(attempted), 1)
        with self.assertRaises(target.SourceEvidenceError):
            target.fetch_exact(target.SOURCE_ROOT + "../unreviewed?format=TEXT",
                               runner=lambda *a, **kw: self.fail("Unsafe URL contacted"))

    def test_publisher_notice_generator_invocation_is_joined_path(self):
        run = 'os.path.join(webrtc_src_dir, "tools_webrtc", "libs", "generate_licenses.py")'
        self.assertTrue(target.has_exact_notice_generator_invocation(run))
        self.assertFalse(target.has_exact_notice_generator_invocation(
            run.replace('"generate_licenses.py"', '"unknown.py"')))
        self.assertFalse(target.has_exact_notice_generator_invocation(
            'os.path.join("tools_webrtc", "libs", "unreviewed.py")'))

    def test_static_gn_license_map_only_records_candidate_paths(self):
        fixture = b"""# GN desc dependencies, not an independent native SBOM.
LIB_TO_LICENSES_DICT = {
  'webrtc': ['LICENSE'],
  'boringssl': ['third_party/boringssl/src/LICENSE'],
  'libsrtp': ['third_party/libsrtp/LICENSE'],
  'libvpx': ['third_party/libvpx/source/libvpx/LICENSE'],
  'opus': ['third_party/opus/src/' + 'COPYING'],
}
LIB_REGEX_TO_LICENSES_DICT = {'android_deps:.*': []}
# generate_license_text GN desc
""" + b"# copyright text\n" * 6
        result = target.inspect_license_generator_snapshot(fixture)
        self.assertEqual(result["notice_component_count"], 34)
        self.assertEqual(result["mapped_notice_component_count"], 5)
        self.assertEqual(result["unmapped_notice_component_count"], 29)
        self.assertEqual(result["notice_components_with_source_license_path_candidates"]["opus"],
                         ["third_party/opus/src/COPYING"])
        self.assertFalse(result["gn_desc_build_graph_independently_reproduced"])
        self.assertFalse(result["license_source_paths_prove_binary_linkage"])
        self.assertFalse(result["mapped_license_texts_independently_verified"])
        self.assertFalse(result["transitive_license_spdx_clearance"])
        for tamper in (
            fixture.replace(b"['third_party/opus/src/' + 'COPYING']",
                            b"[__import__('os').system('id')]"),
            fixture.replace(b"'third_party/libsrtp/LICENSE'",
                            b"'../LICENSE'"),
            fixture.replace(b"'webrtc': ['LICENSE']", b"'webrtc': []"),
            fixture.replace(b"LIB_TO_LICENSES_DICT", b"BROKEN", 1),
        ):
            with self.assertRaises(target.SourceEvidenceError):
                target.inspect_license_generator_snapshot(tamper)

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
