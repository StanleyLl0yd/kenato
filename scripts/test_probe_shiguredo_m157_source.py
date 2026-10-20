#!/usr/bin/env python3
"""Offline negative cases for Shiguredo m157 source/NOTICE research."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import probe_shiguredo_m157_source as probe


GOOD_VERSION = (
    "WEBRTC_BUILD_VERSION=157.8103.0.0\n"
    "WEBRTC_COMMIT=b321f634929af0af61a8964487fbd7894a008f12\n"
)
GOOD_LICENSE = "Apache License\nVersion 2.0"
GOOD_NOTICE = "## WebRTC\n## WebKit\nRedistribution and use in source and binary forms"
GOOD_SOURCE = """
std::vector<int> RtpPacketizer::SplitAboutEqually(
    size_t payload_size, const PayloadSizeLimits& limits) {
}
if (SafeGt(payload.size(), limits.max_payload_len * 0x7000)) {}
"""


class ProbeTests(unittest.TestCase):
    def test_valid_snapshot_is_research_only(self):
        report = probe.inspect_snapshots(GOOD_VERSION, GOOD_LICENSE, GOOD_NOTICE, GOOD_SOURCE)
        self.assertFalse(report["vendor_approved_for_kenato"])
        self.assertFalse(report["cve_2026_78891_binary_remediation_verified"])
        self.assertFalse(report["license_inventory_complete_for_binary"])

    def test_invalid_declared_source_sha(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "VERSION mismatch"):
            probe.inspect_snapshots(
                GOOD_VERSION.replace(probe.WEBRTC_SHA, "0" * 40),
                GOOD_LICENSE, GOOD_NOTICE, GOOD_SOURCE,
            )

    def test_duplicate_version_field_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "duplicate"):
            probe.validate_version(GOOD_VERSION + GOOD_VERSION)

    def test_missing_notice_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "NOTICE"):
            probe.validate_licenses(GOOD_LICENSE, "## WebRTC")

    def test_missing_size_t_fix_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "size_t"):
            probe.validate_vp9_source(
                GOOD_SOURCE.replace("size_t payload_size", "int payload_len")
            )

    def test_missing_frame_bound_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "guard absent"):
            probe.validate_vp9_source(GOOD_SOURCE.replace("0x7000", "0x8000"))

    def test_old_signature_even_with_new_one_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "old int"):
            probe.validate_vp9_source(
                GOOD_SOURCE + "RtpPacketizer::SplitAboutEqually(int payload_len)"
            )

    def test_http_redirect_is_rejected(self):
        class Response:
            status = 302
            def read(self, n): return b"x"
        class Connection:
            def request(self, *args, **kwargs): pass
            def getresponse(self): return Response()
            def close(self): pass
        with patch.object(probe.http.client, "HTTPSConnection", return_value=Connection()):
            with self.assertRaisesRegex(probe.SourceProbeError, "HTTP status 302"):
                probe.fetch_exact(probe.PUBLISHER_ROOT + "VERSION", maximum=10, host="raw.githubusercontent.com")

    def test_oversized_content_is_rejected(self):
        class Response:
            status = 200
            def read(self, n): return b"x" * (n + 1)
        class Connection:
            def request(self, *args, **kwargs): pass
            def getresponse(self): return Response()
            def close(self): pass
        with patch.object(probe.http.client, "HTTPSConnection", return_value=Connection()):
            with self.assertRaisesRegex(probe.SourceProbeError, "oversized"):
                probe.fetch_exact(probe.PUBLISHER_ROOT + "VERSION", maximum=10, host="raw.githubusercontent.com")

    def test_non_allowlisted_url_rejected_without_request(self):
        with patch.object(probe.http.client, "HTTPSConnection") as make:
            with self.assertRaisesRegex(probe.SourceProbeError, "allowlist"):
                probe.fetch_exact("https://raw.githubusercontent.com/attacker/other", maximum=10, host="raw.githubusercontent.com")
            make.assert_not_called()


if __name__ == "__main__":
    unittest.main()
