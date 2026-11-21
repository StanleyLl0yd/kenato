#!/usr/bin/env python3
"""No-network defensive tests for the exact WebRTC SDK security rejection audit."""
import unittest
from unittest import mock

import audit_webrtc_sdk_m150_04 as audit

class CveAuditTests(unittest.TestCase):
    def test_fixed_pins_and_reject_unknown_url(self):
        self.assertEqual(len(audit.RELEASE_SHA), 64)
        self.assertEqual(len(audit.SOURCE_SHA), 40)
        with self.assertRaises(audit.AuditError):
            audit.fetch_exact("https://evil.example/a")
        with self.assertRaises(audit.AuditError):
            audit.fetch_exact(audit.SOURCE_ROOT + "../unapproved")

    def test_patch_chain_cannot_expand(self):
        version = ("WEBRTC_BUILD_VERSION=150.7871.04\n"
                   "WEBRTC_COMMIT=" + audit.SOURCE_SHA + "\n")
        body = ("PATCHES = {'android': ['add_license_dav1d.patch', "
                "'android_webrtc_version.patch', 'fix_mocks.patch'], }\n"
                'COMMON_GN_ARGS = ["rtc_use_h264=false"]\n')
        patch = {p: "diff --git a/" + path + " b/" + path + "\n"
                 for p, path in zip(audit.PATCH_FILES, audit.PATCH_ONLY_PATHS)}
        result = audit.check_producer(version, body, patch)
        self.assertTrue(result["h264_common_gn_flag_off"])
        bad = dict(patch)
        bad[audit.PATCH_FILES[0]] += (
            "diff --git a/modules/rtp_rtcp/source/rtp_format.cc "
            "b/modules/rtp_rtcp/source/rtp_format.cc\n"
        )
        with self.assertRaises(audit.AuditError):
            audit.check_producer(version, body, bad)
        with self.assertRaises(audit.AuditError):
            audit.check_producer(version.replace(audit.SOURCE_SHA, "0"*40),
                                 body, patch)

    def test_incomplete_security_signature_fails_closed(self):
        source = {path: "synthetic" for path in audit.SOURCES}
        with self.assertRaises(audit.AuditError):
            audit.inspect_source(source)
        with self.assertRaises(audit.AuditError):
            audit.inspect_source({})

    def test_binary_identifier_is_full_unprefixed(self):
        self.assertNotIn("stripped", audit.RELEASE_URL)
        self.assertNotIn("prefixed", audit.RELEASE_URL)
        self.assertTrue(audit.RELEASE_URL.endswith("/libwebrtc.aar"))

if __name__ == "__main__":
    unittest.main()
