#!/usr/bin/env python3
"""Fail-closed generated NOTICE structure regression tests (network-free)."""
from __future__ import annotations

import hashlib
import unittest
from unittest import mock

import probe_shiguredo_m157_notice as note

class NoticeTests(unittest.TestCase):
    def test_exact_inventory_is_pinned(self):
        self.assertEqual(len(note.COMPONENTS), 34)
        self.assertEqual(len(note.NOTICE_SHA256), 64)
        self.assertEqual(note.NOTICE_BYTES, 214353)

    def test_missing_duplicated_and_short_headers_rejected(self):
        body = "".join("# " + name + "\n" + "Copyright " + "x"*200 + "\n"
                       for name in sorted(note.COMPONENTS))
        data = body.encode()
        with mock.patch.object(note, "NOTICE_SHA256", hashlib.sha256(data).hexdigest()), \
             mock.patch.object(note, "NOTICE_BYTES", len(data)):
            result = note.inspect_notice(data)
            self.assertEqual(result["component_count"], 34)
            self.assertFalse(result["third_party_notice_obligations_fully_cleared"])
            self.assertEqual(
                result["license_review_status"],
                "BLOCKED_PARTIAL_NOTICE_INVENTORY_NOT_SPDX_CLEARANCE")
            self.assertEqual(result["license_components_reviewed_count"], 0)
            self.assertEqual(result["license_components_pending_count"], 34)
            gaps = result["component_license_gap_register"]
            self.assertEqual([item["notice_component"] for item in gaps],
                             sorted(note.COMPONENTS))
            self.assertEqual(len({item["notice_section_sha256"]
                                  for item in gaps}), 34)
            for item in gaps:
                self.assertEqual(len(item["notice_section_sha256"]), 64)
                self.assertEqual(item["license_declared_spdx"], "NOASSERTION")
                self.assertEqual(item["license_concluded_spdx"], "NOASSERTION")
                self.assertFalse(item["upstream_license_verified"])
                self.assertFalse(item["native_linkage_verified"])
                self.assertFalse(item["redistribution_obligations_reviewed"])
                self.assertFalse(item["independent_license_signoff"])
            for tamper in (
                data.replace(b"# webrtc\n", b"# other\n"),
                data + b"# webrtc\nCopyright x\n",
                data.replace(b"Copyright " + b"x"*200, b"Copyright small", 1),
            ):
                with self.assertRaises(note.NoticeInventoryError):
                    note.inspect_notice(tamper)

    def test_no_synthetic_notice_accepted_as_exact_publisher(self):
        with self.assertRaises(note.NoticeInventoryError):
            note.inspect_notice(b"# webrtc\nCopyright fake\n")

if __name__ == "__main__":
    unittest.main()
