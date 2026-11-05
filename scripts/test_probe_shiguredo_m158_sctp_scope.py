#!/usr/bin/env python3
"""Offline bounds and non-approval tests for m158 SCTP source scope."""
import unittest
import probe_shiguredo_m158_sctp_scope as scope


class SctpScopeTests(unittest.TestCase):
    def test_bounded_context_limits_and_no_guessing(self):
        text = "before\nSctpDataChannel::~SctpDataChannel() { safe(); }\nafter"
        self.assertEqual(
            scope.bounded_context(text, "SctpDataChannel::~SctpDataChannel()",
                                  limit=9),
            "SctpDataC")
        self.assertEqual(scope.bounded_context(text, "nonexistent"), "")
        with self.assertRaises(scope.m158.M158EvidenceError):
            scope.bounded_context(text, "after", limit=10000)
        with self.assertRaises(scope.m158.M158EvidenceError):
            scope.bounded_context(text + text, "SctpDataChannel::~SctpDataChannel()",
                                  unique=True)

    def test_no_executable_source_or_unreviewed_fallback(self):
        self.assertEqual(scope.TARGET, "pc/sctp_data_channel.cc")
        self.assertIn(scope.m158.SOURCE_SHA, scope.URL)
        self.assertNotIn("main", scope.URL)
        self.assertFalse(scope.m158.RELEASE_AAR_SHA256 ==
                         scope.m158.base.vendor.PATCH_EXPECTED_SHA256)


if __name__ == "__main__":
    unittest.main()
