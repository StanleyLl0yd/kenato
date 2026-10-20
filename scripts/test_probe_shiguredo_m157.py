#!/usr/bin/env python3
"""Offline regressions for source-pinned, ready-made m157 AAR research."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import probe_shiguredo_m157 as m157


class ReadyMadeVendorTests(unittest.TestCase):
    def test_exact_publisher_sha_and_size_are_mandatory(self):
        m157.verify_observation(m157.EXPECTED_SHA256, m157.EXPECTED_SIZE)
        for digest, size in (
            ("0" * 64, m157.EXPECTED_SIZE),
            (m157.EXPECTED_SHA256, m157.EXPECTED_SIZE + 1),
        ):
            with self.assertRaises(m157.CandidateProbeError):
                m157.verify_observation(digest, size)

    def test_mismatch_never_reaches_zip_or_elf_parser(self):
        def corrupted(_url, output, *, max_bytes):
            self.assertLess(max_bytes, 18 * 1024 * 1024)
            output.write_bytes(b"not a real AAR")
            return hashlib.sha256(b"not a real AAR").hexdigest(), 14
        with mock.patch.object(m157, "inspect_pinned_aar") as inspect:
            with self.assertRaises(m157.CandidateProbeError):
                m157.collect(downloader=corrupted)
            inspect.assert_not_called()

    def test_success_reporting_never_authorizes_or_executes_media(self):
        def fake_download(url, output, *, max_bytes):
            self.assertEqual(m157.RELEASE_URL, url)
            output.write_bytes(b"fixture")
            return m157.EXPECTED_SHA256, m157.EXPECTED_SIZE
        with mock.patch.object(m157, "inspect_pinned_aar",
                               return_value={"status": "STRUCTURAL_PASS_NOT_VENDOR_APPROVAL",
                                             "vendor_approved_for_kenato": False}):
            # Separate actual-size check refuses fixture-only checksum spoofing.
            with self.assertRaises(m157.CandidateProbeError):
                m157.collect(downloader=fake_download)

    def test_invalid_research_abi_is_rejected_by_existing_auditor(self):
        with mock.patch.object(m157.evidence.audit, "audit_aar",
                               side_effect=m157.evidence.audit.AarAuditError("no ARM64")):
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(m157.evidence.audit.AarAuditError, "ARM64"):
                    m157.inspect_pinned_aar(Path(directory) / "missing.aar")


if __name__ == "__main__":
    unittest.main()
