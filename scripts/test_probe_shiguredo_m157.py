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

    def test_embedded_notice_paths_are_inventory_only(self):
        import io
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "synthetic.aar"
            api = io.BytesIO()
            with zipfile.ZipFile(api, "w") as nested:
                nested.writestr("org/webrtc/LoggingJni.class", b"synthetic")
            with zipfile.ZipFile(out, "w") as aar:
                aar.writestr("classes.jar", api.getvalue())
                aar.writestr("META-INF/NOTICE", b"WebRTC redistribution notice")
            details = {
                "sha256": m157.EXPECTED_SHA256,
                "file_bytes": m157.EXPECTED_SIZE,
                "native_paths": ["jni/arm64-v8a/libjingle_peerconnection_so.so"],
                "webrtc_api_jar": "classes.jar",
                "java_classfile_major_counts": {"69": 1},
                "required_abis": ["arm64-v8a"],
                "optional_abis_present": [],
                "embedded_license_or_notice_paths": ["META-INF/NOTICE"],
            }
            with mock.patch.object(m157.evidence.audit, "audit_aar", return_value=details):
                result = m157.inspect_pinned_aar(out)
            self.assertEqual(result["embedded_license_or_notice_paths"], ["META-INF/NOTICE"])
            self.assertFalse(result["license_and_notice_binary_inventory_complete"])
            self.assertFalse(result["vendor_approved_for_kenato"])

    def test_empty_aar_notice_is_never_automatically_approved(self):
        import io
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "synthetic.aar"
            api = io.BytesIO()
            with zipfile.ZipFile(api, "w") as nested:
                nested.writestr("org/webrtc/LoggingJni.class", b"synthetic")
            with zipfile.ZipFile(out, "w") as aar:
                aar.writestr("classes.jar", api.getvalue())
            details = {
                "sha256": m157.EXPECTED_SHA256,
                "file_bytes": m157.EXPECTED_SIZE,
                "native_paths": ["jni/arm64-v8a/libjingle_peerconnection_so.so"],
                "webrtc_api_jar": "classes.jar",
                "java_classfile_major_counts": {"69": 1},
                "required_abis": ["arm64-v8a"],
                "optional_abis_present": [],
                "embedded_license_or_notice_paths": [],
            }
            with mock.patch.object(m157.evidence.audit, "audit_aar", return_value=details):
                result = m157.inspect_pinned_aar(out)
            self.assertEqual(result["embedded_license_or_notice_paths"], [])
            self.assertFalse(result["license_and_notice_binary_inventory_complete"])
            self.assertFalse(result["vendor_approved_for_kenato"])

    def test_notice_content_fingerprint_does_not_approve_vendor(self):
        import io
        import zipfile
        import hashlib
        raw = b"WebRTC\nRedistribution and use in source and binary forms"
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "synthetic.aar"
            jar = io.BytesIO()
            with zipfile.ZipFile(jar, "w") as z:
                z.writestr("org/webrtc/LoggingJni.class", b"synthetic")
            with zipfile.ZipFile(out, "w") as z:
                z.writestr("classes.jar", jar.getvalue())
                z.writestr("META-INF/NOTICE", raw)
            details = {
                "sha256": m157.EXPECTED_SHA256,
                "file_bytes": m157.EXPECTED_SIZE,
                "native_paths": ["jni/arm64-v8a/libjingle_peerconnection_so.so"],
                "webrtc_api_jar": "classes.jar",
                "java_classfile_major_counts": {"69": 1},
                "required_abis": ["arm64-v8a"],
                "optional_abis_present": [],
                "embedded_license_or_notice_paths": ["META-INF/NOTICE"],
            }
            with mock.patch.object(m157.evidence.audit, "audit_aar", return_value=details):
                result = m157.inspect_pinned_aar(out)
            record = result["embedded_notice_content_evidence"][0]
            self.assertEqual(record["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(record["bytes"], len(raw))
            self.assertTrue(record["contains_webrtc_attribution"])
            self.assertFalse(result["license_and_notice_binary_inventory_complete"])
            self.assertFalse(result["vendor_approved_for_kenato"])

    def test_empty_notice_is_rejected_not_misreported_as_clearance(self):
        import io
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "empty.aar"
            with zipfile.ZipFile(out, "w") as z:
                z.writestr("META-INF/NOTICE", b"")
            with zipfile.ZipFile(out) as z:
                with self.assertRaisesRegex(m157.CandidateProbeError, "Missing or oversized"):
                    m157.inspect_notice_evidence(z, ["META-INF/NOTICE"])

    def test_oversized_notice_is_rejected(self):
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "oversized.aar"
            with zipfile.ZipFile(out, "w") as z:
                z.writestr("META-INF/NOTICE", b"x" * (m157.MAX_EMBEDDED_NOTICE_BYTES + 1))
            with zipfile.ZipFile(out) as z:
                with self.assertRaisesRegex(m157.CandidateProbeError, "Missing or oversized"):
                    m157.inspect_notice_evidence(z, ["META-INF/NOTICE"])

    def test_duplicate_inventory_over_limit_is_rejected(self):
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(), "w") as z:
            with self.assertRaisesRegex(m157.CandidateProbeError, "Too many"):
                m157.inspect_notice_evidence(z, ["META-INF/NOTICE"] * (m157.MAX_EMBEDDED_NOTICE_ENTRIES + 1))

    def test_invalid_research_abi_is_rejected_by_existing_auditor(self):
        with mock.patch.object(m157.evidence.audit, "audit_aar",
                               side_effect=m157.evidence.audit.AarAuditError("no ARM64")):
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(m157.evidence.audit.AarAuditError, "ARM64"):
                    m157.inspect_pinned_aar(Path(directory) / "missing.aar")


if __name__ == "__main__":
    unittest.main()
