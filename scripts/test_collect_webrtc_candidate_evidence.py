#!/usr/bin/env python3
"""No-network unit tests for bounded M5 AAR provenance evidence gathering."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).with_name("collect_webrtc_candidate_evidence.py")
SPEC = importlib.util.spec_from_file_location("kenato_aar_evidence_test", SOURCE)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class FakeResponse(io.BytesIO):
    def __init__(self, value: bytes, status: int = 200):
        super().__init__(value)
        self.status = status


class CandidateEvidenceTests(unittest.TestCase):
    def test_bounded_download_computes_digest_of_written_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "sample.aar"
            payload = b"fixture bytes (not a valid vendor AAR)"
            observed, size = evidence.download_snapshot(
                "https://example.invalid/fixture.aar", destination,
                opener=lambda *_args, **_kwargs: FakeResponse(payload),
            )
            self.assertEqual(hashlib.sha256(payload).hexdigest(), observed)
            self.assertEqual(len(payload), size)
            self.assertEqual(payload, destination.read_bytes())

    def test_excess_bytes_and_non_200_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "sample.aar"
            with self.assertRaisesRegex(evidence.EvidenceError, "size bound"):
                evidence.download_snapshot(
                    "https://example.invalid/fixture.aar", destination,
                    opener=lambda *_args, **_kwargs: FakeResponse(b"five!"),
                    max_bytes=4,
                )
            with self.assertRaisesRegex(evidence.EvidenceError, "non-200"):
                evidence.download_snapshot(
                    "https://example.invalid/fixture.aar", destination,
                    opener=lambda *_args, **_kwargs: FakeResponse(b"nope", 404),
                )
            with self.assertRaisesRegex(evidence.EvidenceError, "Empty"):
                evidence.download_snapshot(
                    "https://example.invalid/fixture.aar", destination,
                    opener=lambda *_args, **_kwargs: FakeResponse(b""),
                )

    def test_native_inventory_is_bounded_and_does_not_extract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.aar"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("jni/arm64-v8a/libx.so", b"not executable")
                archive.writestr("jni/x86/libx.so", b"not executable")
                archive.writestr("misc/file.txt", b"ignored")
            observed = evidence.native_entry_inventory(path)
            self.assertEqual(2, observed["total_so_paths"])
            self.assertEqual(
                ["jni/arm64-v8a/libx.so", "jni/x86/libx.so"],
                observed["displayed_so_paths"],
            )
            self.assertFalse(observed["paths_truncated"])
            self.assertFalse((Path(directory) / "jni").exists())

    def test_nested_jar_api_inventory_finds_separate_library(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.aar"
            package_jar = io.BytesIO()
            with zipfile.ZipFile(package_jar, "w") as nested:
                nested.writestr("org/webrtc/PeerConnection.class", b"fixture")
            with zipfile.ZipFile(path, "w") as outer:
                outer.writestr("classes.jar", b"not the API")
                outer.writestr("libs/libwebrtc.jar", package_jar.getvalue())
            result = evidence.jar_entry_inventory(path)
            self.assertEqual(2, len(result["jars"]))
            self.assertTrue(result["jars"][1]["exact_peer_connection_path"])

    def test_modelled_m150_major_stamping_is_header_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial = root / "input.aar"
            result = root / "output.aar"
            klass = b"\xca\xfe\xba\xbe" + b"\x00\x00\x00\x41" + b"payload"
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as jar:
                jar.writestr("org/webrtc/PeerConnection.class", klass)
            with zipfile.ZipFile(initial, "w") as aar:
                aar.writestr("classes.jar", nested.getvalue())
            count = evidence.reproduce_published_m150_stamping(initial, result)
            self.assertEqual(1, count)
            with zipfile.ZipFile(result) as aar:
                with zipfile.ZipFile(io.BytesIO(aar.read("classes.jar"))) as jar:
                    updated = jar.read("org/webrtc/PeerConnection.class")
            self.assertEqual(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + b"payload", updated)

    def test_stamping_refuses_oversized_nested_jar_entry_before_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.aar"
            output = Path(directory) / "output.aar"
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as jar:
                jar.writestr("org/webrtc/PeerConnection.class", b"x" * 100)
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("classes.jar", nested.getvalue())
            with mock.patch.object(evidence.audit, "MAX_JAR_ENTRY_BYTES", 8):
                with self.assertRaisesRegex(evidence.EvidenceError, "Oversized"):
                    evidence.reproduce_published_m150_stamping(source, output)

    def test_release_asset_digest_mismatch_blocks_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            def untrusted_source(_url: str, target: Path) -> tuple[str, int]:
                target.write_bytes(b"wrong")
                return hashlib.sha256(b"wrong").hexdigest(), 5
            with self.assertRaisesRegex(evidence.EvidenceError, "SHA-256 mismatch"):
                evidence.collect_evidence(
                    Path(directory),
                    candidates=(("release", "https://example.invalid", "0" * 64),),
                    downloader=untrusted_source,
                )

    def test_unverified_structural_reject_remains_unapproved(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = b"synthetic invalid zip"
            def downloader(_url: str, target: Path) -> tuple[str, int]:
                target.write_bytes(payload)
                return hashlib.sha256(payload).hexdigest(), len(payload)
            report = evidence.collect_evidence(
                Path(directory),
                candidates=(("invalid", "https://example.invalid", None),),
                downloader=downloader,
            )
            self.assertEqual("RESEARCH_ONLY_NOT_VENDOR_APPROVAL", report["status"])
            result = report["candidates"]["invalid"]
            self.assertEqual("STRUCTURAL_REJECTED", result["structural_status"])
            self.assertFalse(result["vendor_approved"])
            self.assertFalse(result["checked_against_release_asset_digest"])
            self.assertIsNone(report["m150_maven_matches_original_release"])


if __name__ == "__main__":
    unittest.main()
