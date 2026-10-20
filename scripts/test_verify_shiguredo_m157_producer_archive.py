#!/usr/bin/env python3
"""Offline synthetic producer archive identity tests, no network."""
from __future__ import annotations
import hashlib
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
import verify_shiguredo_m157_producer_archive as probe

VERSIONS = (
    "WEBRTC_BUILD_VERSION=157.8103.0.0\n"
    "WEBRTC_COMMIT=" + probe.WEBRTC_SHA + "\n"
    "WEBRTC_SRC_COMMIT=" + probe.WEBRTC_SHA + "\n"
).encode()
GOOD_NOTICE = b"WebRTC\nRedistribution and use for testing"
def aar_fixture(notice: bytes = GOOD_NOTICE) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as zipfile_out:
        zipfile_out.writestr(probe.AAR_NOTICE, notice)
    return output.getvalue()
GOOD_AAR = aar_fixture()

def produce(path: Path, aar: bytes = GOOD_AAR,
            metadata: bytes = VERSIONS, duplicate: bool = False,
            notice: bytes = GOOD_NOTICE) -> tuple[int, str]:
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w:gz") as tar:
        for name, data in [(probe.TARGET_VERSIONS, metadata),
                           (probe.TARGET_NOTICE, notice),
                           (probe.TARGET_AAR, aar)]:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
        if duplicate:
            entry = tarfile.TarInfo(probe.TARGET_AAR)
            entry.size = len(aar)
            tar.addfile(entry, io.BytesIO(aar))
    with zipfile.ZipFile(path, "w") as outer:
        outer.writestr(probe.OUTER_NAME, content.getvalue())
    return path.stat().st_size, probe.file_sha256(path)


class ArchiveTests(unittest.TestCase):
    def validate(self, path: Path, size: int, digest: str, aar: bytes = GOOD_AAR):
        return probe.prove(path, expected_outer_size=size,
                           expected_outer_sha=digest, expected_aar_size=len(aar),
                           expected_aar_sha=hashlib.sha256(aar).hexdigest(),
                           expected_notice_size=len(GOOD_NOTICE),
                           expected_notice_sha=hashlib.sha256(GOOD_NOTICE).hexdigest())

    def test_exact_archive_with_declared_source_is_only_lineage_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact.zip"
            size, digest = produce(path)
            result = self.validate(path, size, digest)
            self.assertTrue(result["source_to_ci_output_metadata_consistent"])
            self.assertFalse(result["vendor_approved_for_kenato"])
            self.assertFalse(result["independent_source_rebuild_reproducibility_verified"])
            self.assertFalse(result["native_cve_binary_remediation_verified"])

    def test_damaged_outer_hash_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact.zip"
            size, digest = produce(path)
            with self.assertRaisesRegex(probe.ProducerArchiveError, "SHA256 mismatch"):
                self.validate(path, size, "0" * 64)

    def test_changed_aar_bytes_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact.zip"
            changed = b"X" + GOOD_AAR[1:]  # Same size, invalid digest before ZIP parsing
            size, digest = produce(path, aar=changed)
            with self.assertRaisesRegex(probe.ProducerArchiveError, "CI-built AAR differs"):
                self.validate(path, size, digest)

    def test_duplicate_aar_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact.zip"
            size, digest = produce(path, duplicate=True)
            with self.assertRaisesRegex(probe.ProducerArchiveError, "Duplicate"):
                self.validate(path, size, digest)

    def test_wrong_declared_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact.zip"
            size, digest = produce(path, metadata=VERSIONS.replace(probe.WEBRTC_SHA.encode(), b"0" * 40))
            with self.assertRaisesRegex(probe.ProducerArchiveError, "source missing"):
                self.validate(path, size, digest)

    def test_mismatch_root_notice_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact.zip"
            size, digest = produce(path, notice=b"unexpected-root-notice")
            with self.assertRaisesRegex(probe.ProducerArchiveError, "Producer NOTICE"):
                self.validate(path, size, digest)

    def test_mismatch_embedded_notice_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact.zip"
            changed = aar_fixture(b"Tampered embedded")
            size, digest = produce(path, aar=changed)
            with self.assertRaisesRegex(probe.ProducerArchiveError, "embedded NOTICE"):
                self.validate(path, size, digest, aar=changed)

    def test_missing_embedded_notice_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact.zip"
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as inner:
                inner.writestr("missing-notice.txt", b"not-a-notice")
            changed = output.getvalue()
            size, digest = produce(path, aar=changed)
            with self.assertRaisesRegex(probe.ProducerArchiveError, "NOTICE missing"):
                self.validate(path, size, digest, aar=changed)

    def test_undocumented_zip_member_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact.zip"
            produce(path)
            with zipfile.ZipFile(path, "a") as z:
                z.writestr("unexpected", b"data")
            with self.assertRaisesRegex(probe.ProducerArchiveError, "outer ZIP"):
                self.validate(path, path.stat().st_size, probe.file_sha256(path))

if __name__ == "__main__":
    unittest.main()
