#!/usr/bin/env python3
"""Negative/positive research-only tests; never execute vendor ELF."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import probe_shiguredo_m157_elf as probe


class NativeInventoryTests(unittest.TestCase):
    def test_exact_structural_input_reports_only_static_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.aar"
            raw = b"Z" * 64
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(probe.LIB_PATH, raw)
            fake = {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "gnu_relro": True, "bind_now": True,
                "gnu_stack_executable": False,
                "jni_onload_exported": True,
            }
            def scanner(payload, abi):
                self.assertEqual(payload, raw)
                self.assertEqual(abi, "arm64-v8a")
                return fake
            with patch.object(probe.m157, "inspect_pinned_aar",
                              return_value={"status": "STRUCTURAL_PASS_NOT_VENDOR_APPROVAL"}):
                result = probe.inventory(path, scanner=scanner)
            self.assertFalse(result["vendor_approved_for_kenato"])
            self.assertFalse(result["native_executed"])
            self.assertFalse(result["symbol_presence_proves_cve_fix"])
            self.assertFalse(result["source_to_native_binary_reproducibility_verified"])
            self.assertEqual(result["native_arm64"]["sha256"], fake["sha256"])

    def test_wrong_abi_path_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "synthetic.aar"
            with zipfile.ZipFile(file, "w") as z:
                z.writestr("jni/x86_64/libjingle_peerconnection_so.so", b"Z" * 64)
            with patch.object(probe.m157, "inspect_pinned_aar",
                              return_value={"status": "STRUCTURAL_PASS_NOT_VENDOR_APPROVAL"}):
                with self.assertRaises(KeyError):
                    probe.inventory(file)

    def test_oversized_elf_refused_before_readelf(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "synthetic.aar"
            with zipfile.ZipFile(file, "w") as z:
                z.writestr(probe.LIB_PATH, b"Z" * (probe.native.LIMIT + 1))
            with patch.object(probe.m157, "inspect_pinned_aar",
                              return_value={"status": "STRUCTURAL_PASS_NOT_VENDOR_APPROVAL"}):
                with self.assertRaisesRegex(probe.M157NativeError, "oversized"):
                    probe.inventory(file, scanner=lambda *x: self.fail("must not execute"))

    def test_download_mismatch_blocks_before_binary_read(self):
        def fake_download(_url, output, *, max_bytes):
            output.write_bytes(b"untrusted")
            return "0" * 64, probe.m157.EXPECTED_SIZE
        with patch.object(probe, "inventory") as inv:
            with self.assertRaises(probe.m157.CandidateProbeError):
                probe.collect(downloader=fake_download)
            inv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
