#!/usr/bin/env python3
"""No-network synthetic regression tests; never execute or load native vendor code."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import probe_webrtc_native_elf as native

READELF = b"""Program Headers:
  GNU_RELRO      0x100 0x100 0x100 0x10 0x10 R 0x1
  GNU_STACK      0x0 0x0 0x0 0x0 0x0 RW 0
Dynamic section:
 (NEEDED) Shared library: [libc.so]
 (SONAME) Library soname: [libjingle_peerconnection_so.so]
 (FLAGS) BIND_NOW
Symbol table:
 22: 0 5 FUNC GLOBAL DEFAULT 15 JNI_OnLoad
 23: 0 5 FUNC GLOBAL DEFAULT 15 Java_org_webrtc_PeerConnection_nativeCreate
 24: 0 5 FUNC GLOBAL DEFAULT 15 Java_org_webrtc_DataChannel_nativeSend
"""

def sample(abi):
    cls, machine = native.ABIS[abi]
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = cls
    data[5:7] = b"\x01\x01"
    data[16:18] = (3).to_bytes(2, "little")
    data[18:20] = machine.to_bytes(2, "little")
    return bytes(data) + b"RtpPacketizerVp9|VP9|SctpDataChannel"

class NativeResearchTests(unittest.TestCase):
    def test_all_valid_elf_header_architectures(self):
        for abi in native.ABIS:
            native.elf_header(sample(abi), abi)
        with self.assertRaises(native.NativeProbeError):
            native.elf_header(b"garbage", "arm64-v8a")
        with self.assertRaises(native.NativeProbeError):
            native.elf_header(sample("x86"), "armeabi-v7a")

    def test_readelf_parses_hardening_symbols_and_markers(self):
        def reader(args, **kw):
            self.assertEqual("readelf", args[0])
            self.assertFalse(kw["check"])
            return type("Process", (), {"returncode": 0, "stdout": READELF})()
        out = native.scan_elf(sample("arm64-v8a"), "arm64-v8a", runner=reader)
        self.assertEqual(["libc.so"], out["dt_needed"])
        self.assertEqual(2, out["jni_export_count"])
        self.assertEqual(1, out["jni_data_channel_exports"])
        self.assertTrue(out["gnu_relro"])
        self.assertTrue(out["bind_now"])
        self.assertFalse(out["gnu_stack_executable"])
        self.assertTrue(out["jni_onload_exported"])
        self.assertEqual(1, out["binary_marker_counts_NOT_reachability"]["vp9_packetizer_type_name"])
        self.assertFalse(out["native_code_executed"])
        self.assertFalse(out["cve_exploitability_established"])

    def test_failed_readelf_is_not_success(self):
        def fail(*args, **kwargs):
            return type("Process", (), {"returncode": 1, "stdout": b""})()
        with self.assertRaisesRegex(native.NativeProbeError, "Invalid"):
            native.scan_elf(sample("arm64-v8a"), "arm64-v8a", runner=fail)

    def test_mismatched_digests_skip_native_processing(self):
        def wrong(_url, path):
            value = b"mismatch"
            path.write_bytes(value)
            return hashlib.sha256(value).hexdigest(), len(value)
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(native, "scan_aar") as scan:
            report, okay = native.collect(Path(temp), downloader=wrong)
        self.assertFalse(okay)
        self.assertFalse(scan.called)
        self.assertFalse(report["vendor_approved"])
        self.assertEqual(2, len(report["candidates"]))

if __name__ == "__main__":
    unittest.main()
