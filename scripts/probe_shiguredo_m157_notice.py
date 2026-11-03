#!/usr/bin/env python3
"""Inventory exact generated NOTICE from the pinned m157.8103.4.0 AAR, no JNI."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

import collect_webrtc_candidate_evidence as evidence
import probe_shiguredo_m157 as m157

EMBEDDED_NOTICE = "META-INF/NOTICE"
NOTICE_SHA256 = "e5e1a734e1f1e73a0526a4f6ab857f26c4657eb5a70c4f4bc05c20c5444e1ec9"
NOTICE_BYTES = 214353
COMPONENTS = frozenset((
    "webrtc", "abseil-cpp", "android_sdk", "boringssl", "compiler-rt",
    "cpu_features", "dav1d", "fft", "fiat", "g711", "g722", "jni_zero",
    "kotlin_stdlib", "libaom", "libc++", "libc++abi", "libjpeg_turbo",
    "libsrtp", "libunwind", "libvpx", "libyuv", "llvm-libc", "ooura",
    "opus", "perfetto", "pffft", "protobuf", "rnnoise", "rust/cxx/v1",
    "rust/foldhash/v0_2", "rust_stdlib", "sframe", "spl_sqrt_floor", "zlib",
))

class NoticeInventoryError(ValueError):
    pass

def inspect_notice(notice: bytes) -> dict:
    if len(notice) != NOTICE_BYTES or hashlib.sha256(notice).hexdigest() != NOTICE_SHA256:
        raise NoticeInventoryError("Exact generated NOTICE digest or size changed")
    try:
        text = notice.decode("utf-8")
    except UnicodeError as error:
        raise NoticeInventoryError("Generated NOTICE is not UTF-8") from error
    headers = list(re.finditer(r"^# ([^\n\r]+)\r?$", text, re.MULTILINE))
    names = [m.group(1) for m in headers]
    if len(names) != len(COMPONENTS) or len(names) != len(set(names)) or set(names) != COMPONENTS:
        raise NoticeInventoryError("Generated NOTICE component attribution set changed")
    lengths = {}
    for i, match in enumerate(headers):
        part = text[match.end(): headers[i + 1].start() if i + 1 < len(headers)
                    else len(text)]
        if len(part) < 120 or "copyright" not in part.lower():
            raise NoticeInventoryError("Incomplete copyright terms for notice component " + names[i])
        lengths[names[i]] = len(part)
    return {
        "status": "EXACT_EMBEDDED_NOTICE_COMPONENT_INVENTORY_PASS_NOT_LICENSE_CLEARANCE",
        "notice_sha256": NOTICE_SHA256,
        "notice_bytes": NOTICE_BYTES,
        "component_count": len(names),
        "component_attribution_lengths": lengths,
        "copyright_attributions_present_for_every_component": True,
        "all_spdx_licenses_independently_classified": False,
        "native_link_closure_proven_by_notice_alone": False,
        "third_party_notice_obligations_fully_cleared": False,
    }

def collect(*, downloader=evidence.download_snapshot) -> dict:
    url, _size, _sha, _prod, _source = m157.candidate(m157.PATCH_TAG)
    with tempfile.TemporaryDirectory(prefix="kenato-shiguredo-notice-") as root:
        aar = Path(root) / "m157.4.aar"
        digest, size = downloader(url, aar, max_bytes=m157.MAX_BYTES)
        m157.verify_observation(digest, size, tag=m157.PATCH_TAG)
        m157.inspect_pinned_aar(aar, tag=m157.PATCH_TAG)
        with zipfile.ZipFile(aar) as zipped:
            entry = zipped.getinfo(EMBEDDED_NOTICE)
            if entry.file_size != NOTICE_BYTES:
                raise NoticeInventoryError("Embedded NOTICE size changed")
            with zipped.open(entry) as stream:
                notice = stream.read(NOTICE_BYTES + 1)
        report = inspect_notice(notice)
        report["publisher_tag"] = m157.PATCH_TAG
        report["published_aar_sha256"] = digest
        report["vendor_approved"] = False
        return report

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    opt = parser.parse_args()
    try:
        data = collect()
        exit_code = 0
    except (NoticeInventoryError, OSError, ValueError, zipfile.BadZipFile,
            evidence.EvidenceError, evidence.audit.AarAuditError) as error:
        data = {
            "status": "EXACT_GENERATED_NOTICE_INVENTORY_FAILED",
            "failure": type(error).__name__, "reason": str(error)[:180],
            "vendor_approved": False,
        }
        exit_code = 1
    opt.output.parent.mkdir(parents=True, exist_ok=True)
    opt.output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
    print("Shiguredo m157.4 AAR NOTICE:", data["status"])
    print("Full SPDX/transitive binary license clearance: NOT ESTABLISHED")
    return exit_code

if __name__ == "__main__":
    sys.exit(main())
