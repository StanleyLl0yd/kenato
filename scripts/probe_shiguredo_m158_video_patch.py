#!/usr/bin/env python3
"""Pin m158 ToI420 Java/JNI patch failure-path markers separately from CVEs.

Source-only research: NO native memory safety, AAR provenance, legal approval,
video runtime, device/JNI execution or production dependency migration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import probe_shiguredo_m158_patch_security as m158

PATCH_PATH = "patches/android_toi420_failure_handling.patch"
URL = m158.PRODUCER_ROOT + PATCH_PATH


def collect(*, fetcher=m158.fetch_exact) -> dict:
    payload = fetcher(URL)
    if not 0 < len(payload) <= 512 * 1024:
        raise m158.M158EvidenceError("m158 pinned video patch is missing or oversized")
    try:
        patch = payload.decode("utf-8")
    except UnicodeError as error:
        raise m158.M158EvidenceError("m158 pinned video patch encoding invalid") from error
    reviewed = m158.inspect_to_i420_failure_patch(patch)
    return {
        "status": "M158_VIDEO_FAILURE_PATCH_STATIC_MARKERS_PRESENT_NOT_APPROVAL",
        "producer_tag": m158.TAG,
        "producer_exact_sha": m158.PRODUCER_SHA,
        "upstream_declared_sha": m158.SOURCE_SHA,
        "source_patch_path": PATCH_PATH,
        "source_patch_sha256": hashlib.sha256(payload).hexdigest(),
        "static_patch_markers": reviewed,
        "runtime_gl_egl_error_paths_tested": False,
        "android_jni_media_executed": False,
        "source_to_binary_proven": False,
        "vendor_approved": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = collect()
        code = 0
    except (m158.M158EvidenceError, OSError, ValueError) as error:
        result = {
            "status": "M158_VIDEO_FAILURE_PATCH_EVIDENCE_FAILED",
            "error_type": type(error).__name__,
            "reason": str(error)[:160],
            "vendor_approved": False,
        }
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print("Exact m158 Java/JNI video failure-path research:", result["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
