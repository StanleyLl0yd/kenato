#!/usr/bin/env python3
"""Exact m158.8127.1.0 source-CVE, patch-chain and license-path research.

This never approves a native ELF, executes JNI, imports an AAR into Kenato,
generates an SPDX SBOM or provides legal clearance. New source fingerprints
must be checked at the new commit, not inherited from Shiguredo m157.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import probe_shiguredo_m157_patch_security as base

TAG = "m158.8127.1.0"
PRODUCER_SHA = "e60fe55f9c9c4dd6b02a12479107602a36b0951f"
SOURCE_SHA = "fb1c41a93d92d4188f068f437d80ef2c4b50c3a9"
PRODUCER_ROOT = ("https://raw.githubusercontent.com/shiguredo-webrtc-build/"
                 "webrtc-build/" + PRODUCER_SHA + "/")
SOURCE_ROOT = "https://webrtc.googlesource.com/src/+/" + SOURCE_SHA + "/"
PRODUCER_RUN = 41959194651
PRODUCER_ARTIFACT_ID = 13386994126
RELEASE_AAR_SHA256 = "8a2f4da8e9546d9242d67b9bbb5b9ef0e4fa0e75a4bd86b431209f67a65176cf"
RELEASE_AAR_BYTES = 14889470
ARM64_ELF_SHA256 = "010e394de8d114133fca568abec3efbacd05865da5b75f662f0d17863b06bf81"
NOTICE_SHA256 = base.NOTICE_SHA256
NOTICE_BYTES = base.NOTICE_BYTES
SOURCE_LICENSE_GENERATOR_PATH = base.SOURCE_LICENSE_GENERATOR_PATH
PATCHES = (
    "add_deps.patch", "4k.patch", "revive_proxy.patch",
    "ssl_verify_callback_with_native_handle.patch",
    "android_webrtc_version.patch", "android_fixsegv.patch",
    "android_simulcast.patch", "android_hardware_video_encoder.patch",
    "android_proxy.patch", "h265.patch", "h265_android.patch",
    "remove_crel.patch", "revert_siso.patch",
    "android_audio_pause_resume.patch", "android_audio_track_sink.patch",
    "unsafe_buffers_optout_list.patch",
    "android_ssl_certificate_verifier_chain.patch",
    "turn_tls_client_certificate.patch",
    "android_turn_tls_client_certificate.patch",
    "android_jni_zero_generated_java.patch",
    "android_toi420_failure_handling.patch",
)
SOURCE_PATHS = base.SOURCE_PATHS
CRITICAL_SOURCES = base.CRITICAL_SOURCES
MAX_SOURCE_BYTES = base.MAX_SIZE


class M158EvidenceError(ValueError):
    pass


def allowed_url(url: str) -> tuple[str, int]:
    gitiles = {SOURCE_ROOT + name + "?format=TEXT" for name in SOURCE_PATHS}
    gitiles.add(SOURCE_ROOT + "LICENSE?format=TEXT")
    gitiles.add(SOURCE_ROOT + SOURCE_LICENSE_GENERATOR_PATH + "?format=TEXT")
    publisher = {PRODUCER_ROOT + name
                 for name in ("VERSION", "run.py", "NOTICE", "LICENSE")}
    publisher.update(PRODUCER_ROOT + "patches/" + name for name in PATCHES)
    if url in gitiles:
        return "webrtc.googlesource.com", MAX_SOURCE_BYTES
    if url in publisher:
        return "raw.githubusercontent.com", 512 * 1024
    raise M158EvidenceError("Source URL not explicitly pinned to exact m158 SHA")


def fetch_exact(url: str, *, runner=subprocess.run, sleeper=time.sleep) -> bytes:
    host, bound = allowed_url(url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != host or (
        parsed.username or parsed.password or parsed.port is not None
        or parsed.fragment
    ):
        raise M158EvidenceError("Unsafe or unsupported source URI")
    status = b""
    for attempt in range(4):
        try:
            result = runner(
                ["curl", "--silent", "--show-error", "--proto", "=https",
                 "--max-time", "35", "--connect-timeout", "15",
                 "--max-filesize", str(bound),
                 "--write-out", "\n@@KENATO_STATUS:%{http_code}",
                 "--url", url],
                capture_output=True, timeout=42, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise M158EvidenceError("Exact source fetch failed") from error
        body, sep, status = result.stdout.rpartition(b"\n@@KENATO_STATUS:")
        if result.returncode == 0 and sep and status == b"200":
            if not body or len(body) > bound:
                raise M158EvidenceError("Exact pinned source is missing/oversized")
            return body
        if result.returncode != 0 or not sep or status not in (
            b"429", b"502", b"503", b"504"
        ) or attempt == 3:
            break
        sleeper(min(2 ** attempt, 4))
    raise M158EvidenceError("Pinned source rejected at " +
                            parsed.path.rsplit("/", 1)[-1][:80] +
                            " status=" + status.decode("ascii", "replace")[:8])


def verify_producer(version: str, build_script: str,
                    vendor_patches: dict[str, str]) -> dict:
    fields = {}
    for line in version.splitlines():
        if not line:
            continue
        key, sep, val = line.partition("=")
        if sep != "=" or key in fields:
            raise M158EvidenceError("Malformed/duplicate producer VERSION field")
        fields[key] = val
    if (fields.get("WEBRTC_BUILD_VERSION") != "158.8127.1.0" or
            fields.get("WEBRTC_COMMIT") != SOURCE_SHA):
        raise M158EvidenceError("New publisher tag/source mismatch")
    if "rtc_use_h264=false" not in build_script:
        raise M158EvidenceError("Unexpected m158 Android H264 GN flag")
    if not base.has_exact_notice_generator_invocation(build_script):
        raise M158EvidenceError("Publisher no longer calls pinned notice generator")

    def ordered_patches(target: str) -> list[str]:
        regex = r"""(?P<quote>['"])""" + re.escape(target) + (
            r"""(?P=quote)\s*:\s*\[([^\]]+)\]"""
        )
        block = re.search(regex, build_script)
        if block is None:
            raise M158EvidenceError("Missing Android patch selection: " + target)
        return re.findall(r"""['"]([^'"]+\.patch)['"]""", block.group(2))

    if (ordered_patches("android") != list(PATCHES) or
            ordered_patches("android_sdk") != list(PATCHES) or
            set(vendor_patches) != set(PATCHES)):
        raise M158EvidenceError("Unexpected m158 Android SDK patch-chain")
    digests = {}
    touched = set()
    for name in PATCHES:
        raw = vendor_patches[name]
        changes = re.findall(r"^diff --git a/(\S+) b/(\S+)$", raw, re.M)
        if not changes or any(left != right for left, right in changes):
            raise M158EvidenceError("Unsafe or missing publisher patch paths: " + name)
        for path, _ in changes:
            if path in CRITICAL_SOURCES:
                raise M158EvidenceError("Publisher changed CVE source target: " + name)
            touched.add(path)
        digests[name] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if not any("sdk/android/api/org/webrtc/YuvConverter.java" in
               row for row in touched):
        raise M158EvidenceError("Expected new ToI420 Java patch path absent")
    if "sdk/android/src/jni/android_video_track_source.cc" not in touched:
        raise M158EvidenceError("Expected new ToI420 JNI patch path absent")
    return {
        "producer_sha": PRODUCER_SHA,
        "declared_source_sha": SOURCE_SHA,
        "producer_build_run": PRODUCER_RUN,
        "producer_actions_artifact_id": PRODUCER_ARTIFACT_ID,
        "patch_count": len(PATCHES),
        "patch_sha256": digests,
        "distinct_touched_paths": len(touched),
        "direct_cve_source_files_modified_by_publisher": False,
        "rtc_use_h264": False,
        "native_source_equivalence_or_patch_reachability_verified": False,
    }


def collect(*, fetcher=fetch_exact) -> dict:
    producer_version = fetcher(PRODUCER_ROOT + "VERSION").decode("utf-8")
    publisher_run = fetcher(PRODUCER_ROOT + "run.py").decode("utf-8")
    patch_texts = {name: fetcher(PRODUCER_ROOT + "patches/" + name).decode("utf-8")
                   for name in PATCHES}
    producer = verify_producer(producer_version, publisher_run, patch_texts)
    encoded = {name: fetcher(SOURCE_ROOT + name + "?format=TEXT")
               for name in SOURCE_PATHS}
    try:
        snapshots = {
            name: base64.b64decode(value, validate=True).decode("utf-8")
            for name, value in encoded.items()
        }
    except (UnicodeError, binascii.Error) as error:
        raise M158EvidenceError("Invalid exact Gitiles C++ source encoding") from error

    # Reuse *pure* upstream six-CVE source validators but evaluate against
    # this NEW SHA. A refactored or missing predicate fails closed and cannot
    # be mistaken for a native build security verdict.
    cves = base.check_snapshots(snapshots)
    raw_license = fetcher(SOURCE_ROOT + "LICENSE?format=TEXT")
    raw_generator = fetcher(SOURCE_ROOT + SOURCE_LICENSE_GENERATOR_PATH + "?format=TEXT")
    try:
        source_license = base64.b64decode(raw_license, validate=True)
        generator_source = base64.b64decode(raw_generator, validate=True)
    except (ValueError, binascii.Error) as error:
        raise M158EvidenceError("Invalid pinned license source encoding") from error
    license_hints = base.inspect_license_generator_snapshot(generator_source)
    base.require_complete_notice_license_path_map(license_hints)
    publisher_license = fetcher(PRODUCER_ROOT + "LICENSE")
    notice = fetcher(PRODUCER_ROOT + "NOTICE")
    if b"## WebRTC" not in notice or b"## WebKit" not in notice:
        raise M158EvidenceError("Incomplete publisher source notice")
    return {
        "status": "PINNED_M158_SOURCE_CVE_FINGERPRINTS_PASS_NOT_BINARY_APPROVAL",
        "producer": producer,
        "release_aar_sha256_REFERENCED_NOT_REBUILT": RELEASE_AAR_SHA256,
        "release_aar_bytes_REFERENCED": RELEASE_AAR_BYTES,
        "arm64_elf_sha256_REFERENCED_NOT_REBUILT": ARM64_ELF_SHA256,
        "publisher_source_notice_sha256":
            hashlib.sha256(notice).hexdigest(),
        "generated_aar_notice_sha256_INDEPENDENTLY_VERIFIED":
            NOTICE_SHA256,
        "generated_aar_notice_bytes": NOTICE_BYTES,
        "source_file_sha256": {
            name: hashlib.sha256(text.encode("utf-8")).hexdigest()
            for name, text in snapshots.items()
        },
        "source_cve_fingerprints": cves,
        "source_root_license_not_transitive_approval": {
            "upstream_webrtc": base.check_root_license(
                source_license, origin="webrtc_source"),
            "publisher_build_project": base.check_root_license(
                publisher_license, origin="publisher_build_project"),
        },
        "source_license_paths_not_spdx_clearance": license_hints,
        "new_vendor_to_i420_patch_jni_runtime_reviewed": False,
        "complete_linked_sbom_legal_clearance": False,
        "eight_mozilla_cve_applicability_cleared": False,
        "native_compilation_reproduced": False,
        "native_jni_executed": False,
        "vendor_approved": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    try:
        result = collect()
        ok = True
    except (M158EvidenceError, base.SourceEvidenceError,
            OSError, ValueError, UnicodeError) as error:
        result = {
            "status": "PINNED_M158_SOURCE_CVE_EVIDENCE_FAILED",
            "error_type": type(error).__name__,
            "reason": str(error)[:200],
            "vendor_approved": False,
        }
        ok = False
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")
    print("Exact m158 producer/CVE/NOTICE source audit:", result["status"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
