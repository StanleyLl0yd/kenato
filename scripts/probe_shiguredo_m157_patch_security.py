#!/usr/bin/env python3
"""Exact Shiguredo m157.8103.4.0 CVE-source and producer patch audit.

Research only: positive source fingerprints and release/producer artifact
identity do not establish an independently reproducible native binary, all
transitive-license compliance, JNI safety or vendor approval.
"""
from __future__ import annotations

import argparse
import ast
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

import probe_shiguredo_m157 as vendor
import probe_shiguredo_m157_source as old
import probe_shiguredo_m157_notice as notice

TAG = vendor.PATCH_TAG
PRODUCER_SHA = vendor.PATCH_PRODUCER_TAG_SHA
SOURCE_SHA = vendor.PATCH_PUBLISHER_DECLARED_WEBRTC_SHA
PRODUCER_ROOT = ("https://raw.githubusercontent.com/shiguredo-webrtc-build/"
                 "webrtc-build/" + PRODUCER_SHA + "/")
SOURCE_ROOT = "https://webrtc.googlesource.com/src/+/" + SOURCE_SHA + "/"
PRODUCER_RUN = 40991854569
PRODUCER_ARTIFACT_ID = 12951911807
NOTICE_SHA256 = "e5e1a734e1f1e73a0526a4f6ab857f26c4657eb5a70c4f4bc05c20c5444e1ec9"
NOTICE_BYTES = 214353
WEBRTC_ROOT_LICENSE_PATH = "LICENSE"
SOURCE_LICENSE_GENERATOR_PATH = "tools_webrtc/libs/generate_licenses.py"
PRODUCER_ROOT_LICENSE_PATH = "LICENSE"
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
    "turn_tls_client_certificate.patch", "android_turn_tls_client_certificate.patch",
    "android_jni_zero_generated_java.patch", "logging_sink_min_severity.patch",
)
SOURCE_PATHS = (
    old.UPSTREAM_RTP_PATH, old.UPSTREAM_RTP_HEADER_PATH,
    old.UPSTREAM_H264_PATH, old.UPSTREAM_H265_PATH,
    old.UPSTREAM_VIDEO_SENDER_PATH, old.UPSTREAM_SCTP_PATH,
    old.UPSTREAM_TRANSCEIVER_PATH, old.UPSTREAM_PEER_CONNECTION_PATH,
    old.UPSTREAM_TRANSCEIVER_LIST_PATH,
    "modules/rtp_rtcp/source/forward_error_correction.cc",
    "modules/rtp_rtcp/source/forward_error_correction_internal.h",
    "modules/rtp_rtcp/source/forward_error_correction_internal.cc",
)
CRITICAL_SOURCES = frozenset(SOURCE_PATHS)
MAX_SIZE = 5 * 1024 * 1024

class SourceEvidenceError(ValueError):
    pass

def allowed_url(url: str) -> tuple[str, int]:
    sources = {SOURCE_ROOT + path + "?format=TEXT" for path in SOURCE_PATHS}
    sources.add(SOURCE_ROOT + WEBRTC_ROOT_LICENSE_PATH + "?format=TEXT")
    sources.add(SOURCE_ROOT + SOURCE_LICENSE_GENERATOR_PATH + "?format=TEXT")
    producers = {PRODUCER_ROOT + path for path in
                 ("VERSION", "run.py", "NOTICE", PRODUCER_ROOT_LICENSE_PATH)}
    producers.update(PRODUCER_ROOT + "patches/" + patch for patch in PATCHES)
    if url in sources:
        return "webrtc.googlesource.com", MAX_SIZE
    if url in producers:
        return "raw.githubusercontent.com", 512 * 1024
    raise SourceEvidenceError("Not an exact SHA-pinned source URL")

def fetch_exact(url: str, *, runner=subprocess.run, sleeper=time.sleep) -> bytes:
    host, maximum = allowed_url(url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != host or (
        parsed.username or parsed.password or parsed.fragment or parsed.port is not None
    ):
        raise SourceEvidenceError("Unsafe or unsupported source host")
    status = b""
    # Gitiles can temporarily return 503 during an otherwise valid exact-SHA
    # audit. Never redirect, change commit/URL/host or substitute unpinned data.
    for attempt in range(4):
        try:
            reply = runner([
                "curl", "--silent", "--show-error", "--proto", "=https",
                "--max-time", "35", "--connect-timeout", "15",
                "--max-filesize", str(maximum), "--write-out",
                "\\n@@KENATO_STATUS:%{http_code}", "--url", url,
            ], capture_output=True, timeout=42, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SourceEvidenceError("Pinned producer/source fetch failed") from error
        payload, split, status = reply.stdout.rpartition(b"\n@@KENATO_STATUS:")
        if reply.returncode == 0 and split and status == b"200" and (
            payload and len(payload) <= maximum
        ):
            return payload
        temporary = status in {b"429", b"502", b"503", b"504"} and split
        if not temporary or attempt == 3:
            break
        sleeper(min(2 ** attempt, 4))
    raise SourceEvidenceError("Pinned snapshot rejected at " +
                              parsed.path.rsplit("/", 1)[-1][:96] +
                              " status=" + status.decode("ascii", "replace")[:8])

def validate_fec_fixes(fec: str, header: str, internal: str) -> None:
    """CVE-2026-118328 source-level two-commit FEC hardening fingerprints."""
    begin = fec.find("InsertZerosInPacketMasks(")
    if begin < 0:
        raise SourceEvidenceError("FEC mask insertion function absent")
    section = fec[begin:begin + 9000]
    # This covers the second fix: avoid unbounded writes when seqno wraps twice.
    if "if (new_bit_index == max_media_packets)" in section:
        raise SourceEvidenceError("CVE-2026-118328 stale equality/break gate")
    if len(re.findall(r"if\s*\(\s*new_bit_index\s*>=\s*max_media_packets\s*\)", section)) < 2:
        raise SourceEvidenceError("CVE-2026-118328 two strict FEC range guards absent")
    # Initial and post-hole guards must stop before copying a mask column.
    first = section.find("if (new_bit_index >= max_media_packets)")
    update = section.find("new_bit_index += num_zeros_to_insert")
    second = section.find("if (new_bit_index >= max_media_packets)", update)
    copy = section.find("internal::CopyColumn(", update)
    if not (0 <= first < update < second < copy and
            "return -1;" in section[first:update] and
            "return -1;" in section[second:copy]):
        raise SourceEvidenceError("CVE-2026-118328 FEC guards are not fail-closed")
    # First upstream fix spanified packet-mask tables, reducing unsafe indexing.
    if not ("std::span<const uint8_t>" in header and
            "std::span<const uint8_t>" in internal):
        raise SourceEvidenceError("CVE-2026-118328 FEC table span hardening absent")

def check_root_license(payload: bytes, *, origin: str) -> dict:
    """Pin source-root license evidence; never classify transitive or linked code."""
    if origin not in ("webrtc_source", "publisher_build_project") or not (
        150 <= len(payload) <= 65536
    ):
        raise SourceEvidenceError("Missing or unbounded pinned root license")
    try:
        normalized = " ".join(payload.decode("utf-8").casefold().split())
    except UnicodeError as error:
        raise SourceEvidenceError("Invalid pinned root license encoding") from error
    checks = (
        ("redistribution and use in source and binary forms",
         "redistributions of source code must retain",
         "redistributions in binary form must reproduce",
         "neither the name of")
        if origin == "webrtc_source" else
        ("apache license", "version 2.0, january 2004",
         "terms and conditions for use, reproduction, and distribution",
         "grant of patent license", "redistribution.")
    )
    if any(phrase not in normalized for phrase in checks):
        raise SourceEvidenceError("Pinned source-root license clauses differ")
    return {
        "origin": origin,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "textual_license_pattern_candidate": (
            "BSD-3-Clause" if origin == "webrtc_source" else "Apache-2.0"
        ),
        "root_license_clause_fingerprint_present": True,
        "actual_linked_component_license_verified": False,
        "complete_license_spdx_audit": False,
        "independent_legal_clearance": False,
    }

def inspect_license_generator_snapshot(payload: bytes) -> dict:
    """Source-map hints only: no code execution, GN desc, SPDX or linked-SBOM claim."""
    if not 200 <= len(payload) <= 128 * 1024:
        raise SourceEvidenceError("Exact license generator missing or oversized")
    try:
        script = payload.decode("utf-8")
        syntax = ast.parse(script)
    except (UnicodeError, SyntaxError) as error:
        raise SourceEvidenceError("Invalid exact source license generator") from error

    def static_string(expr: ast.AST) -> str:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return static_string(expr.left) + static_string(expr.right)
        raise SourceEvidenceError("Dynamic or executable license-path expression")

    def static_mapping(name: str) -> dict[str, list[str]]:
        assignments = [node.value for node in syntax.body
                       if isinstance(node, ast.Assign) and
                       len(node.targets) == 1 and
                       isinstance(node.targets[0], ast.Name) and
                       node.targets[0].id == name]
        if len(assignments) != 1 or not isinstance(assignments[0], ast.Dict):
            raise SourceEvidenceError("Missing or ambiguous license source map")
        tree = assignments[0]
        if not 1 <= len(tree.keys) <= 200:
            raise SourceEvidenceError("Unbounded license generator entries")
        mapping = {}
        for key_ast, value_ast in zip(tree.keys, tree.values):
            key = static_string(key_ast)
            if not (1 <= len(key) <= 128) or key in mapping:
                raise SourceEvidenceError("Bad or repeated generator license key")
            if not isinstance(value_ast, (ast.List, ast.Tuple)) or len(value_ast.elts) > 12:
                raise SourceEvidenceError("Dynamic or unbounded license path set")
            values = [static_string(value) for value in value_ast.elts]
            for path in values:
                parts = path.split("/")
                if not (1 <= len(path) <= 256 and
                        all(part not in ("", ".", "..") for part in parts) and
                        re.fullmatch(r"[a-zA-Z0-9_.+/-]+", path) and
                        not path.startswith("/")):
                    raise SourceEvidenceError("Unsafe upstream license file path")
            if len(set(values)) != len(values):
                raise SourceEvidenceError("Repeated source license file")
            mapping[key] = values
        return mapping

    components = static_mapping("LIB_TO_LICENSES_DICT")
    patterns = static_mapping("LIB_REGEX_TO_LICENSES_DICT")
    for key in ("webrtc", "boringssl", "libsrtp", "libvpx", "opus"):
        if not components.get(key):
            raise SourceEvidenceError("Expected source license component absent: " + key)
    if components["webrtc"] != ["LICENSE"] or not (
        "gn desc" in script.casefold() and "generate_license_text" in script
    ):
        raise SourceEvidenceError("License generator GN/root contract changed")
    matched = {
        component: components[component]
        for component in sorted(notice.COMPONENTS) if components.get(component)
    }
    not_mapped = sorted(set(notice.COMPONENTS) - set(matched))
    return {
        "source_sha256": hashlib.sha256(payload).hexdigest(),
        "source_bytes": len(payload),
        "generator_source_path": SOURCE_LICENSE_GENERATOR_PATH,
        "notice_component_count": len(notice.COMPONENTS),
        "mapped_notice_component_count": len(matched),
        "unmapped_notice_component_count": len(not_mapped),
        "notice_components_with_source_license_path_candidates": matched,
        "notice_components_without_direct_source_license_map": not_mapped,
        "generator_direct_map_entry_count": len(components),
        "generator_regex_map_entry_count": len(patterns),
        "gn_desc_build_graph_independently_reproduced": False,
        "mapped_license_texts_independently_verified": False,
        "license_source_paths_prove_binary_linkage": False,
        "transitive_license_spdx_clearance": False,
    }

def require_complete_notice_license_path_map(report: dict) -> None:
    # All known exact-pinned NOTICE headings must retain generator-source maps.
    # This is still NOT native-linkage evidence or SPDX clearance.
    if (report.get("notice_component_count") != len(notice.COMPONENTS) or
            report.get("mapped_notice_component_count") != len(notice.COMPONENTS) or
            report.get("unmapped_notice_component_count") != 0 or
            report.get("notice_components_without_direct_source_license_map") != []):
        raise SourceEvidenceError("Pinned NOTICE headings lost source license paths")

def has_exact_notice_generator_invocation(producer_run: str) -> bool:
    # Publisher builds this path using three os.path.join arguments.
    return bool(re.search(
        r"""['"]tools_webrtc['"]\s*,\s*['"]libs['"]\s*,\s*['"]generate_licenses\.py['"]""",
        producer_run,
    ))

def validate_producer(version: str, run: str, patch_texts: dict[str, str]) -> dict:
    fields = {}
    for line in version.splitlines():
        if not line:
            continue
        key, eq, val = line.partition("=")
        if not eq or key in fields:
            raise SourceEvidenceError("Malformed producer VERSION")
        fields[key] = val
    if fields.get("WEBRTC_BUILD_VERSION") != "157.8103.4.0" or (
        fields.get("WEBRTC_COMMIT") != SOURCE_SHA
    ):
        raise SourceEvidenceError("Producer exact tag/source mismatch")
    if "rtc_use_h264=false" not in run:
        raise SourceEvidenceError("Unrecognized Shiguredo Android GN profile")
    def listing(target: str) -> list[str]:
        found = re.search(r"(?P<q>['\"])" + re.escape(target) +
                          r"(?P=q)\s*:\s*\[([^\]]+)\]", run)
        if not found:
            raise SourceEvidenceError("Producer patch target absent: " + target)
        return re.findall(r"['\"]([^'\"]+\.patch)['\"]", found.group(2))
    if listing("android") != list(PATCHES) or listing("android_sdk") != list(PATCHES):
        raise SourceEvidenceError("Producer Android patch list changed")
    touched = set()
    snapshots = {}
    for patch in PATCHES:
        payload = patch_texts[patch]
        destinations = re.findall(r"^diff --git a/(\S+) b/(\S+)$",
                                  payload, re.MULTILINE)
        if not destinations or any(x != y for x, y in destinations):
            raise SourceEvidenceError("Invalid vendor patch path mapping: " + patch)
        for path, _ in destinations:
            if path in CRITICAL_SOURCES:
                raise SourceEvidenceError("Vendor patch modifies source CVE target: " + patch)
            touched.add(path)
        snapshots[patch] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {
        "producer_sha": PRODUCER_SHA,
        "producer_android_sdk_run": PRODUCER_RUN,
        "producer_android_sdk_artifact_id": PRODUCER_ARTIFACT_ID,
        "declared_source_sha": SOURCE_SHA,
        "patch_count": len(PATCHES),
        "patch_sha256": snapshots,
        "patch_target_path_count": len(touched),
        "direct_cve_source_files_modified_by_publisher_patches": False,
        "rtc_use_h264": False,
    }

def check_snapshots(source: dict[str, str]) -> dict:
    old.validate_vp9_source(source[old.UPSTREAM_RTP_PATH])
    old.validate_sctp_source(source[old.UPSTREAM_SCTP_PATH])
    old.validate_transceiver_source(source[old.UPSTREAM_TRANSCEIVER_PATH])
    old.validate_mid_binding_source(
        source[old.UPSTREAM_PEER_CONNECTION_PATH],
        source[old.UPSTREAM_TRANSCEIVER_PATH],
        source[old.UPSTREAM_TRANSCEIVER_LIST_PATH],
    )
    old.validate_rtp_payload_capacity_source(
        source[old.UPSTREAM_RTP_PATH],
        source[old.UPSTREAM_RTP_HEADER_PATH],
        source[old.UPSTREAM_H264_PATH],
        source[old.UPSTREAM_H265_PATH],
        source[old.UPSTREAM_VIDEO_SENDER_PATH],
    )
    validate_fec_fixes(
        source["modules/rtp_rtcp/source/forward_error_correction.cc"],
        source["modules/rtp_rtcp/source/forward_error_correction_internal.h"],
        source["modules/rtp_rtcp/source/forward_error_correction_internal.cc"],
    )
    return {
        "CVE-2026-78891": "SOURCE_FIX_FINGERPRINT_PRESENT",
        "CVE-2026-9962": "SOURCE_FIX_FINGERPRINT_PRESENT",
        "CVE-2026-106268": "SOURCE_FIX_FINGERPRINT_PRESENT",
        "CVE-2026-103631": "SOURCE_FIX_FINGERPRINT_PRESENT",
        "CVE-2026-106357": "SOURCE_FIX_FINGERPRINT_PRESENT",
        "CVE-2026-118328": "SOURCE_FIX_FINGERPRINT_PRESENT",
        "CVE-2026-110137": "BLINK_RENDERER_COMPONENT_OUTSIDE_ANDROID_SDK_BUILD",
    }

def collect(*, fetcher=fetch_exact) -> dict:
    version = fetcher(PRODUCER_ROOT + "VERSION").decode("utf-8")
    run = fetcher(PRODUCER_ROOT + "run.py").decode("utf-8")
    patches = {name: fetcher(PRODUCER_ROOT + "patches/" + name).decode("utf-8")
               for name in PATCHES}
    producer = validate_producer(version, run, patches)
    encoded_sources = {path: fetcher(SOURCE_ROOT + path + "?format=TEXT")
                       for path in SOURCE_PATHS}
    try:
        sources = {path: base64.b64decode(data, validate=True).decode("utf-8")
                   for path, data in encoded_sources.items()}
    except (UnicodeError, binascii.Error) as error:
        raise SourceEvidenceError("Invalid pinned Gitiles source encoding") from error
    statuses = check_snapshots(sources)
    try:
        upstream_license = base64.b64decode(
            fetcher(SOURCE_ROOT + WEBRTC_ROOT_LICENSE_PATH + "?format=TEXT"),
            validate=True)
    except (binascii.Error, ValueError) as error:
        raise SourceEvidenceError("Invalid pinned upstream LICENSE encoding") from error
    generator_encoded = fetcher(SOURCE_ROOT + SOURCE_LICENSE_GENERATOR_PATH + "?format=TEXT")
    try:
        generator = base64.b64decode(generator_encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SourceEvidenceError("Invalid pinned generator Gitiles encoding") from error
    if not has_exact_notice_generator_invocation(run):
        raise SourceEvidenceError("Publisher no longer invokes expected GN notice generator")
    license_generator_inventory = inspect_license_generator_snapshot(generator)
    require_complete_notice_license_path_map(license_generator_inventory)
    root_licenses = {
        "upstream_webrtc": check_root_license(
            upstream_license, origin="webrtc_source"),
        "publisher_build_project": check_root_license(
            fetcher(PRODUCER_ROOT + PRODUCER_ROOT_LICENSE_PATH),
            origin="publisher_build_project"),
    }
    publisher_notice = fetcher(PRODUCER_ROOT + "NOTICE")
    if b"## WebRTC" not in publisher_notice or b"## WebKit" not in publisher_notice:
        raise SourceEvidenceError("Publisher source NOTICE lacks basic attributions")
    return {
        "status": "PINNED_PATCH_SOURCE_FIXES_PASS_NOT_NATIVE_APPROVAL",
        "tag": TAG,
        "producer": producer,
        "binary_aar_sha256_REFERENCED": vendor.PATCH_EXPECTED_SHA256,
        "binary_source_reproduction_verified": False,
        "producer_release_artifact_byte_identity_independently_checked": True,
        "producer_archive_notice_exact_embedded_match_INDEPENDENTLY_VERIFIED": True,
        "publisher_repository_notice_sha256": hashlib.sha256(publisher_notice).hexdigest(),
        "producer_archive_and_aar_notice_sha256": NOTICE_SHA256,
        "producer_archive_notice_bytes": NOTICE_BYTES,
        "root_license_text_evidence_not_transitive_clearance": root_licenses,
        "upstream_exact_license_generator_not_sbom": license_generator_inventory,
        "source_snapshots_sha256": {
            path: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for path, content in sources.items()
        },
        "source_cve_fingerprints": statuses,
        "all_native_cves_cleared": False,
        "all_third_party_license_obligations_verified": False,
        "native_jni_executed": False,
        "vendor_approved": False,
    }

def main() -> int:
    options = argparse.ArgumentParser(description=__doc__)
    options.add_argument("--output", required=True, type=Path)
    args = options.parse_args()
    try:
        report = collect()
        code = 0
    except (SourceEvidenceError, old.SourceProbeError, OSError, ValueError) as error:
        report = {"status": "PINNED_PATCH_SOURCE_EVIDENCE_FAILED",
                  "error_type": type(error).__name__, "reason": str(error)[:200],
                  "vendor_approved": False}
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print("Shiguredo m157.8103.4.0 pinned source CVE audit:", report["status"])
    if code == 0:
        print("CVE source fix fingerprints: 6; Blink-only issue scoped out.")
        print("Native compilation equivalence, exploitation, JNI and third-party licenses NOT approved.")
    else:
        print("Failure:", report["error_type"], report["reason"])
    return code

if __name__ == "__main__":
    sys.exit(main())
