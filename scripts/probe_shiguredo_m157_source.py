#!/usr/bin/env python3
"""Research-only, bounded Shiguredo m157 pinned-source and license probe.

Source signature does NOT prove that a published binary contains the patch.
Never change a production dependency or approve a vendor based on this output.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

PUBLISHER_SHA = "c575fdf836d1185d8cefda37197a2a489e95ffd9"
WEBRTC_SHA = "b321f634929af0af61a8964487fbd7894a008f12"
VERSION = "157.8103.0.0"
EXPECTED_AAR_SHA256 = "b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a"
PUBLISHER_ROOT = "https://raw.githubusercontent.com/shiguredo-webrtc-build/webrtc-build/" + PUBLISHER_SHA + "/"
GITILES_ROOT = "https://webrtc.googlesource.com/src/+/" + WEBRTC_SHA + "/"
UPSTREAM_RTP_PATH = "modules/rtp_rtcp/source/rtp_format.cc"
MAX_VERSION = 4096
MAX_NOTICE = 128 * 1024
MAX_LICENSE = 128 * 1024
MAX_RTP_BASE64 = 2 * 1024 * 1024


class SourceProbeError(ValueError):
    pass


def fetch_exact(url: str, *, maximum: int, host: str) -> bytes:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise SourceProbeError("Non-HTTPS source refused")
    request = urllib.request.Request(url, headers={"User-Agent": "Kenato-M5-pinned-source-research/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != host:
            raise SourceProbeError("Unexpected source redirect host")
        body = response.read(maximum + 1)
    if not body or len(body) > maximum:
        raise SourceProbeError("Missing or oversized source snapshot")
    return body


def validate_version(text: str) -> None:
    expected = {
        "WEBRTC_BUILD_VERSION": VERSION,
        "WEBRTC_COMMIT": WEBRTC_SHA,
    }
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if sep != "=" or name in fields:
            raise SourceProbeError("Malformed or duplicate publisher VERSION field")
        fields[name] = value
    for key, value in expected.items():
        if fields.get(key) != value:
            raise SourceProbeError("Publisher VERSION mismatch: " + key)


def validate_licenses(license_text: str, notice_text: str) -> None:
    if not ("Apache License" in license_text and "Version 2.0" in license_text):
        raise SourceProbeError("Publisher Apache-2.0 LICENSE missing")
    for marker in ("## WebRTC", "## WebKit", "Redistribution and use in source and binary forms"):
        if marker not in notice_text:
            raise SourceProbeError("Publisher NOTICE incomplete: " + marker)


def validate_vp9_source(source: str) -> None:
    # CVE-2026-78891 source-level fingerprint. This MUST NOT be described as
    # binary verification: the producer applies patches and builds a native .so.
    if not re.search(
        r"RtpPacketizer::SplitAboutEqually\s*\(\s*size_t\s+payload_size\s*,",
        source,
    ):
        raise SourceProbeError("CVE-2026-78891: size_t SplitAboutEqually signature absent")
    if not re.search(
        r"SafeGt\s*\(\s*(?:payload_size|payload\.size\(\))\s*,"
        r"\s*limits\.max_payload_len\s*\*\s*0x7000\s*\)",
        source,
    ):
        raise SourceProbeError("CVE-2026-78891: bounded payload-size guard absent")
    if re.search(r"RtpPacketizer::SplitAboutEqually\s*\(\s*int\s+payload_len", source):
        raise SourceProbeError("CVE-2026-78891: old int payload signature present")


def inspect_snapshots(version: str, license_text: str, notice: str, source: str) -> dict:
    validate_version(version)
    validate_licenses(license_text, notice)
    validate_vp9_source(source)
    return {
        "status": "PINNED_SOURCE_RESEARCH_PASS_NOT_BINARY_APPROVAL",
        "publisher_git_sha": PUBLISHER_SHA,
        "publisher_version": VERSION,
        "publisher_declared_webrtc_sha": WEBRTC_SHA,
        "pinned_aar_sha256_reference_only": EXPECTED_AAR_SHA256,
        "publisher_license_apache_2_0_present": True,
        "publisher_notice_webrtc_and_webkit_present": True,
        "license_inventory_complete_for_binary": False,
        "cve_2026_78891_upstream_source_fix_signature": True,
        "cve_2026_78891_binary_remediation_verified": False,
        "cve_2026_9962_applicability_verified": False,
        "cve_2026_106268_binary_remediation_verified": False,
        "source_to_published_aar_reproducible": False,
        "producer_patches_and_transitive_components_approved": False,
        "vendor_approved_for_kenato": False,
        "jni_or_microphone_executed": False,
    }


def collect() -> dict:
    version = fetch_exact(PUBLISHER_ROOT + "VERSION", maximum=MAX_VERSION, host="raw.githubusercontent.com")
    license_data = fetch_exact(PUBLISHER_ROOT + "LICENSE", maximum=MAX_LICENSE, host="raw.githubusercontent.com")
    notice = fetch_exact(PUBLISHER_ROOT + "NOTICE", maximum=MAX_NOTICE, host="raw.githubusercontent.com")
    encoded = fetch_exact(
        GITILES_ROOT + UPSTREAM_RTP_PATH + "?format=TEXT",
        maximum=MAX_RTP_BASE64,
        host="webrtc.googlesource.com",
    )
    try:
        source = base64.b64decode(encoded, validate=True).decode("utf-8")
        return inspect_snapshots(
            version.decode("utf-8"),
            license_data.decode("utf-8"),
            notice.decode("utf-8"),
            source,
        )
    except (UnicodeError, binascii.Error) as error:
        raise SourceProbeError("Invalid upstream encoded source") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = collect()
        result = 0
    except (SourceProbeError, OSError, ValueError, urllib.error.URLError) as error:
        report = {
            "status": "PINNED_SOURCE_RESEARCH_FAILED",
            "failure": type(error).__name__,
            "detail": str(error)[:180],
            "vendor_approved_for_kenato": False,
        }
        result = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("M5 pinned Shiguredo source/NOTICE research:", report["status"])
    return result


if __name__ == "__main__":
    raise SystemExit(main())
