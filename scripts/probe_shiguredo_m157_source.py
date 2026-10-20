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
import subprocess
import sys
import urllib.parse
from pathlib import Path

PUBLISHER_SHA = "c575fdf836d1185d8cefda37197a2a489e95ffd9"
WEBRTC_SHA = "b321f634929af0af61a8964487fbd7894a008f12"
VERSION = "157.8103.0.0"
EXPECTED_AAR_SHA256 = "b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a"
PUBLISHER_ROOT = "https://raw.githubusercontent.com/shiguredo-webrtc-build/webrtc-build/" + PUBLISHER_SHA + "/"
GITILES_ROOT = "https://webrtc.googlesource.com/src/+/" + WEBRTC_SHA + "/"
UPSTREAM_RTP_PATH = "modules/rtp_rtcp/source/rtp_format.cc"
UPSTREAM_SCTP_PATH = "pc/sctp_data_channel.cc"
MAX_VERSION = 4096
MAX_NOTICE = 128 * 1024
MAX_LICENSE = 128 * 1024
MAX_RTP_BASE64 = 2 * 1024 * 1024
MAX_SCTP_BASE64 = 2 * 1024 * 1024


class SourceProbeError(ValueError):
    pass


def fetch_exact(url: str, *, maximum: int, host: str) -> bytes:
    # Never use a general URL fetch. All four resources are exact and pinned.
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.username or parsed.password or
            parsed.port is not None or parsed.fragment):
        raise SourceProbeError("Invalid pinned HTTPS source URI")
    if host == "raw.githubusercontent.com":
        allowed = (PUBLISHER_ROOT + "VERSION",
                   PUBLISHER_ROOT + "LICENSE",
                   PUBLISHER_ROOT + "NOTICE")
    elif host == "webrtc.googlesource.com":
        allowed = (GITILES_ROOT + UPSTREAM_RTP_PATH + "?format=TEXT",
                   GITILES_ROOT + UPSTREAM_SCTP_PATH + "?format=TEXT")
    else:
        raise SourceProbeError("Source host outside exact allowlist")
    if parsed.hostname != host or url not in allowed:
        raise SourceProbeError("Source URL outside exact allowlist")
    # curl is provided by the pinned ubuntu-24.04 GitHub Actions runner.
    # No shell, redirects, HTTP, proxies via user arguments, or arbitrary URL.
    try:
        result = subprocess.run(
            ["curl", "--silent", "--show-error", "--proto", "=https",
             "--max-time", "30", "--connect-timeout", "15",
             "--max-filesize", str(maximum),
             "--write-out", "\n@@KENATO_STATUS:%{http_code}",
             "--url", url],
            capture_output=True, timeout=40, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SourceProbeError("Pinned source retrieval failed") from error
    if result.returncode != 0:
        raise SourceProbeError("Pinned source transport rejected response")
    body, sep, status = result.stdout.rpartition(b"\n@@KENATO_STATUS:")
    if not sep or status != b"200":
        raise SourceProbeError("Pinned source did not return HTTP 200")
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


def validate_sctp_source(source: str) -> None:
    # CVE-2026-9962: Chromium bug 504716948, upstream fix 9b4ffb3
    # (2026-05-06). Only a SOURCE fingerprint; Android ELF remains unproven.
    if not re.search(r"void\s+SctpDataChannel::SendAsync\s*\(", source):
        raise SourceProbeError("CVE-2026-9962: SendAsync method absent")
    if not re.search(
        r"scoped_refptr\s*<\s*SctpDataChannel\s*>\s+me\s*\(\s*this\s*\)\s*;",
        source,
    ):
        raise SourceProbeError("CVE-2026-9962: reference-counted SendAsync receiver absent")
    if not re.search(
        r"network_thread_->PostTask\s*\(\s*\[\s*me\s*=\s*std::move\s*\(\s*me\s*\)",
        source,
    ):
        raise SourceProbeError("CVE-2026-9962: posted task does not retain receiver")
    if re.search(
        r"network_thread_->PostTask\s*\(\s*SafeTask\s*\(\s*network_safety_",
        source,
    ):
        raise SourceProbeError("CVE-2026-9962: unsafe task safety flag pattern present")


def inspect_snapshots(version: str, license_text: str, notice: str, source: str, sctp_source: str) -> dict:
    validate_version(version)
    validate_licenses(license_text, notice)
    validate_vp9_source(source)
    validate_sctp_source(sctp_source)
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
        "cve_2026_9962_upstream_source_fix_signature": True,
        "cve_2026_9962_binary_remediation_verified": False,
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
    sctp_encoded = fetch_exact(
        GITILES_ROOT + UPSTREAM_SCTP_PATH + "?format=TEXT",
        maximum=MAX_SCTP_BASE64,
        host="webrtc.googlesource.com",
    )
    try:
        source = base64.b64decode(encoded, validate=True).decode("utf-8")
        sctp_source = base64.b64decode(sctp_encoded, validate=True).decode("utf-8")
        return inspect_snapshots(
            version.decode("utf-8"),
            license_data.decode("utf-8"),
            notice.decode("utf-8"),
            source,
            sctp_source,
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
    except (SourceProbeError, OSError, ValueError) as error:
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
