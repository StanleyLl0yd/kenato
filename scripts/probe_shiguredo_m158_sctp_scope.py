#!/usr/bin/env python3
"""Read-only pinned m158 SCTP SendAsync source scope for CVE-2026-9962 review.

This creates evidence for human review, not a vulnerability or binary verdict.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path

import probe_shiguredo_m158_patch_security as m158

TARGET = "pc/sctp_data_channel.cc"
URL = m158.SOURCE_ROOT + TARGET + "?format=TEXT"
MAX_EXCERPT = 4096


def bounded_context(text: str, needle: str, *, limit: int = 2500) -> str:
    """Return a bounded, exact-source context, never the entire upstream file."""
    if not 1 <= limit <= 4096:
        raise m158.M158EvidenceError("Unsafe diagnostic context size")
    at = text.find(needle)
    if at < 0:
        return ""
    if text.find(needle, at + len(needle)) != -1:
        raise m158.M158EvidenceError("Ambiguous source lifecycle marker")
    return text[at:at + limit]


def collect(*, fetcher=m158.fetch_exact) -> dict:
    try:
        payload = base64.b64decode(fetcher(URL), validate=True)
        text = payload.decode("utf-8")
    except (binascii.Error, UnicodeError) as error:
        raise m158.M158EvidenceError("Pinned SCTP source encoding invalid") from error
    needle = "void SctpDataChannel::SendAsync("
    first = text.find(needle)
    if first < 0 or text.find(needle, first + 1) >= 0:
        raise m158.M158EvidenceError("Unique SCTP SendAsync method missing")
    boundary = text.find("\nvoid SctpDataChannel::", first + len(needle))
    if boundary < 0 or boundary - first > MAX_EXCERPT:
        raise m158.M158EvidenceError("SCTP method exceeds review excerpt bound")
    method = text[first:boundary]
    # The excerpt is public pinned source only. No user data, private keys or
    # actual native/vendor SDK runtime enter these artifacts.
    return {
        "status": "EXACT_M158_SCTP_SOURCE_SCOPE_REVIEW_ONLY",
        "source_sha": m158.SOURCE_SHA,
        "source_path": TARGET,
        "source_file_sha256": hashlib.sha256(payload).hexdigest(),
        "send_async_excerpt": method,
        "destructor_context": bounded_context(
            text, "SctpDataChannel::~SctpDataChannel()", limit=1300),
        "set_state_context": bounded_context(
            text, "void SctpDataChannel::SetState(", limit=1800),
        "transport_closed_context": bounded_context(
            text, "void SctpDataChannel::OnTransportChannelClosed(", limit=1600),
        "network_safety_invalidation_count":
            text.count("network_safety_->SetNotAlive()"),
        "network_safety_invalidation_context": bounded_context(
            text, "network_safety_->SetNotAlive()", limit=650),
        "destructor_invalidation_proven_before_object_free": False,
        "contains_ref_counted_capture": "scoped_refptr<SctpDataChannel>" in method,
        "contains_raw_this_capture": "[this" in method,
        "contains_network_safety": "network_safety_" in method,
        "source_fix_or_native_security_approved": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = collect()
        success = True
    except (m158.M158EvidenceError, OSError, ValueError) as error:
        result = {
            "status": "EXACT_M158_SCTP_EVIDENCE_UNAVAILABLE",
            "error_type": type(error).__name__,
            "reason": str(error)[:160],
            "source_fix_or_native_security_approved": False,
        }
        success = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print("Exact m158 SCTP source scope:", result["status"])
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
