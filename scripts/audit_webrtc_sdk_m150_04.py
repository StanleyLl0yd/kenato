#!/usr/bin/env python3
"""Fail-closed native source/CVE rejection audit for exact webrtc-sdk m150.7871.04.

Successful audit execution MUST NOT be interpreted as WebRTC vendor approval.
This consumes only the original, SHA-pinned GitHub Release AAR, exact source
commits and publisher patches. It neither loads JNI nor modifies Kenato.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import collect_webrtc_candidate_evidence as evidence
import probe_shiguredo_m157_elf as elf
import probe_webrtc_native_elf as native

RELEASE_SHA = "f15e6bf94c1cbb9d6defaa95f04d1ae16b84e897f584032781091022d8366e30"
RELEASE_BYTES = 49068339
RELEASE_URL = ("https://github.com/webrtc-sdk/android/releases/download/"
               "v150.7871.04/libwebrtc.aar")
SOURCE_SHA = "a545de45259b47dfac5f3635863e47cb601f1bb2"
PRODUCER_SHA = "717ec1dc5a94389d691e09cccaf3d7b3364fb4b7"
PRODUCER_RUN = 39894397638
PRODUCER_ARTIFACT = 12477894989
NATIVE_PATH = "jni/arm64-v8a/libjingle_peerconnection_so.so"
SOURCE_ROOT = ("https://raw.githubusercontent.com/webrtc-sdk/webrtc/"
               + SOURCE_SHA + "/")
PRODUCER_ROOT = ("https://raw.githubusercontent.com/webrtc-sdk/webrtc-build/"
                 + PRODUCER_SHA + "/build/")
SOURCES = (
    "modules/rtp_rtcp/source/rtp_format.cc",
    "modules/rtp_rtcp/source/rtp_format.h",
    "modules/rtp_rtcp/source/rtp_format_h264.cc",
    "modules/rtp_rtcp/source/rtp_packetizer_h265.cc",
    "modules/rtp_rtcp/source/forward_error_correction.cc",
    "pc/sctp_data_channel.cc",
    "pc/sdp_offer_answer.cc",
    "pc/peer_connection.cc",
    "pc/transceiver_list.cc",
)
PATCH_FILES = (
    "add_license_dav1d.patch",
    "android_webrtc_version.patch",
    "fix_mocks.patch",
)
PATCH_ONLY_PATHS = (
    "tools_webrtc/libs/generate_licenses.py",
    "sdk/android/BUILD.gn",
    "modules/audio_device/include/mock_audio_device.h",
)
MAX_SOURCE = 512 * 1024

class AuditError(ValueError):
    pass

def fetch_exact(url: str, *, opener=urllib.request.urlopen) -> bytes:
    allowed = {SOURCE_ROOT + path for path in SOURCES}
    allowed |= {PRODUCER_ROOT + path for path in ("VERSION", "run.py")}
    allowed |= {PRODUCER_ROOT + "patches/" + path for path in PATCH_FILES}
    if url not in allowed:
        raise AuditError("Source URL not on exact-commit allowlist")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com" or (
        parsed.port is not None or parsed.username or parsed.password or parsed.fragment
    ):
        raise AuditError("Untrusted source host")
    request = urllib.request.Request(url, headers={"User-Agent": "Kenato-M5-CVE-Audit/1"})
    with opener(request, timeout=30) as response:
        if response.status != 200:
            raise AuditError("Pinned source retrieval failed")
        content = response.read(MAX_SOURCE + 1)
    if not content or len(content) > MAX_SOURCE:
        raise AuditError("Pinned source missing or oversized")
    return content

def check_producer(version: str, run: str, patches: dict[str, str]) -> dict:
    expected = "WEBRTC_COMMIT=" + SOURCE_SHA
    if expected not in version.splitlines() or (
        "WEBRTC_BUILD_VERSION=150.7871.04" not in version.splitlines()
    ):
        raise AuditError("Source checkout does not match exact publisher release")
    # Exact plain android variant, not the prefixed / stripped ones.
    section = run.partition("'android': [")[2].partition("],")[0]
    patch_lines = re.findall(r"'([^']+\.patch)'", section)
    if patch_lines != list(PATCH_FILES):
        raise AuditError("Publisher Android patch list is not the reviewed three")
    if '"rtc_use_h264=false"' not in run:
        raise AuditError("Publisher GN arg snapshot changed")
    paths = []
    for filename, permitted in zip(PATCH_FILES, PATCH_ONLY_PATHS):
        content = patches[filename]
        affected = re.findall(r"^diff --git a/(\S+) b/(\S+)", content, flags=re.M)
        if affected != [(permitted, permitted)]:
            raise AuditError("Publisher patch touches unreviewed code: " + filename)
        paths.append(permitted)
    return {
        "checkout_commit": SOURCE_SHA,
        "executed_producer_run": PRODUCER_RUN,
        "producer_artifact_id": PRODUCER_ARTIFACT,
        "publisher_tag_repository_commit": PRODUCER_SHA,
        "reviewed_patch_list": list(PATCH_FILES),
        "reviewed_patch_destinations": paths,
        "h264_common_gn_flag_off": True,
        "source_to_byte_exact_producer_artifact_observed_independently": True,
        "producer_artifact_re_downloaded_by_this_workflow": False,
    }

def inspect_source(sources: dict[str, str]) -> dict:
    def content(p: str) -> str:
        if p not in SOURCES or not sources.get(p):
            raise AuditError("Missing exact pinned source: " + p)
        return sources[p]

    rtp = content("modules/rtp_rtcp/source/rtp_format.cc")
    header = content("modules/rtp_rtcp/source/rtp_format.h")
    h264 = content("modules/rtp_rtcp/source/rtp_format_h264.cc")
    h265 = content("modules/rtp_rtcp/source/rtp_packetizer_h265.cc")
    fec = content("modules/rtp_rtcp/source/forward_error_correction.cc")
    sctp = content("pc/sctp_data_channel.cc")
    sdp = content("pc/sdp_offer_answer.cc")
    peer = content("pc/peer_connection.cc")
    transceiver_list = content("pc/transceiver_list.cc")

    old_packetizer = bool(re.search(
        r"RtpPacketizer::SplitAboutEqually\s*\(\s*int\s+payload_len", rtp
    )) and "SplitAboutEqually(int payload_len" in header and "SafeGt(" not in rtp
    unbounded_video_rtp = (
        "Sanitize() const" not in header and
        "limits_(limits.Sanitize())" not in h264 and
        "limits_(limits.Sanitize())" not in h265 and
        "struct PayloadSizeLimits" in header
    )
    fixed_sctp = (
        "void SctpDataChannel::SendAsync" in sctp and
        "scoped_refptr<SctpDataChannel> me(this);" in sctp and
        "network_thread_->PostTask([me = std::move(me)" in sctp
    )
    begin = sdp.find("void SdpOfferAnswerHandler::RemoveStoppedTransceivers()")
    end = sdp.find("void SdpOfferAnswerHandler::RemoveUnusedChannels(", begin + 1)
    if begin < 0 or end <= begin:
        raise AuditError("Unexpected SDP transceiver method")
    teardown = sdp[begin:end]
    old_transceiver_teardown = (
        "transceiver->internal()->ClearChannel();" in teardown and
        "ScopedOperationsBatcher" not in teardown and
        "if (content.rejected) {" in sdp and
        "content.rejected || transceiver->internal()->stopped()" not in sdp
    )
    old_mid_lookup = (
        "channel_mid()" not in peer and
        "FindUnassociatedByMLineIndex" not in transceiver_list and
        "FindUnassociatedByMLineIndex" not in sdp and
        "FindByMLineIndex(" in transceiver_list
    )
    old_fec_bounds = (
        "if (new_bit_index == max_media_packets)" in fec and
        "internal::InsertZeroColumns(num_zeros_to_insert" in fec and
        "new_bit_index += num_zeros_to_insert;" in fec and
        "if (new_bit_index >= max_media_packets)" not in fec
    )
    predicates = {
        "CVE-2026-78891": old_packetizer,
        "CVE-2026-103631": unbounded_video_rtp,
        "CVE-2026-106268": old_transceiver_teardown,
        "CVE-2026-106357": old_mid_lookup,
        "CVE-2026-118328": old_fec_bounds,
    }
    if not all(predicates.values()) or not fixed_sctp:
        raise AuditError("Unexpected source fingerprint; manual re-review required")
    findings = {
        id: {"state": "UNPATCHED_EXACT_SOURCE_REJECT",
             "source_fingerprint_matches_published_pre_fix": True,
             "binary_exploitability_proven": False}
        for id in predicates
    }
    findings["CVE-2026-9962"] = {
        "state": "EXACT_SOURCE_FIX_PRESENT_NOT_BINARY_PROOF",
        "source_fingerprint_matches_ownership_fix": True,
        "binary_exploitability_proven": False,
    }
    findings["CVE-2026-110137"] = {
        "state": "CHROMIUM_BLINK_NOT_IN_STANDALONE_ANDROID_WEBRTC_COMPONENT",
        "upstream_scope": "Blink RTCEncoded*UnderlyingSource worker context teardown",
        "native_code_approval": False,
    }
    return findings

def inspect_release(path: Path) -> dict:
    audit = evidence.audit.audit_aar(path, expected_sha256=RELEASE_SHA,
        required_abis=frozenset(("arm64-v8a",)), max_classfile_major=69)
    if audit["file_bytes"] != RELEASE_BYTES:
        raise AuditError("Unexpected size for exact published release")
    with zipfile.ZipFile(path) as aar:
        info = aar.getinfo(NATIVE_PATH)
        if info.file_size < 1 or info.file_size > native.LIMIT:
            raise AuditError("ARM64 native ELF omitted/oversized")
        so = aar.read(info)
        with zipfile.ZipFile(aar.open("classes.jar")) as classes:
            blink_classes = [name for name in classes.namelist()
                             if name.startswith("org/chromium/blink/")
                             or name.startswith("third_party/blink/")]
    native_info = native.scan_elf(so, "arm64-v8a")
    loads = elf.require_16k_elf_loads(so)
    required_rtti = {
        "RtpPacketizerVp9": b"N6webrtc16RtpPacketizerVp9E",
        "RtpPacketizerH265": b"N6webrtc17RtpPacketizerH265E",
        "RtpPacketizerH264": b"N6webrtc17RtpPacketizerH264E",
        "ForwardErrorCorrection": b"N6webrtc22ForwardErrorCorrection6PacketE",
        "SctpDataChannel": b"N6webrtc15SctpDataChannelE",
        "RtpTransceiver": b"N6webrtc14RtpTransceiverE",
    }
    counts = {name: so.count(marker) for name, marker in required_rtti.items()}
    if not all(counts.values()) or blink_classes:
        raise AuditError("Unexpected exact ARM64 native/library composition")
    return {
        "aar_sha256": audit["sha256"], "aar_bytes": audit["file_bytes"],
        "aar_other_abis": audit["optional_abis_present"],
        "arm64_native_sha256": native_info["sha256"],
        "arm64_native_bytes": native_info["bytes"],
        "arm64_elf_load_alignment": loads,
        "gnu_relro": native_info["gnu_relro"],
        "bind_now": native_info["bind_now"],
        "executable_stack": native_info["gnu_stack_executable"],
        "compiled_type_rtti_MARKERS_NOT_exploitability": counts,
        "blink_java_class_count": len(blink_classes),
        "blink_native_renderer_not_part_of_android_build_targets": True,
        "native_debug_symbols_for_exact_function_reconstruction": False,
        "source_to_binary_function_by_function_equivalence_proven": False,
        "native_executed": False,
    }

def collect(*, downloader=evidence.download_snapshot,
            source_fetcher=fetch_exact) -> dict:
    with tempfile.TemporaryDirectory(prefix="kenato-m5-exact-m150-cve-") as tmp:
        target = Path(tmp) / "original-v150.7871.04.aar"
        digest, size = downloader(RELEASE_URL, target, max_bytes=64 * 1024 * 1024)
        if digest != RELEASE_SHA or size != RELEASE_BYTES:
            raise AuditError("Original full AAR release SHA or byte count changed")
        src_raw = {p: source_fetcher(SOURCE_ROOT + p) for p in SOURCES}
        source = {p: data.decode("utf-8") for p, data in src_raw.items()}
        patches = {p: source_fetcher(PRODUCER_ROOT + "patches/" + p).decode("utf-8")
                   for p in PATCH_FILES}
        producer = check_producer(
            source_fetcher(PRODUCER_ROOT + "VERSION").decode("utf-8"),
            source_fetcher(PRODUCER_ROOT + "run.py").decode("utf-8"),
            patches,
        )
        return {
            "status": "AUDIT_COMPLETE_CANDIDATE_REJECTED",
            "target": "webrtc-sdk/android original unprefixed full v150.7871.04",
            "source": SOURCE_SHA,
            "source_sha256_by_path": {
                path: hashlib.sha256(data).hexdigest() for path, data in src_raw.items()
            },
            "producer": producer,
            "native": inspect_release(target),
            "findings": inspect_source(source),
            "security_signoff": "REJECT",
            "vendor_approved": False,
            "actual_libwebrtc_cve_free_proven": False,
            "known_source_defects_block_acceptance": True,
            "android_arm64_real_exploit_attempted": False,
        }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = collect()
        code = 0
    except (AuditError, OSError, RuntimeError, ValueError,
            zipfile.BadZipFile, evidence.EvidenceError,
            evidence.audit.AarAuditError, native.NativeProbeError) as exc:
        result = {"status": "AUDIT_EVIDENCE_INCOMPLETE", "error_type": type(exc).__name__,
                  "error": str(exc)[:180], "vendor_approved": False}
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print("WebRTC SDK m150.04 exact-binary/security source audit:", result["status"])
    if code == 0:
        print("Security disposition: REJECT (five unpatched source findings; "
              "source fix for one; Chromium-only scope for one)")
        print("This workflow succeeding NEVER approves the library.")
    else:
        print("Evidence retrieval/inventory failed:", result["error_type"], result["error"])
    return code

if __name__ == "__main__":
    sys.exit(main())
