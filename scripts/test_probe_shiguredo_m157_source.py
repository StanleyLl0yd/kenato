#!/usr/bin/env python3
"""Offline negative cases for Shiguredo m157 source/NOTICE research."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import probe_shiguredo_m157_source as probe


GOOD_VERSION = (
    "WEBRTC_BUILD_VERSION=157.8103.0.0\n"
    "WEBRTC_COMMIT=b321f634929af0af61a8964487fbd7894a008f12\n"
)
GOOD_LICENSE = "Apache License\nVersion 2.0"
GOOD_NOTICE = "## WebRTC\n## WebKit\nRedistribution and use in source and binary forms"
GOOD_SOURCE = """
std::vector<int> RtpPacketizer::SplitAboutEqually(
    size_t payload_size, const PayloadSizeLimits& limits) {
}
if (SafeGt(payload.size(), limits.max_payload_len * 0x7000)) {}
"""


GOOD_SCTP_SOURCE = """
void SctpDataChannel::SendAsync(DataBuffer buffer) {
  scoped_refptr<SctpDataChannel> me(this);
  network_thread_->PostTask([me = std::move(me), buffer = std::move(buffer)]() mutable {
    RTC_DCHECK_RUN_ON(me->network_thread_);
    RTCError err = me->SendImpl(std::move(buffer));
  });
}
"""

GOOD_TRANSCEIVER_SOURCE = """
void ApplyRemoteDescriptionUpdateTransceiverState() {
  if (transceiver->mid() && !transceiver->stopped()) { }
}
void UpdateTransceiverChannel() {
  if (content.rejected || transceiver->internal()->stopped()) { }
}
void SdpOfferAnswerHandler::RemoveStoppedTransceivers() {
  ScopedOperationsBatcher network_teardown_tasks(context_->network_thread());
  ScopedOperationsBatcher worker_tasks(context_->worker_thread());
  if (transceiver->internal()->HasChannel()) {
    network_teardown_tasks.Add(
      transceiver->internal()->GetClearChannelNetworkTask());
    worker_tasks.Add(
      transceiver->internal()->GetDeleteChannelWorkerTask(false));
  }
  transceivers()->Remove(transceiver);
  RTCError error = network_teardown_tasks.Run();
  error = worker_tasks.Run();
}
void SdpOfferAnswerHandler::RemoveUnusedChannels() {}
"""

class ProbeTests(unittest.TestCase):
    def test_valid_snapshot_is_research_only(self):
        report = probe.inspect_snapshots(GOOD_VERSION, GOOD_LICENSE, GOOD_NOTICE, GOOD_SOURCE, GOOD_SCTP_SOURCE, GOOD_TRANSCEIVER_SOURCE)
        self.assertFalse(report["vendor_approved_for_kenato"])
        self.assertFalse(report["cve_2026_78891_binary_remediation_verified"])
        self.assertFalse(report["license_inventory_complete_for_binary"])

    def test_invalid_declared_source_sha(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "VERSION mismatch"):
            probe.inspect_snapshots(
                GOOD_VERSION.replace(probe.WEBRTC_SHA, "0" * 40),
                GOOD_LICENSE, GOOD_NOTICE, GOOD_SOURCE, GOOD_SCTP_SOURCE, GOOD_TRANSCEIVER_SOURCE,
            )

    def test_duplicate_version_field_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "duplicate"):
            probe.validate_version(GOOD_VERSION + GOOD_VERSION)

    def test_missing_notice_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "NOTICE"):
            probe.validate_licenses(GOOD_LICENSE, "## WebRTC")

    def test_missing_size_t_fix_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "size_t"):
            probe.validate_vp9_source(
                GOOD_SOURCE.replace("size_t payload_size", "int payload_len")
            )

    def test_missing_frame_bound_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "guard absent"):
            probe.validate_vp9_source(GOOD_SOURCE.replace("0x7000", "0x8000"))

    def test_old_signature_even_with_new_one_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "old int"):
            probe.validate_vp9_source(
                GOOD_SOURCE + "RtpPacketizer::SplitAboutEqually(int payload_len)"
            )

    def test_sctp_fixed_ref_counted_task_passes(self):
        probe.validate_sctp_source(GOOD_SCTP_SOURCE)

    def test_sctp_old_raw_this_task_rejected(self):
        vulnerable = GOOD_SCTP_SOURCE.replace(
            "scoped_refptr<SctpDataChannel> me(this);", ""
        ).replace("me = std::move(me)", "this")
        with self.assertRaisesRegex(probe.SourceProbeError, "reference-counted"):
            probe.validate_sctp_source(vulnerable)

    def test_sctp_nonretaining_post_task_rejected(self):
        vulnerable = GOOD_SCTP_SOURCE.replace(
            "[me = std::move(me), buffer", "[this, buffer"
        )
        with self.assertRaisesRegex(probe.SourceProbeError, "does not retain"):
            probe.validate_sctp_source(vulnerable)

    def test_sctp_old_safety_flag_rejected_even_if_fixed_pattern_exists(self):
        vulnerable = GOOD_SCTP_SOURCE + (
            "\nnetwork_thread_->PostTask(SafeTask(network_safety_, [this]{}));\n"
        )
        with self.assertRaisesRegex(probe.SourceProbeError, "unsafe task"):
            probe.validate_sctp_source(vulnerable)

    def test_sctp_missing_method_rejected(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "SendAsync method absent"):
            probe.validate_sctp_source("")

    def test_sctp_exact_gitiles_path_allowlisted(self):
        from unittest.mock import patch
        outcome = probe.subprocess.CompletedProcess(
            args=["curl"], returncode=0,
            stdout=b"ZGF0YQ==\n@@KENATO_STATUS:200", stderr=b"",
        )
        with patch.object(probe.subprocess, "run", return_value=outcome):
            self.assertEqual(
                probe.fetch_exact(
                    probe.GITILES_ROOT + probe.UPSTREAM_SCTP_PATH + "?format=TEXT",
                    maximum=128, host="webrtc.googlesource.com",
                ), b"ZGF0YQ=="
            )

    def test_transceiver_fixed_guards_pass(self):
        probe.validate_transceiver_source(GOOD_TRANSCEIVER_SOURCE)

    def test_transceiver_transport_guard_absent_fails(self):
        bad = GOOD_TRANSCEIVER_SOURCE.replace(
            "transceiver->mid() && !transceiver->stopped()", "transceiver->mid()"
        )
        with self.assertRaisesRegex(probe.SourceProbeError, "transport guard"):
            probe.validate_transceiver_source(bad)

    def test_transceiver_channel_guard_absent_fails(self):
        bad = GOOD_TRANSCEIVER_SOURCE.replace(
            "content.rejected || transceiver->internal()->stopped()", "content.rejected"
        )
        with self.assertRaisesRegex(probe.SourceProbeError, "channel guard"):
            probe.validate_transceiver_source(bad)

    def test_transceiver_remove_before_teardown_fails(self):
        bad = GOOD_TRANSCEIVER_SOURCE.replace(
            "  transceivers()->Remove(transceiver);\n  RTCError error = network_teardown_tasks.Run();",
            "  RTCError error = network_teardown_tasks.Run();\n  transceivers()->Remove(transceiver);"
        )
        with self.assertRaisesRegex(probe.SourceProbeError, "ordered removal"):
            probe.validate_transceiver_source(bad)

    def test_transceiver_no_worker_teardown_fails(self):
        bad = GOOD_TRANSCEIVER_SOURCE.replace("GetDeleteChannelWorkerTask(", "MissingWorkerTask(")
        with self.assertRaisesRegex(probe.SourceProbeError, "ordered removal"):
            probe.validate_transceiver_source(bad)

    def test_transceiver_missing_method_fails(self):
        with self.assertRaisesRegex(probe.SourceProbeError, "method missing"):
            probe.validate_transceiver_source("")

    def test_transceiver_pinned_gitiles_path_allowlisted(self):
        from unittest.mock import patch
        outcome = probe.subprocess.CompletedProcess(
            args=["curl"], returncode=0,
            stdout=b"ZGF0YQ==\n@@KENATO_STATUS:200", stderr=b"",
        )
        with patch.object(probe.subprocess, "run", return_value=outcome):
            result = probe.fetch_exact(
                probe.GITILES_ROOT + probe.UPSTREAM_TRANSCEIVER_PATH + "?format=TEXT",
                maximum=128, host="webrtc.googlesource.com",
            )
            self.assertEqual(result, b"ZGF0YQ==")

    def test_http_redirect_is_rejected(self):
        outcome = probe.subprocess.CompletedProcess(
            args=["curl"], returncode=0,
            stdout=b"redirect\n@@KENATO_STATUS:302", stderr=b"",
        )
        with patch.object(probe.subprocess, "run", return_value=outcome):
            with self.assertRaisesRegex(probe.SourceProbeError, "HTTP 200"):
                probe.fetch_exact(probe.PUBLISHER_ROOT + "VERSION", maximum=10, host="raw.githubusercontent.com")

    def test_oversized_content_is_rejected(self):
        outcome = probe.subprocess.CompletedProcess(
            args=["curl"], returncode=0,
            stdout=b"x" * 11 + b"\n@@KENATO_STATUS:200", stderr=b"",
        )
        with patch.object(probe.subprocess, "run", return_value=outcome):
            with self.assertRaisesRegex(probe.SourceProbeError, "oversized"):
                probe.fetch_exact(probe.PUBLISHER_ROOT + "VERSION", maximum=10, host="raw.githubusercontent.com")

    def test_non_allowlisted_url_rejected_without_request(self):
        with patch.object(probe.subprocess, "run") as call:
            with self.assertRaisesRegex(probe.SourceProbeError, "allowlist"):
                probe.fetch_exact("https://raw.githubusercontent.com/attacker/other", maximum=10, host="raw.githubusercontent.com")
            call.assert_not_called()

    def test_transport_failure_rejected(self):
        outcome = probe.subprocess.CompletedProcess(
            args=["curl"], returncode=22, stdout=b"", stderr=b"hidden",
        )
        with patch.object(probe.subprocess, "run", return_value=outcome):
            with self.assertRaisesRegex(probe.SourceProbeError, "transport"):
                probe.fetch_exact(probe.PUBLISHER_ROOT + "VERSION", maximum=10, host="raw.githubusercontent.com")

    def test_https_only_curl_invariant(self):
        outcome = probe.subprocess.CompletedProcess(
            args=["curl"], returncode=0,
            stdout=b"v\n@@KENATO_STATUS:200", stderr=b"",
        )
        with patch.object(probe.subprocess, "run", return_value=outcome) as call:
            self.assertEqual(
                probe.fetch_exact(probe.PUBLISHER_ROOT + "VERSION", maximum=10, host="raw.githubusercontent.com"),
                b"v",
            )
            args = call.call_args.args[0]
            self.assertIn("=https", args)
            self.assertNotIn("--location", args)
            self.assertIn("--max-filesize", args)


if __name__ == "__main__":
    unittest.main()
