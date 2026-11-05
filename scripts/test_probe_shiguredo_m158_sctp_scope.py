#!/usr/bin/env python3
"""Offline bounds and non-approval tests for m158 SCTP source scope."""
import unittest
import probe_shiguredo_m158_sctp_scope as scope


class SctpScopeTests(unittest.TestCase):
    def test_bounded_context_limits_and_no_guessing(self):
        text = "before\nSctpDataChannel::~SctpDataChannel() { safe(); }\nafter"
        self.assertEqual(
            scope.bounded_context(text, "SctpDataChannel::~SctpDataChannel()",
                                  limit=9),
            "SctpDataC")
        self.assertEqual(scope.bounded_context(text, "nonexistent"), "")
        with self.assertRaises(scope.m158.M158EvidenceError):
            scope.bounded_context(text, "after", limit=10000)
        with self.assertRaises(scope.m158.M158EvidenceError):
            scope.bounded_context(text + text, "SctpDataChannel::~SctpDataChannel()",
                                  unique=True)

    def test_new_lifetime_markers_are_not_native_security_clearance(self):
        sending = """void SctpDataChannel::SendAsync() {
            network_thread_->PostTask([this, network_safety = network_safety_,
                buffer = std::move(buffer)]() mutable {
                if (network_safety->alive()) {
                    SendImpl(std::move(buffer));
                }
            });
        }"""
        closing = """void SctpDataChannel::SetState() {
            if (state_ == kClosed) {
                network_safety_->SetNotAlive();
            }
            controller_->OnChannelStateChanged(this, state_);
        }"""
        marker = scope.inspect_postfix_lifetime_markers(sending, closing)
        self.assertFalse(marker["concurrent_object_lifetime_proven"])
        self.assertFalse(marker["CVE_2026_9962_native_binary_approved"])
        self.assertFalse(marker["checks"]["refcounted_receiver_capture_present"])
        for bad_send, bad_state in (
            (sending.replace("network_safety->alive()", "true"), closing),
            (sending.replace("PostTask([this", "PostTask([other"), closing),
            (sending, closing.replace("network_safety_->SetNotAlive()", "")),
            (sending, closing.replace("controller_->OnChannelStateChanged", "other")),
        ):
            with self.assertRaises(scope.m158.M158EvidenceError):
                scope.inspect_postfix_lifetime_markers(bad_send, bad_state)

    def test_controller_transfer_requires_owner_held_until_close(self):
        controller = (
            "closed_channel = OnSctpDataChannelClosed(channel);\n"
            "signaling_thread()->PostTask(SafeTask(\n"
            "closed_channel = std::move(closed_channel)\n"
            "scoped_refptr<SctpDataChannel> DataChannelController::OnSctpDataChannelClosed(\n"
            "scoped_refptr<SctpDataChannel> closed_channel = std::move(*it)"
        )
        header = "std::vector<scoped_refptr<SctpDataChannel>> sctp_data_channels_n_;"
        report = scope.inspect_controller_owner_transfer(controller, header)
        self.assertFalse(report["destructor_happens_before_independently_proven"])
        self.assertFalse(report["CVE_2026_9962_cleared"])
        for fragment in ("closed_channel = OnSctpDataChannelClosed(channel)",
                         "closed_channel = std::move(closed_channel)",
                         "scoped_refptr<SctpDataChannel> closed_channel = std::move(*it)"):
            with self.assertRaises(scope.m158.M158EvidenceError):
                scope.inspect_controller_owner_transfer(
                    controller.replace(fragment, "removed"), header
                )
        with self.assertRaises(scope.m158.M158EvidenceError):
            scope.inspect_controller_owner_transfer(controller, "raw pointer only")

    def test_no_executable_source_or_unreviewed_fallback(self):
        self.assertEqual(scope.TARGET, "pc/sctp_data_channel.cc")
        self.assertIn(scope.m158.SOURCE_SHA, scope.URL)
        self.assertNotIn("main", scope.URL)
        self.assertFalse(scope.m158.RELEASE_AAR_SHA256 ==
                         scope.m158.base.vendor.PATCH_EXPECTED_SHA256)


if __name__ == "__main__":
    unittest.main()
