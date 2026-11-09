package com.sl.kenato

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class M5VoiceUiSnapshotGuardTest {
    @Test
    fun unavailableOrCorruptedVoiceConsentCannotBlockTextScreen() {
        assertEquals(true, M5VoiceUiSnapshotGuard.confirmedOrUnavailable { true })
        assertEquals(false, M5VoiceUiSnapshotGuard.confirmedOrUnavailable { false })
        assertEquals(false, M5VoiceUiSnapshotGuard.confirmedOrUnavailable {
            throw IllegalStateException("Android Keystore key unavailable")
        })
    }

    @Test
    fun currentEpochCanShowOnlySelectedPeerProofInForeground() {
        val before = M45AcceptanceUiState(selectedPeerIdentityId = "contact-a", voiceUiEpoch = 7)
        val snapshot = before.copy(voiceChallengeQr = "challenge", voiceProofQr = "proof")
        val next = M5VoiceUiSnapshotGuard.redactStaleProofs(before, snapshot, true)
        assertEquals("challenge", next.voiceChallengeQr)
        assertEquals("proof", next.voiceProofQr)
        assertEquals(7L, next.voiceUiEpoch)
    }

    @Test
    fun appBackgroundRedactsEvenIdenticalEpoch() {
        val before = M45AcceptanceUiState(selectedPeerIdentityId = "contact-a", voiceUiEpoch = 2)
        val snapshot = before.copy(voiceChallengeQr = "challenge", voiceProofQr = "proof")
        val next = M5VoiceUiSnapshotGuard.redactStaleProofs(before, snapshot, false)
        assertNull(next.voiceChallengeQr)
        assertNull(next.voiceProofQr)
        assertEquals(2L, next.voiceUiEpoch)
    }

    @Test
    fun lateCallbackFromBeforeBackgroundCannotRestoreQrAfterResume() {
        val before = M45AcceptanceUiState(selectedPeerIdentityId = "contact-a", voiceUiEpoch = 10)
        val paused = before.copy(voiceUiEpoch = 11)
        val stale = before.copy(voiceChallengeQr = "challenge", voiceProofQr = "proof")
        val next = M5VoiceUiSnapshotGuard.redactStaleProofs(paused, stale, true)
        assertNull(next.voiceChallengeQr)
        assertNull(next.voiceProofQr)
        assertEquals(11L, next.voiceUiEpoch)
    }

    @Test
    fun backgroundEpochRejectsEntireOutdatedSnapshotNotOnlyQr() {
        val current = M45AcceptanceUiState(
            selectedPeerIdentityId = "contact-new",
            voiceUiEpoch = 12,
            messages = emptyList(),
            voiceCapabilityConfirmed = false,
            busy = true,
            notice = "Current operation",
        )
        val old = current.copy(
            selectedPeerIdentityId = "contact-old",
            voiceUiEpoch = 11,
            voiceChallengeQr = "old-challenge",
            voiceProofQr = "old-proof",
            voiceCapabilityConfirmed = true,
            busy = false,
            notice = "Obsolete result",
        )
        val updated = M5VoiceUiSnapshotGuard.redactStaleProofs(current, old, true)
        assertEquals("contact-new", updated.selectedPeerIdentityId)
        assertEquals(false, updated.voiceCapabilityConfirmed)
        assertEquals(12L, updated.voiceUiEpoch)
        assertEquals("Current operation", updated.notice)
        // The stale completion must not release a newer operation's UI lock.
        assertEquals(true, updated.busy)
        assertNull(updated.voiceChallengeQr)
        assertNull(updated.voiceProofQr)

        val fresh = updated.copy(busy = false, voiceUiEpoch = 12)
        val settled = M5VoiceUiSnapshotGuard.redactStaleProofs(updated, fresh, true)
        assertEquals(false, settled.busy)
    }

    @Test
    fun completedOldWorkerCannotLaunderQrThroughNewForegroundSnapshot() {
        val launchedEpoch = 20L
        val newForeground = M45AcceptanceUiState(
            voiceUiEpoch = launchedEpoch + 1,
            selectedPeerIdentityId = "peer-new",
            busy = true,
            voiceCapabilityConfirmed = false,
        )
        // Build work may finish after a foreground transition. The controller
        // stamps the response with the epoch captured BEFORE dispatch.
        val finishedWorker = newForeground.copy(
            voiceUiEpoch = launchedEpoch,
            selectedPeerIdentityId = "peer-old",
            voiceProofQr = "old-user-approved-signature",
            voiceCapabilityConfirmed = true,
            busy = false,
        )
        val unchanged = M5VoiceUiSnapshotGuard.redactStaleProofs(
            newForeground, finishedWorker, true,
        )
        assertEquals(21L, unchanged.voiceUiEpoch)
        assertEquals("peer-new", unchanged.selectedPeerIdentityId)
        assertEquals(false, unchanged.voiceCapabilityConfirmed)
        assertEquals(true, unchanged.busy)
        assertNull(unchanged.voiceProofQr)
    }

    @Test
    fun foregroundRefreshDoesNotReleaseActiveOperationEvenInMatchingEpoch() {
        val action = M45AcceptanceUiState(voiceUiEpoch = 8, busy = true)
        assertEquals(false, M5VoiceUiSnapshotGuard.mayApplyForegroundRefresh(action, 8))
        assertEquals(false, M5VoiceUiSnapshotGuard.mayApplyForegroundRefresh(
            action.copy(busy = false), 7,
        ))
        assertEquals(true, M5VoiceUiSnapshotGuard.mayApplyForegroundRefresh(
            action.copy(busy = false), 8,
        ))
    }

    @Test
    fun actualStaleCompletionReleasesOnlyItsOwnTicketWithoutShowingOldProof() {
        val resumed = M45AcceptanceUiState(
            voiceUiEpoch = 31,
            busy = true,
            voiceProofQr = "should-not-survive",
            notice = "obsolete",
            error = "old error",
        )
        val staleOtherAction = M5VoiceUiSnapshotGuard.settleStaleOperation(
            resumed, operationEpoch = 30, completedTicket = 12, activeTicket = 13,
        )
        assertEquals(true, staleOtherAction.busy)
        assertEquals("obsolete", staleOtherAction.notice)

        val matchingCompletion = M5VoiceUiSnapshotGuard.settleStaleOperation(
            resumed, operationEpoch = 30, completedTicket = 13, activeTicket = 13,
        )
        assertEquals(false, matchingCompletion.busy)
        assertNull(matchingCompletion.voiceProofQr)
        assertNull(matchingCompletion.notice)
        assertNull(matchingCompletion.error)
        assertEquals(31L, matchingCompletion.voiceUiEpoch)
    }

    @Test
    fun matchingEpochCompletionCannotPrematurelyReleaseBusyWithoutSnapshot() {
        val active = M45AcceptanceUiState(voiceUiEpoch = 40, busy = true)
        val unchanged = M5VoiceUiSnapshotGuard.settleStaleOperation(
            active, operationEpoch = 40, completedTicket = 14, activeTicket = 14,
        )
        assertEquals(true, unchanged.busy)
    }

    @Test
    fun sameEpochLegitimateContactSelectionStillApplies() {
        val old = M45AcceptanceUiState(selectedPeerIdentityId = "old", voiceUiEpoch = 3)
        val selected = old.copy(selectedPeerIdentityId = "new", voiceCapabilityConfirmed = true)
        val updated = M5VoiceUiSnapshotGuard.redactStaleProofs(old, selected, true)
        assertEquals("new", updated.selectedPeerIdentityId)
        assertEquals(true, updated.voiceCapabilityConfirmed)
    }

    @Test
    fun changedSelectedContactNeverReceivesPreviousContactQr() {
        val current = M45AcceptanceUiState(selectedPeerIdentityId = "contact-b", voiceUiEpoch = 6)
        val outdated = current.copy(
            selectedPeerIdentityId = "contact-a",
            voiceChallengeQr = "contact-a-challenge",
            voiceProofQr = "contact-a-proof",
        )
        val next = M5VoiceUiSnapshotGuard.redactStaleProofs(current, outdated, true)
        assertNull(next.voiceChallengeQr)
        assertNull(next.voiceProofQr)
        assertEquals(6L, next.voiceUiEpoch)
    }
}
