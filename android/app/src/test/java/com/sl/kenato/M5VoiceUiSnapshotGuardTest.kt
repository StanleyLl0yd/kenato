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
