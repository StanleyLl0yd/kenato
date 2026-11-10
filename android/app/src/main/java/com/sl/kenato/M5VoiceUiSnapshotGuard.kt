package com.sl.kenato

/**
 * Compose/controller thread boundary for short-lived signed QR records.
 * An async snapshot prepared in an earlier Activity foreground epoch must
 * never reintroduce challenge/proof text after pause, even if a new Activity
 * foreground was entered before the stale callback reaches the main thread.
 */
internal object M5VoiceUiSnapshotGuard {
    /**
     * A picked QR image belongs to the same pinned peer AND the same local approval
     * generation. Resetting consent must fence a picker callback or decode that
     * was already in flight, even if the selected contact did not change.
     */
    fun mayApplyImportedVoiceQr(
        requestPeerId: String?,
        selectedPeerId: String?,
        requestResetEpoch: Long,
        currentResetEpoch: Long,
    ): Boolean = requestPeerId != null && requestPeerId == selectedPeerId &&
        requestResetEpoch == currentResetEpoch

    /** Failure of optional voice consent storage never blocks M4 text UI. */
    fun confirmedOrUnavailable(check: () -> Boolean): Boolean =
        try {
            check()
        } catch (_: Exception) {
            false
        }

    fun redactStaleProofs(
        current: M45AcceptanceUiState,
        incoming: M45AcceptanceUiState,
        foreground: Boolean,
    ): M45AcceptanceUiState {
        // An old Activity epoch cannot overwrite current contact/message/UI state.
        // Preserve only the completed worker's busy release; QR data remains redacted.
        if (current.voiceUiEpoch != incoming.voiceUiEpoch ||
            incoming.voiceConsentResetEpoch < current.voiceConsentResetEpoch
        ) {
            return current.copy(
                busy = incoming.busy,
                voiceChallengeQr = null,
                voiceProofQr = null,
            )
        }
        val mayExpose = foreground &&
            current.selectedPeerIdentityId == incoming.selectedPeerIdentityId
        return incoming.copy(
            voiceUiEpoch = current.voiceUiEpoch,
            voiceChallengeQr = incoming.voiceChallengeQr.takeIf { mayExpose },
            voiceProofQr = incoming.voiceProofQr.takeIf { mayExpose },
        )
    }
}
