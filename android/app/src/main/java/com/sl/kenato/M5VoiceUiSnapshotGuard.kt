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
        operationInProgress: Boolean = false,
    ): Boolean = !operationInProgress && requestPeerId != null && requestPeerId == selectedPeerId &&
        requestResetEpoch == currentResetEpoch

    /** Failure of optional voice consent storage never blocks M4 text UI. */
    fun confirmedOrUnavailable(check: () -> Boolean): Boolean =
        try {
            check()
        } catch (_: Exception) {
            false
        }

    /** A foreground refresh is not an operation completion. It must not
     * release another action's busy flag, even inside the same UI epoch. */
    fun mayApplyForegroundRefresh(
        current: M45AcceptanceUiState,
        requestEpoch: Long,
    ): Boolean = !current.busy && current.voiceUiEpoch == requestEpoch

    /** The exact operation ticket may release busy after Activity recreation
     * without applying any stale QR, contact, notice or error snapshot. */
    fun settleStaleOperation(
        current: M45AcceptanceUiState,
        operationEpoch: Long,
        completedTicket: Long,
        activeTicket: Long?,
    ): M45AcceptanceUiState {
        if (completedTicket != activeTicket || current.voiceUiEpoch == operationEpoch) {
            return current
        }
        return current.copy(
            busy = false,
            notice = null,
            error = null,
            voiceChallengeQr = null,
            voiceProofQr = null,
        )
    }

    fun redactStaleProofs(
        current: M45AcceptanceUiState,
        incoming: M45AcceptanceUiState,
        foreground: Boolean,
    ): M45AcceptanceUiState {
        // A stale Activity callback cannot finish a newer UI operation or
        // overwrite its contact/message snapshot. The fresh-epoch foreground
        // refresh or matching operation callback must release its own busy state.
        if (current.voiceUiEpoch != incoming.voiceUiEpoch ||
            incoming.voiceConsentResetEpoch < current.voiceConsentResetEpoch
        ) {
            return current.copy(
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
