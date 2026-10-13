package com.sl.kenato.call

import java.security.MessageDigest

internal class RestorableVoiceSignalMismatchException(message: String) :
    IllegalStateException(message)

/**
 * Fail-closed, read-only intersection of two independently durable records:
 *  - a M3-authenticated and AES-GCM-encrypted semantic event,
 *  - a replay-journal admission record permitting this event to be considered.
 *
 * A suppressed OFFER remains decryptable in the semantic store for audit/retry but
 * must NEVER be returned as a candidate. The caller must still atomically claim
 * each matched event before a reducer, ringing, media or other observable effect.
 *
 * This is not wired to the M4 WSS receiver, reducer or call UI.
 */
internal class RestorableVoiceSignalMatcher(
    private val replay: VoiceSignalReplayJournal,
    private val semantic: DurableVoiceSemanticEventRepository,
) {
    /**
     * Return an authenticated semantic event ONLY after its one-time dispatch
     * claim has been durably written. A failure/duplicate returns no event.
     * The caller still MUST check current contact capability/consent and freshness
     * before ringing, touching the reducer or creating media tracks.
     */
    @Synchronized
    fun claimRestorableCandidate(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        nowEpochSeconds: Long,
    ): VoiceSignalPlaintext? {
        if (peerIdentityId.size != 32 || messageId.size != 16) {
            throw RestorableVoiceSignalMismatchException("Invalid requested voice dispatch key")
        }
        val verified = restorableCandidates(ownerIdentityId, nowEpochSeconds).singleOrNull {
            MessageDigest.isEqual(it.senderIdentityId, peerIdentityId) &&
                MessageDigest.isEqual(it.messageId, messageId)
        } ?: return null
        val permit = replay.pendingLiveDispatchPermits(ownerIdentityId, nowEpochSeconds).singleOrNull {
            MessageDigest.isEqual(it.peerIdentityId, peerIdentityId) &&
                MessageDigest.isEqual(it.messageId, messageId)
        } ?: return null
        return if (replay.claimLiveDispatchPermit(ownerIdentityId, permit, nowEpochSeconds)) {
            verified
        } else null
    }

    @Synchronized
    fun restorableCandidates(
        ownerIdentityId: ByteArray,
        nowEpochSeconds: Long,
    ): List<VoiceSignalPlaintext> {
        if (ownerIdentityId.size != 32 ||
            ownerIdentityId.all { it == 0.toByte() } ||
            nowEpochSeconds < 0
        ) {
            throw RestorableVoiceSignalMismatchException("Voice recovery snapshot context invalid")
        }

        // Both stores use one immutable receive-time snapshot. This avoids creating
        // an artificial mismatch when a 90-second expiry crosses between reads.
        val permits = replay.pendingLiveDispatchPermits(ownerIdentityId, nowEpochSeconds)
        val events = semantic.pendingLiveEventSnapshots(ownerIdentityId, nowEpochSeconds)

        // Reject a mismatched live replay receipt instead of silently skipping
        // authenticated signaling that should have a durably recoverable payload.
        return permits.map { permit ->
            val matches = events.filter {
                MessageDigest.isEqual(it.signal.senderIdentityId, permit.peerIdentityId) &&
                    MessageDigest.isEqual(it.signal.messageId, permit.messageId)
            }
            if (matches.size != 1) {
                throw RestorableVoiceSignalMismatchException(
                    "Admitted M5 replay event lacks exactly one durable semantic counterpart",
                )
            }
            val semanticRecord = matches.single()
            val event = semanticRecord.signal
            if (!MessageDigest.isEqual(event.recipientIdentityId, ownerIdentityId) ||
                !MessageDigest.isEqual(event.callId, permit.callId) ||
                !MessageDigest.isEqual(semanticRecord.envelopeDigest, permit.envelopeDigest) ||
                event.kind != permit.kind ||
                event.expiresAtEpochSeconds <= nowEpochSeconds
            ) {
                throw RestorableVoiceSignalMismatchException(
                    "Admitted M5 replay and semantic event disagree about authenticated call context",
                )
            }
            event
        }
    }
}
