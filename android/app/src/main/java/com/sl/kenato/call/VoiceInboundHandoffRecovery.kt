package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingProtocol
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec

internal class VoiceInboundHandoffRecoveryException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

/**
 * Reconciliation result, NOT a command to send an ACK. A caller may remove the committed M3
 * handoff only after this operation succeeds. An expired event must never produce an ACK.
 */
internal enum class VoiceInboundHandoffRecoveryOutcome {
    DURABLY_IMPORTED,
    EXPIRED_WITHOUT_ACK,
}

/**
 * Crash-safe M5 receive-side staging primitive. It never calls a reducer, sends to WSS, or
 * touches M4 chat history. Caller must supply a handoff from the already-committed M3
 * atomic decrypt+ratchet transition, never an arbitrary unverified plaintext.
 *
 * On recovery after 90s expiry, authenticate inner/outer exact binding at the last possible
 * valid instant, then allow the M3 handoff to be retired without emitting effects or ACKs.
 * This prevents permanently stranding scarce M3 handoff slots when the app restarts late.
 * No live transport is wired to this primitive yet.
 */
internal class VoiceInboundHandoffRecovery(
    private val journal: VoiceSignalReplayJournal,
) {
    @Synchronized
    fun reconcileCommittedHandoff(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
        nowEpochSeconds: Long,
    ): VoiceInboundHandoffRecoveryOutcome {
        if (nowEpochSeconds < 0L ||
            ownerIdentityId.size != 32 ||
            ownerIdentityId.all { it == 0.toByte() } ||
            handoff.direction != SessionStateCodec.HANDOFF_DIRECTION_INBOUND ||
            handoff.localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES
        ) {
            throw VoiceInboundHandoffRecoveryException("Voice M3 handoff recovery context is invalid")
        }

        val envelope = try {
            MessagingWire.decodeEnvelope(handoff.encodedEnvelope).also {
                if (!MessagingWire.encodeEnvelope(it).contentEquals(handoff.encodedEnvelope)) {
                    throw VoiceInboundHandoffRecoveryException("Noncanonical recovered voice envelope")
                }
            }
        } catch (error: Exception) {
            throw VoiceInboundHandoffRecoveryException("Invalid recovered voice envelope", error)
        }
        if (!envelope.senderIdentityId.contentEquals(handoff.peerIdentityId) ||
            !envelope.recipientIdentityId.contentEquals(ownerIdentityId) ||
            !envelope.messageId.contentEquals(handoff.messageId)
        ) {
            throw VoiceInboundHandoffRecoveryException("Recovered voice handoff is not owner/peer/id bound")
        }
        val expired = envelope.expiresAtEpochSeconds <= nowEpochSeconds
        val validationTime = if (expired) envelope.expiresAtEpochSeconds - 1 else nowEpochSeconds
        if (validationTime < 0L) {
            throw VoiceInboundHandoffRecoveryException("Recovered voice expiry cannot be validated")
        }
        try {
            MessagingProtocol.validateEnvelope(envelope, validationTime)
            VoiceSignalingWire.decode(
                handoff.encodedPlaintext,
                VoiceSignalEnvelopeBinding(
                    envelope.senderIdentityId,
                    envelope.recipientIdentityId,
                    envelope.messageId,
                    envelope.expiresAtEpochSeconds,
                ),
                validationTime,
            )
        } catch (error: Exception) {
            throw VoiceInboundHandoffRecoveryException("Invalid authenticated M5 handoff context", error)
        }
        if (expired) {
            // No ACK and no call effect. Native M3 ratchet already advanced atomically with this
            // handoff. Completing that handoff after this validation cannot replay its ciphertext.
            return VoiceInboundHandoffRecoveryOutcome.EXPIRED_WITHOUT_ACK
        }
        try {
            journal.importAuthenticatedInboundHandoff(ownerIdentityId, handoff, nowEpochSeconds)
        } catch (error: Exception) {
            // Crash recovery retains the M3 handoff; no ACK is authorized by this call.
            throw VoiceInboundHandoffRecoveryException("Unable to durably import recovered voice event", error)
        }
        return VoiceInboundHandoffRecoveryOutcome.DURABLY_IMPORTED
    }

    fun pendingLiveAcknowledgements(
        ownerIdentityId: ByteArray,
        nowEpochSeconds: Long,
    ): List<VoiceSignalReplayAck> = journal.pendingLiveAcknowledgements(ownerIdentityId, nowEpochSeconds)
}
