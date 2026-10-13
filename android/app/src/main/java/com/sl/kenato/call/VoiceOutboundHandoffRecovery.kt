package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingProtocol
import com.sl.kenato.messaging.MessagingRecoveredSend
import com.sl.kenato.messaging.MessagingSendAccepted
import com.sl.kenato.messaging.MessagingSessionHandoffRepository
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.security.MessageDigest

internal class VoiceOutboundRecoveryException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

/**
 * Optional typed outbound M5 recovery/terminalization over the same M3 handoff repository
 * used by the sender. No second ratchet encryption and no chat-history import.
 *
 * The authenticated WSS transport must serialize expiration against its in-flight socket:
 * never expire an envelope while it can still be accepted on that connection. A repeated
 * SendAccepted is not treated as permission to regenerate expired work.
 */
internal class VoiceOutboundHandoffRecovery(
    private val handoffs: MessagingSessionHandoffRepository,
) {
    @Synchronized
    fun recover(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
        nowEpochSeconds: Long,
    ): MessagingRecoveredSend {
        validate(ownerIdentityId, handoff, nowEpochSeconds)
        return MessagingRecoveredSend(
            peerIdentityId = handoff.peerIdentityId.copyOf(),
            messageId = handoff.messageId.copyOf(),
            encodedEnvelope = handoff.encodedEnvelope.copyOf(),
        )
    }

    @Synchronized
    fun expireIfDue(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        nowEpochSeconds: Long,
    ): Boolean {
        val handoff = requirePending(ownerIdentityId, peerIdentityId, messageId)
        val envelope = validate(ownerIdentityId, handoff, nowEpochSeconds)
        if (envelope.expiresAtEpochSeconds > nowEpochSeconds) return false
        completeRequired(ownerIdentityId, handoff)
        return true
    }

    @Synchronized
    fun recordAccepted(
        ownerIdentityId: ByteArray,
        accepted: MessagingSendAccepted,
        nowEpochSeconds: Long,
    ) {
        val handoff = requirePending(
            ownerIdentityId, accepted.recipientIdentityId, accepted.messageId,
        )
        validate(ownerIdentityId, handoff, nowEpochSeconds)
        // The authenticated server accepted the exact staged message key. Removing
        // the M3 handoff is one AtomicFile commit, with no separate text-history state.
        completeRequired(ownerIdentityId, handoff)
    }

    private fun requirePending(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
    ): SessionMessageHandoff = handoffs.pendingMessageHandoffs(ownerIdentityId)
        .singleOrNull {
            it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                MessageDigest.isEqual(it.peerIdentityId, peerIdentityId) &&
                MessageDigest.isEqual(it.messageId, messageId)
        } ?: throw VoiceOutboundRecoveryException("M5 outbound handoff is missing or ambiguous")

    private fun validate(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
        nowEpochSeconds: Long,
    ): MessagingEnvelope {
        if (ownerIdentityId.size != 32 || ownerIdentityId.all { it == 0.toByte() } ||
            nowEpochSeconds <= 0 ||
            handoff.direction != SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND
        ) {
            throw VoiceOutboundRecoveryException("Invalid M5 outbound recovery context")
        }
        val envelope = try {
            MessagingWire.decodeEnvelope(handoff.encodedEnvelope)
        } catch (error: Exception) {
            throw VoiceOutboundRecoveryException("Invalid M5 outbound envelope", error)
        }
        if (!MessagingWire.encodeEnvelope(envelope).contentEquals(handoff.encodedEnvelope) ||
            !MessageDigest.isEqual(envelope.senderIdentityId, ownerIdentityId) ||
            !MessageDigest.isEqual(envelope.recipientIdentityId, handoff.peerIdentityId) ||
            !MessageDigest.isEqual(envelope.messageId, handoff.messageId)
        ) {
            throw VoiceOutboundRecoveryException("M5 outbound handoff/envelope binding is invalid")
        }
        try {
            // When already expired, authenticate the original canonical record at the
            // last instant it could have been valid. Expiry itself is decided only by
            // the caller's actual clock, never by this historical validation snapshot.
            val validationTime = minOf(nowEpochSeconds, envelope.expiresAtEpochSeconds - 1L)
            MessagingProtocol.validateEnvelope(envelope, validationTime)
            VoiceSignalingWire.decode(
                handoff.encodedPlaintext,
                VoiceSignalEnvelopeBinding(
                    envelope.senderIdentityId, envelope.recipientIdentityId,
                    envelope.messageId, envelope.expiresAtEpochSeconds,
                ),
                validationTime,
            )
            val session = SessionCiphertextWire.decode(envelope.ciphertext)
            if (!SessionCiphertextWire.encode(session).contentEquals(envelope.ciphertext) ||
                !MessageDigest.isEqual(session.senderIdentityId, ownerIdentityId) ||
                !MessageDigest.isEqual(session.recipientIdentityId, handoff.peerIdentityId)
            ) {
                throw VoiceOutboundRecoveryException("M5 outbound session ciphertext is not canonical")
            }
        } catch (error: Exception) {
            throw VoiceOutboundRecoveryException("M5 outbound ciphertext/semantic binding is invalid", error)
        }
        return envelope
    }

    private fun completeRequired(ownerIdentityId: ByteArray, handoff: SessionMessageHandoff) {
        if (!handoffs.completeMessageHandoff(
                ownerIdentityId, handoff.peerIdentityId, handoff.messageId,
                SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
            )
        ) {
            throw VoiceOutboundRecoveryException("M5 outbound completion did not durably remove handoff")
        }
    }
}
