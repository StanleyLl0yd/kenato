package com.sl.kenato.messaging

import com.sl.kenato.session.LocalSessionRepository
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec

internal data class MessagingRecoveredSend(
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
    val encodedEnvelope: ByteArray,
)

internal data class MessagingRecoveredAck(
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
)

internal data class MessagingRecoveryPlan(
    val outboundSends: List<MessagingRecoveredSend>,
    val inboundAcks: List<MessagingRecoveredAck>,
)

internal class MessagingRecoveryException(message: String) : IllegalStateException(message)

internal interface MessagingSessionHandoffRepository {
    fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff>

    fun completeMessageHandoff(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        direction: Int,
    ): Boolean
}

internal class LocalMessagingSessionHandoffRepository(
    private val repository: LocalSessionRepository,
) : MessagingSessionHandoffRepository {
    override fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff> =
        repository.pendingMessageHandoffs(ownerIdentityId)

    override fun completeMessageHandoff(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        direction: Int,
    ): Boolean = repository.completeMessageHandoff(
        ownerIdentityId,
        peerIdentityId,
        messageId,
        direction,
    )
}

/**
 * Reconciles the M4 crypto-coupled handoff journal with durable conversation history after
 * process restart or reconnect. It does not own sockets, timers, retry policy, or encryption.
 * Returned outbound envelopes are the exact bytes staged with the ratchet advance.
 */
internal class MessagingRecoveryCoordinator(
    private val sessions: MessagingSessionHandoffRepository,
    private val history: ConversationHistoryRepository,
) {
    @Synchronized
    fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan {
        requireIdentity(ownerIdentityId)
        val handoffs = sessions.pendingMessageHandoffs(ownerIdentityId)
        val recoveredSends = ArrayList<MessagingRecoveredSend>()
        val pendingSendKeys = HashSet<MessageKey>()

        handoffs.forEach { handoff ->
            when (handoff.direction) {
                SessionStateCodec.HANDOFF_DIRECTION_INBOUND -> recoverInbound(ownerIdentityId, handoff)
                SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND -> {
                    val record = history.importOutboundPendingAcceptance(ownerIdentityId, handoff)
                    when (record.deliveryState) {
                        ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE -> {
                            val key = MessageKey(record.peerIdentityId, record.messageId)
                            if (!pendingSendKeys.add(key)) {
                                throw MessagingRecoveryException("Duplicate outbound recovery handoff")
                            }
                            recoveredSends += MessagingRecoveredSend(
                                peerIdentityId = handoff.peerIdentityId.copyOf(),
                                messageId = handoff.messageId.copyOf(),
                                encodedEnvelope = handoff.encodedEnvelope.copyOf(),
                            )
                        }
                        ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
                        ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED,
                        -> completeRequired(ownerIdentityId, handoff)
                        else -> throw MessagingRecoveryException("Outbound recovery history state is invalid")
                    }
                }
                else -> throw MessagingRecoveryException("Recovery handoff direction is invalid")
            }
        }

        history.pendingOutboundAcceptances(ownerIdentityId).forEach { record ->
            if (!pendingSendKeys.contains(MessageKey(record.peerIdentityId, record.messageId))) {
                throw MessagingRecoveryException(
                    "Pending outbound history is missing its recoverable staged envelope",
                )
            }
        }

        val recoveredAcks = history.pendingInboundAcks(ownerIdentityId).map { record ->
            MessagingRecoveredAck(
                peerIdentityId = record.peerIdentityId.copyOf(),
                messageId = record.messageId.copyOf(),
            )
        }
        return MessagingRecoveryPlan(recoveredSends, recoveredAcks)
    }

    /**
     * Called only for a durable outbound key that has not yet been sent on the active WSS
     * connection. If the exact plaintext/envelope expiry is due, history is transitioned first and
     * the staged ciphertext is removed second. A crash between those writes is recovered by
     * [recover] from the durable EXPIRED state without another send.
     */
    @Synchronized
    fun expireOutboundIfDue(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        nowEpochSeconds: Long,
    ): Boolean {
        requireIdentity(ownerIdentityId)
        val record = history.expireOutboundIfDue(
            ownerIdentityId = ownerIdentityId,
            peerIdentityId = peerIdentityId,
            messageId = messageId,
            nowEpochSeconds = nowEpochSeconds,
        )
        return when (record.deliveryState) {
            ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE -> false
            ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED -> {
                if (
                    !sessions.completeMessageHandoff(
                        ownerIdentityId = ownerIdentityId,
                        peerIdentityId = peerIdentityId,
                        messageId = messageId,
                        direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                    )
                ) {
                    throw MessagingRecoveryException("Expired outbound message lost its staged handoff")
                }
                true
            }
            else -> throw MessagingRecoveryException("Outbound expiry history state is invalid")
        }
    }

    /**
     * Applies an authenticated server SendAccepted in crash-safe order: history first, staged
     * ciphertext second. If a crash happens between those writes, [recover] observes ACCEPTED and
     * removes the leftover handoff without scheduling another send.
     */
    @Synchronized
    fun recordSendAccepted(
        ownerIdentityId: ByteArray,
        accepted: MessagingSendAccepted,
    ) {
        requireIdentity(ownerIdentityId)
        val before = history.currentState(ownerIdentityId)
            ?.messages
            ?.singleOrNull {
                it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                    it.peerIdentityId.contentEquals(accepted.recipientIdentityId) &&
                    it.messageId.contentEquals(accepted.messageId)
            }
            ?: throw MessagingRecoveryException("Accepted outbound message is absent from history")
        val wasAccepted = before.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED
        history.markOutboundAccepted(ownerIdentityId, accepted)
        val removed = sessions.completeMessageHandoff(
            ownerIdentityId = ownerIdentityId,
            peerIdentityId = accepted.recipientIdentityId,
            messageId = accepted.messageId,
            direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
        )
        if (!removed && !wasAccepted) {
            throw MessagingRecoveryException("Accepted outbound message lost its staged handoff")
        }
    }

    private fun recoverInbound(ownerIdentityId: ByteArray, handoff: SessionMessageHandoff) {
        history.importInboundPendingAck(ownerIdentityId, handoff)
        completeRequired(ownerIdentityId, handoff)
    }

    private fun completeRequired(ownerIdentityId: ByteArray, handoff: SessionMessageHandoff) {
        if (
            !sessions.completeMessageHandoff(
                ownerIdentityId = ownerIdentityId,
                peerIdentityId = handoff.peerIdentityId,
                messageId = handoff.messageId,
                direction = handoff.direction,
            )
        ) {
            throw MessagingRecoveryException("Recovery handoff disappeared before durable completion")
        }
    }

    private fun requireIdentity(ownerIdentityId: ByteArray) {
        if (ownerIdentityId.size != MESSAGING_IDENTITY_BYTES) {
            throw MessagingRecoveryException("Recovery owner identity id size is invalid")
        }
    }

    private class MessageKey(
        peerIdentityId: ByteArray,
        messageId: ByteArray,
    ) {
        private val peer = peerIdentityId.copyOf()
        private val message = messageId.copyOf()

        override fun equals(other: Any?): Boolean =
            other is MessageKey && peer.contentEquals(other.peer) && message.contentEquals(other.message)

        override fun hashCode(): Int = 31 * peer.contentHashCode() + message.contentHashCode()
    }
}
