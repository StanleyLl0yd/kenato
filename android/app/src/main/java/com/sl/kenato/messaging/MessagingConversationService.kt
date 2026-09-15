package com.sl.kenato.messaging

import com.sl.kenato.session.SessionStateCodec
import java.util.Base64

internal class MessagingConversationException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal enum class MessagingConversationDirection {
    INBOUND,
    OUTBOUND,
}

internal enum class MessagingConversationDeliveryState {
    RECEIVED,
    PENDING_SEND,
    SENT,
    EXPIRED_UNCONFIRMED,
}

internal data class MessagingConversationMessage(
    val messageId: String,
    val direction: MessagingConversationDirection,
    val deliveryState: MessagingConversationDeliveryState,
    val sentAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val text: String,
)

internal data class MessagingConversationState(
    val peerIdentityId: String,
    val messages: List<MessagingConversationMessage>,
)

internal interface MessagingConversationTextSender {
    fun stageText(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        text: String,
        ttlSeconds: Long,
    ): ConversationHistoryRecord
}

internal class DurableMessagingConversationTextSender(
    private val sender: DurableMessagingOutboundSender,
) : MessagingConversationTextSender {
    override fun stageText(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        text: String,
        ttlSeconds: Long,
    ): ConversationHistoryRecord = sender.stageText(
        ownerIdentityId = ownerIdentityId,
        peerIdentityId = peerIdentityId,
        text = text,
        ttlSeconds = ttlSeconds,
    )
}

/**
 * Best-effort wake-up for already durable messaging work. Transport failures are handled by the
 * WSS coordinator itself; this boundary never owns plaintext, encryption, or retry ciphertext.
 */
internal fun interface MessagingDurableWorkFlusher {
    fun flushDurableWork()
}

internal class WssMessagingDurableWorkFlusher(
    private val coordinator: MessagingWssCoordinator,
) : MessagingDurableWorkFlusher {
    override fun flushDurableWork() = coordinator.flushDurableWork()
}

/**
 * Minimal application boundary for one-to-one M4 text conversations. Plaintext becomes visible to
 * callers only from a durable conversation-history record. The service does not own sockets,
 * sessions, crypto state, or persistence encoding.
 */
internal class MessagingConversationService(
    private val outbound: MessagingConversationTextSender,
    private val history: ConversationHistoryRepository,
    private val durableWork: MessagingDurableWorkFlusher,
) {
    @Synchronized
    fun sendText(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        text: String,
        ttlSeconds: Long = MESSAGING_MAX_TTL_SECONDS,
    ): MessagingConversationMessage {
        requireConversation(ownerIdentityId, peerIdentityId)
        val record = outbound.stageText(
            ownerIdentityId = ownerIdentityId.copyOf(),
            peerIdentityId = peerIdentityId.copyOf(),
            text = text,
            ttlSeconds = ttlSeconds,
        )
        val visible = applicationMessage(ownerIdentityId, peerIdentityId, record)
        durableWork.flushDurableWork()
        return visible
    }

    @Synchronized
    fun conversation(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
    ): MessagingConversationState {
        requireConversation(ownerIdentityId, peerIdentityId)
        val messages = history.currentState(ownerIdentityId.copyOf())
            ?.messages
            ?.asSequence()
            ?.filter { it.peerIdentityId.contentEquals(peerIdentityId) }
            ?.map { applicationMessage(ownerIdentityId, peerIdentityId, it) }
            ?.toList()
            .orEmpty()
        return MessagingConversationState(
            peerIdentityId = BASE64_URL_ENCODER.encodeToString(peerIdentityId),
            messages = messages,
        )
    }

    private fun applicationMessage(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        record: ConversationHistoryRecord,
    ): MessagingConversationMessage {
        if (!record.peerIdentityId.contentEquals(peerIdentityId)) {
            throw MessagingConversationException("M4 conversation record belongs to a different peer")
        }
        val plaintext = try {
            MessagingWire.decodePlaintext(record.encodedPlaintext)
        } catch (error: Exception) {
            throw MessagingConversationException("M4 conversation plaintext is invalid", error)
        }
        val canonical = try {
            MessagingWire.encodePlaintext(plaintext)
        } catch (error: Exception) {
            throw MessagingConversationException("M4 conversation plaintext is invalid", error)
        }
        if (!canonical.contentEquals(record.encodedPlaintext)) {
            throw MessagingConversationException("M4 conversation plaintext is not canonical")
        }

        val direction: MessagingConversationDirection
        val deliveryState: MessagingConversationDeliveryState
        val expectedSender: ByteArray
        val expectedRecipient: ByteArray
        when (record.direction) {
            SessionStateCodec.HANDOFF_DIRECTION_INBOUND -> {
                if (record.deliveryState != ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK) {
                    throw MessagingConversationException("M4 inbound conversation delivery state is invalid")
                }
                direction = MessagingConversationDirection.INBOUND
                deliveryState = MessagingConversationDeliveryState.RECEIVED
                expectedSender = peerIdentityId
                expectedRecipient = ownerIdentityId
            }
            SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND -> {
                direction = MessagingConversationDirection.OUTBOUND
                deliveryState = when (record.deliveryState) {
                    ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE ->
                        MessagingConversationDeliveryState.PENDING_SEND
                    ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED ->
                        MessagingConversationDeliveryState.SENT
                    // TTL elapsed without a durable SendAccepted. A previous socket enqueue may
                    // have succeeded, so this state deliberately does not claim non-delivery.
                    ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED ->
                        MessagingConversationDeliveryState.EXPIRED_UNCONFIRMED
                    else -> throw MessagingConversationException("M4 outbound conversation delivery state is invalid")
                }
                expectedSender = ownerIdentityId
                expectedRecipient = peerIdentityId
            }
            else -> throw MessagingConversationException("M4 conversation direction is invalid")
        }
        if (
            !plaintext.senderIdentityId.contentEquals(expectedSender) ||
            !plaintext.recipientIdentityId.contentEquals(expectedRecipient) ||
            !plaintext.messageId.contentEquals(record.messageId)
        ) {
            throw MessagingConversationException("M4 conversation plaintext provenance is invalid")
        }

        return MessagingConversationMessage(
            messageId = BASE64_URL_ENCODER.encodeToString(record.messageId),
            direction = direction,
            deliveryState = deliveryState,
            sentAtEpochSeconds = plaintext.sentAtEpochSeconds,
            expiresAtEpochSeconds = plaintext.expiresAtEpochSeconds,
            text = plaintext.text,
        )
    }

    private fun requireConversation(ownerIdentityId: ByteArray, peerIdentityId: ByteArray) {
        if (
            ownerIdentityId.size != MESSAGING_IDENTITY_BYTES ||
            peerIdentityId.size != MESSAGING_IDENTITY_BYTES ||
            ownerIdentityId.contentEquals(peerIdentityId)
        ) {
            throw MessagingConversationException("M4 conversation identity context is invalid")
        }
    }

    private companion object {
        val BASE64_URL_ENCODER: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    }
}
