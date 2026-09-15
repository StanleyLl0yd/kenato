package com.sl.kenato.messaging

import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.security.MessageDigest

internal class ConversationHistoryRepository(
    private val stateStore: ConversationHistoryStore,
) {
    @Synchronized
    fun currentState(ownerIdentityId: ByteArray): ConversationHistoryState? {
        requireIdentity(ownerIdentityId, "owner identity id")
        return loadState(ownerIdentityId)?.copyForCaller()
    }

    @Synchronized
    fun importInboundPendingAck(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
    ): ConversationHistoryRecord {
        requireIdentity(ownerIdentityId, "owner identity id")
        val candidate = inboundPendingAck(ownerIdentityId, handoff)
        val state = loadState(ownerIdentityId) ?: ConversationHistoryState(
            ownerIdentityId = ownerIdentityId.copyOf(),
            messages = emptyList(),
        )
        val existing = state.messages.singleOrNull {
            sameIdempotencyKey(it, candidate)
        }
        if (existing != null) {
            if (!sameRecord(existing, candidate)) {
                throw ConversationHistoryException("Conflicting conversation history record for authenticated message id")
            }
            return existing.copyForCaller()
        }

        val updated = state.copy(messages = state.messages + candidate)
        val encoded = ConversationHistoryStateCodec.encode(updated)
        if (!stateStore.write(encoded)) {
            throw ConversationHistoryException("Unable to durably persist conversation history")
        }
        return candidate.copyForCaller()
    }

    @Synchronized
    fun pendingInboundAcks(ownerIdentityId: ByteArray): List<ConversationHistoryRecord> {
        requireIdentity(ownerIdentityId, "owner identity id")
        return loadState(ownerIdentityId)
            ?.messages
            ?.filter {
                it.direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND &&
                    it.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK
            }
            ?.map(ConversationHistoryRecord::copyForCaller)
            .orEmpty()
    }

    @Synchronized
    fun matchesAuthenticatedInboundEnvelope(
        ownerIdentityId: ByteArray,
        encodedEnvelope: ByteArray,
    ): Boolean {
        requireIdentity(ownerIdentityId, "owner identity id")
        val envelope = decodeCanonicalEnvelope(encodedEnvelope)
        if (!envelope.recipientIdentityId.contentEquals(ownerIdentityId)) {
            throw ConversationHistoryException("Inbound history envelope recipient does not match local identity")
        }
        val envelopeDigest = MessageDigest.getInstance("SHA-256").digest(encodedEnvelope)
        return loadState(ownerIdentityId)?.messages?.any {
            it.direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND &&
                it.peerIdentityId.contentEquals(envelope.senderIdentityId) &&
                it.messageId.contentEquals(envelope.messageId) &&
                MessageDigest.isEqual(it.envelopeDigest, envelopeDigest)
        } == true
    }

    private fun loadState(ownerIdentityId: ByteArray): ConversationHistoryState? {
        val encoded = stateStore.read() ?: return null
        val state = ConversationHistoryStateCodec.decode(encoded)
        if (!state.ownerIdentityId.contentEquals(ownerIdentityId)) {
            throw ConversationHistoryException("Persisted conversation history belongs to a different local identity")
        }
        return state
    }

    private fun inboundPendingAck(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
    ): ConversationHistoryRecord {
        if (handoff.localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw ConversationHistoryException("Inbound history handoff contact id is invalid")
        }
        requireIdentity(handoff.peerIdentityId, "inbound history handoff peer identity id")
        requireMessageId(handoff.messageId)
        if (handoff.direction != SessionStateCodec.HANDOFF_DIRECTION_INBOUND) {
            throw ConversationHistoryException("Only inbound handoffs may enter PENDING_ACK")
        }

        val plaintext = decodeCanonicalPlaintext(handoff.encodedPlaintext)
        val envelope = decodeCanonicalEnvelope(handoff.encodedEnvelope)
        if (
            !plaintext.senderIdentityId.contentEquals(handoff.peerIdentityId) ||
            !plaintext.recipientIdentityId.contentEquals(ownerIdentityId) ||
            !plaintext.messageId.contentEquals(handoff.messageId) ||
            !envelope.senderIdentityId.contentEquals(handoff.peerIdentityId) ||
            !envelope.recipientIdentityId.contentEquals(ownerIdentityId) ||
            !envelope.messageId.contentEquals(handoff.messageId) ||
            envelope.expiresAtEpochSeconds != plaintext.expiresAtEpochSeconds
        ) {
            throw ConversationHistoryException("Inbound history handoff does not match authenticated messaging context")
        }

        return ConversationHistoryRecord(
            localContactId = handoff.localContactId.copyOf(),
            peerIdentityId = handoff.peerIdentityId.copyOf(),
            messageId = handoff.messageId.copyOf(),
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
            deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK,
            encodedPlaintext = handoff.encodedPlaintext.copyOf(),
            envelopeDigest = MessageDigest.getInstance("SHA-256").digest(handoff.encodedEnvelope),
        )
    }

    private fun decodeCanonicalPlaintext(encoded: ByteArray): MessagingPlaintext {
        val value = try {
            MessagingWire.decodePlaintext(encoded)
        } catch (error: Exception) {
            throw ConversationHistoryException("Inbound history plaintext is invalid", error)
        }
        val canonical = try {
            MessagingWire.encodePlaintext(value)
        } catch (error: Exception) {
            throw ConversationHistoryException("Inbound history plaintext is invalid", error)
        }
        if (!canonical.contentEquals(encoded)) {
            throw ConversationHistoryException("Inbound history plaintext is not canonical")
        }
        return value
    }

    private fun decodeCanonicalEnvelope(encoded: ByteArray): MessagingEnvelope {
        val value = try {
            MessagingWire.decodeEnvelope(encoded)
        } catch (error: Exception) {
            throw ConversationHistoryException("Inbound history envelope is invalid", error)
        }
        val canonical = try {
            MessagingWire.encodeEnvelope(value)
        } catch (error: Exception) {
            throw ConversationHistoryException("Inbound history envelope is invalid", error)
        }
        if (!canonical.contentEquals(encoded)) {
            throw ConversationHistoryException("Inbound history envelope is not canonical")
        }
        return value
    }

    private fun requireIdentity(value: ByteArray, name: String) {
        if (value.size != MESSAGING_IDENTITY_BYTES) {
            throw ConversationHistoryException("$name size is invalid")
        }
    }

    private fun requireMessageId(value: ByteArray) {
        if (value.size != MESSAGING_MESSAGE_ID_BYTES || value.all { it == 0.toByte() }) {
            throw ConversationHistoryException("Inbound history message id is invalid")
        }
    }

    private fun sameIdempotencyKey(
        first: ConversationHistoryRecord,
        second: ConversationHistoryRecord,
    ): Boolean =
        first.direction == second.direction &&
            first.peerIdentityId.contentEquals(second.peerIdentityId) &&
            first.messageId.contentEquals(second.messageId)

    private fun sameRecord(
        first: ConversationHistoryRecord,
        second: ConversationHistoryRecord,
    ): Boolean =
        first.localContactId.contentEquals(second.localContactId) &&
            first.peerIdentityId.contentEquals(second.peerIdentityId) &&
            first.messageId.contentEquals(second.messageId) &&
            first.direction == second.direction &&
            first.deliveryState == second.deliveryState &&
            first.encodedPlaintext.contentEquals(second.encodedPlaintext) &&
            first.envelopeDigest.contentEquals(second.envelopeDigest)
}
