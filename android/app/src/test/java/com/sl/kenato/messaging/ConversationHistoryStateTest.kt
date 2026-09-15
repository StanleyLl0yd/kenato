package com.sl.kenato.messaging

import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ConversationHistoryStateTest {
    @Test
    fun pendingAckHistoryRoundTripsExactCanonicalPlaintext() {
        val state = ConversationHistoryState(
            ownerIdentityId = OWNER.copyOf(),
            messages = listOf(record(1)),
        )

        val decoded = ConversationHistoryStateCodec.decode(ConversationHistoryStateCodec.encode(state))
        val actual = decoded.messages.single()

        assertArrayEquals(OWNER, decoded.ownerIdentityId)
        assertArrayEquals(CONTACT, actual.localContactId)
        assertArrayEquals(PEER, actual.peerIdentityId)
        assertArrayEquals(messageId(1), actual.messageId)
        assertEquals(SessionStateCodec.HANDOFF_DIRECTION_INBOUND, actual.direction)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK, actual.deliveryState)
        assertArrayEquals(state.messages.single().encodedPlaintext, actual.encodedPlaintext)
        assertArrayEquals(state.messages.single().envelopeDigest, actual.envelopeDigest)
    }

    @Test
    fun outboundPendingAndAcceptedHistoryRoundTrip() {
        val pending = outboundRecord(1, ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE)
        val accepted = outboundRecord(2, ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED)
        val decoded = ConversationHistoryStateCodec.decode(
            ConversationHistoryStateCodec.encode(
                ConversationHistoryState(OWNER.copyOf(), listOf(pending, accepted)),
            ),
        )

        assertEquals(2, decoded.messages.size)
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE,
            decoded.messages[0].deliveryState,
        )
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED, decoded.messages[1].deliveryState)
        decoded.messages.forEach { actual ->
            assertEquals(SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND, actual.direction)
            val plaintext = MessagingWire.decodePlaintext(actual.encodedPlaintext)
            assertArrayEquals(OWNER, plaintext.senderIdentityId)
            assertArrayEquals(PEER, plaintext.recipientIdentityId)
        }
    }

    @Test
    fun directionDeliveryStateMismatchFailsClosed() {
        assertThrows(ConversationHistoryException::class.java) {
            ConversationHistoryStateCodec.encode(
                ConversationHistoryState(
                    OWNER.copyOf(),
                    listOf(record(1).copy(deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE)),
                ),
            )
        }
        assertThrows(ConversationHistoryException::class.java) {
            ConversationHistoryStateCodec.encode(
                ConversationHistoryState(
                    OWNER.copyOf(),
                    listOf(
                        outboundRecord(1, ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE).copy(
                            deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK,
                        ),
                    ),
                ),
            )
        }
    }

    @Test
    fun checksumCorruptionFailsClosed() {
        val encoded = ConversationHistoryStateCodec.encode(
            ConversationHistoryState(OWNER.copyOf(), listOf(record(1))),
        )
        encoded[encoded.lastIndex] = (encoded.last().toInt() xor 1).toByte()

        assertThrows(ConversationHistoryException::class.java) {
            ConversationHistoryStateCodec.decode(encoded)
        }
    }

    @Test
    fun duplicateAuthenticatedIdempotencyKeyFailsClosed() {
        val first = record(1)
        val conflicting = first.copy(
            encodedPlaintext = encodedPlaintext(1, "different", SessionStateCodec.HANDOFF_DIRECTION_INBOUND),
            envelopeDigest = bytes(0x7f, ConversationHistoryStateCodec.ENVELOPE_DIGEST_BYTES),
        )

        assertThrows(ConversationHistoryException::class.java) {
            ConversationHistoryStateCodec.encode(
                ConversationHistoryState(OWNER.copyOf(), listOf(first, conflicting)),
            )
        }
    }

    @Test
    fun globalMessageCountIsBounded() {
        val sample = record(1)
        val tooMany = List(ConversationHistoryStateCodec.MAX_MESSAGES + 1) { sample }

        assertThrows(ConversationHistoryException::class.java) {
            ConversationHistoryStateCodec.encode(ConversationHistoryState(OWNER.copyOf(), tooMany))
        }
    }

    @Test
    fun perConversationMessageCountIsBounded() {
        val tooMany = (1..ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION + 1).map(::record)

        assertThrows(ConversationHistoryException::class.java) {
            ConversationHistoryStateCodec.encode(ConversationHistoryState(OWNER.copyOf(), tooMany))
        }
    }

    @Test
    fun perConversationRetainedBytesAreBounded() {
        val largeText = "x".repeat(MESSAGING_MAX_TEXT_BYTES)
        val records = (1..300).map { index -> record(index, largeText) }

        assertThrows(ConversationHistoryException::class.java) {
            ConversationHistoryStateCodec.encode(ConversationHistoryState(OWNER.copyOf(), records))
        }
    }

    private fun record(index: Int, text: String = "message-$index"): ConversationHistoryRecord =
        ConversationHistoryRecord(
            localContactId = CONTACT.copyOf(),
            peerIdentityId = PEER.copyOf(),
            messageId = messageId(index),
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
            deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK,
            encodedPlaintext = encodedPlaintext(index, text, SessionStateCodec.HANDOFF_DIRECTION_INBOUND),
            envelopeDigest = bytes(index, ConversationHistoryStateCodec.ENVELOPE_DIGEST_BYTES),
        )

    private fun outboundRecord(index: Int, deliveryState: Int): ConversationHistoryRecord =
        ConversationHistoryRecord(
            localContactId = CONTACT.copyOf(),
            peerIdentityId = PEER.copyOf(),
            messageId = messageId(index),
            direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
            deliveryState = deliveryState,
            encodedPlaintext = encodedPlaintext(index, "message-$index", SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND),
            envelopeDigest = bytes(index, ConversationHistoryStateCodec.ENVELOPE_DIGEST_BYTES),
        )

    private fun encodedPlaintext(index: Int, text: String, direction: Int): ByteArray = MessagingWire.encodePlaintext(
        MessagingPlaintext(
            senderIdentityId = if (direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND) PEER.copyOf() else OWNER.copyOf(),
            recipientIdentityId = if (direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND) OWNER.copyOf() else PEER.copyOf(),
            messageId = messageId(index),
            sentAtEpochSeconds = 100,
            expiresAtEpochSeconds = 200,
            text = text,
        ),
    )

    private fun messageId(index: Int): ByteArray = ByteArray(MESSAGING_MESSAGE_ID_BYTES).also {
        it[0] = ((index ushr 24) and 0xff).toByte()
        it[1] = ((index ushr 16) and 0xff).toByte()
        it[2] = ((index ushr 8) and 0xff).toByte()
        it[3] = (index and 0xff).toByte()
        if (it.all { value -> value == 0.toByte() }) it[0] = 1
    }

    companion object {
        private val OWNER = bytes(0x11, MESSAGING_IDENTITY_BYTES)
        private val PEER = bytes(0x22, MESSAGING_IDENTITY_BYTES)
        private val CONTACT = bytes(0x33, SessionStateCodec.LOCAL_CONTACT_ID_BYTES)

        private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
    }
}
