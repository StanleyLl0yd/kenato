package com.sl.kenato.messaging

import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ConversationHistoryPruningTest {
    @Test
    fun acceptedOutboundIsPrunedBeforeOutboundCapacityPreflightCompletes() {
        val initial = ConversationHistoryState(
            OWNER.copyOf(),
            (1..ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION).map { index ->
                record(
                    index = index,
                    peer = PEER_A,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                    deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
                    sentAt = index.toLong(),
                    expiresAt = 10_000,
                )
            },
        )
        val fixture = Fixture(initial, now = 100)

        fixture.preflight(PEER_A, 2_000)

        assertEquals(1, fixture.store.writeCount)
        val persisted = fixture.repository.currentState(OWNER)!!
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION - 1, persisted.messages.size)
        assertFalse(persisted.messages.any { it.messageId.contentEquals(messageId(1)) })
        assertTrue(persisted.messages.any { it.messageId.contentEquals(messageId(2)) })
    }

    @Test
    fun expiredOutboundIsSafelyPrunableAfterTerminalTransition() {
        val initial = ConversationHistoryState(
            OWNER.copyOf(),
            (1..ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION).map { index ->
                record(
                    index = index,
                    peer = PEER_A,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                    deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED,
                    sentAt = index.toLong(),
                    expiresAt = 2_000,
                )
            },
        )
        val fixture = Fixture(initial, now = 10_000)

        fixture.preflight(PEER_A, 2_000)

        assertEquals(1, fixture.store.writeCount)
        val persisted = fixture.repository.currentState(OWNER)!!
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION - 1, persisted.messages.size)
        assertFalse(persisted.messages.any { it.messageId.contentEquals(messageId(1)) })
    }

    @Test
    fun sameConversationPruningPrecedesOlderUnrelatedHistory() {
        val samePeer = (1..ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION).map { index ->
            record(
                index = index,
                peer = PEER_A,
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
                sentAt = 100L + index,
                expiresAt = 10_000,
            )
        }
        val unrelatedOldest = record(
            index = 5_000,
            peer = PEER_B,
            direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
            deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
            sentAt = 1,
            expiresAt = 10_000,
        )
        val fixture = Fixture(ConversationHistoryState(OWNER.copyOf(), listOf(unrelatedOldest) + samePeer), now = 100)

        fixture.preflight(PEER_A, 6_000)

        val persisted = fixture.repository.currentState(OWNER)!!
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION, persisted.messages.size)
        assertTrue(persisted.messages.any { it.messageId.contentEquals(unrelatedOldest.messageId) })
        assertFalse(persisted.messages.any { it.messageId.contentEquals(messageId(1)) })
    }

    @Test
    fun unexpiredInboundPendingAckIsNeverPruned() {
        val initial = ConversationHistoryState(
            OWNER.copyOf(),
            (1..ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION).map { index ->
                record(
                    index = index,
                    peer = PEER_A,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
                    deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK,
                    sentAt = index.toLong(),
                    expiresAt = 2_000,
                )
            },
        )
        val fixture = Fixture(initial, now = 1_999)

        assertThrows(ConversationHistoryException::class.java) {
            fixture.preflight(PEER_A, 2_000)
        }

        assertEquals(0, fixture.store.writeCount)
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION, fixture.repository.currentState(OWNER)!!.messages.size)
    }

    @Test
    fun inboundPendingAckBecomesPrunableAtExactExpiryBoundary() {
        val initial = ConversationHistoryState(
            OWNER.copyOf(),
            (1..ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION).map { index ->
                record(
                    index = index,
                    peer = PEER_A,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
                    deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK,
                    sentAt = index.toLong(),
                    expiresAt = 2_000,
                )
            },
        )
        val fixture = Fixture(initial, now = 2_000)

        fixture.preflight(PEER_A, 2_000)

        assertEquals(1, fixture.store.writeCount)
        val persisted = fixture.repository.currentState(OWNER)!!
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION - 1, persisted.messages.size)
        assertFalse(persisted.messages.any { it.messageId.contentEquals(messageId(1)) })
    }

    @Test
    fun pendingOutboundIsNeverPrunedEvenAfterEnvelopeExpiry() {
        val initial = ConversationHistoryState(
            OWNER.copyOf(),
            (1..ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION).map { index ->
                record(
                    index = index,
                    peer = PEER_A,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                    deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE,
                    sentAt = index.toLong(),
                    expiresAt = 2_000,
                )
            },
        )
        val fixture = Fixture(initial, now = 10_000)

        assertThrows(ConversationHistoryException::class.java) {
            fixture.preflight(PEER_A, 2_000)
        }

        assertEquals(0, fixture.store.writeCount)
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION, fixture.repository.currentState(OWNER)!!.messages.size)
    }

    @Test
    fun globalCountPressurePrunesOldestSafeRecordAcrossConversations() {
        val records = (1..ConversationHistoryStateCodec.MAX_MESSAGES).map { index ->
            record(
                index = index,
                peer = generatedPeer(index),
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
                sentAt = index.toLong(),
                expiresAt = 10_000,
            )
        }
        val fixture = Fixture(ConversationHistoryState(OWNER.copyOf(), records), now = 100)

        fixture.preflight(SPECIAL_PEER, 8_000)

        assertEquals(1, fixture.store.writeCount)
        val persisted = fixture.repository.currentState(OWNER)!!
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES - 1, persisted.messages.size)
        assertFalse(persisted.messages.any { it.messageId.contentEquals(messageId(1)) })
        assertTrue(persisted.messages.any { it.messageId.contentEquals(messageId(2)) })
    }

    @Test
    fun perConversationBytePressurePrunesEnoughSafeHistory() {
        val largeText = "x".repeat(MESSAGING_MAX_TEXT_BYTES)
        val records = ArrayList<ConversationHistoryRecord>()
        var retained = 0L
        var index = 1
        while (true) {
            val candidate = record(
                index = index,
                peer = PEER_A,
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
                sentAt = index.toLong(),
                expiresAt = 10_000,
                text = largeText,
            )
            val bytes = ConversationHistoryStateCodec.retainedBytesForBounds(candidate)
            if (retained + bytes > ConversationHistoryStateCodec.MAX_CONVERSATION_BYTES) break
            records += candidate
            retained += bytes
            index++
        }
        assertTrue(records.size < ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION)
        val fixture = Fixture(ConversationHistoryState(OWNER.copyOf(), records), now = 100)

        fixture.preflight(PEER_A, 20_000, largeText)

        assertEquals(1, fixture.store.writeCount)
        assertTrue(fixture.repository.currentState(OWNER)!!.messages.size < records.size)
    }

    @Test
    fun inboundImportMayPruneSafeHistoryAndCandidateIsPersistedInSameWrite() {
        val initial = ConversationHistoryState(
            OWNER.copyOf(),
            (1..ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION).map { index ->
                record(
                    index = index,
                    peer = PEER_A,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                    deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
                    sentAt = index.toLong(),
                    expiresAt = 10_000,
                )
            },
        )
        val fixture = Fixture(initial, now = 100)
        val handoff = inboundHandoff(9_000, PEER_A)

        val imported = fixture.repository.importInboundPendingAck(OWNER, handoff)

        assertEquals(1, fixture.store.writeCount)
        assertArrayEquals(messageId(9_000), imported.messageId)
        val persisted = fixture.repository.currentState(OWNER)!!
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION, persisted.messages.size)
        assertTrue(
            persisted.messages.any {
                it.direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND &&
                    it.messageId.contentEquals(messageId(9_000))
            },
        )
        assertFalse(persisted.messages.any { it.messageId.contentEquals(messageId(1)) })
    }

    @Test
    fun failedDurablePruneBlocksOutboundPreflightWithoutChangingHistory() {
        val initial = ConversationHistoryState(
            OWNER.copyOf(),
            (1..ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION).map { index ->
                record(
                    index = index,
                    peer = PEER_A,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                    deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
                    sentAt = index.toLong(),
                    expiresAt = 10_000,
                )
            },
        )
        val fixture = Fixture(initial, now = 100)
        fixture.store.failWrites = true

        assertThrows(ConversationHistoryException::class.java) {
            fixture.preflight(PEER_A, 2_000)
        }

        assertEquals(0, fixture.store.writeCount)
        val persisted = fixture.repository.currentState(OWNER)!!
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION, persisted.messages.size)
        assertTrue(persisted.messages.any { it.messageId.contentEquals(messageId(1)) })
    }

    private class Fixture(
        initial: ConversationHistoryState,
        now: Long,
    ) {
        val store = FakeHistoryStore(ConversationHistoryStateCodec.encode(initial))
        val repository = ConversationHistoryRepository(store, ConversationHistoryClock { now })

        fun preflight(peer: ByteArray, index: Int, text: String = "new-message") {
            repository.requireCanAppendOutbound(
                ownerIdentityId = OWNER,
                localContactId = CONTACT,
                peerIdentityId = peer,
                messageId = messageId(index),
                encodedPlaintext = encodedPlaintext(
                    index = index,
                    peer = peer,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                    sentAt = 20_000,
                    expiresAt = 21_000,
                    text = text,
                ),
            )
        }
    }

    private class FakeHistoryStore(initial: ByteArray) : ConversationHistoryStore {
        private var value = initial.copyOf()
        var writeCount = 0
        var failWrites = false

        override fun read(): ByteArray = value.copyOf()

        override fun write(value: ByteArray): Boolean {
            if (failWrites) return false
            this.value = value.copyOf()
            writeCount++
            return true
        }

        override fun clear(): Boolean {
            value = ByteArray(0)
            return true
        }
    }

    companion object {
        private val OWNER = bytes(0x11, MESSAGING_IDENTITY_BYTES)
        private val PEER_A = bytes(0x22, MESSAGING_IDENTITY_BYTES)
        private val PEER_B = bytes(0x33, MESSAGING_IDENTITY_BYTES)
        private val SPECIAL_PEER = bytes(0x7a, MESSAGING_IDENTITY_BYTES)
        private val CONTACT = bytes(0x44, SessionStateCodec.LOCAL_CONTACT_ID_BYTES)

        private fun record(
            index: Int,
            peer: ByteArray,
            direction: Int,
            deliveryState: Int,
            sentAt: Long,
            expiresAt: Long,
            text: String = "message-$index",
        ): ConversationHistoryRecord = ConversationHistoryRecord(
            localContactId = CONTACT.copyOf(),
            peerIdentityId = peer.copyOf(),
            messageId = messageId(index),
            direction = direction,
            deliveryState = deliveryState,
            encodedPlaintext = encodedPlaintext(index, peer, direction, sentAt, expiresAt, text),
            envelopeDigest = bytes(0x55, ConversationHistoryStateCodec.ENVELOPE_DIGEST_BYTES),
        )

        private fun encodedPlaintext(
            index: Int,
            peer: ByteArray,
            direction: Int,
            sentAt: Long,
            expiresAt: Long,
            text: String,
        ): ByteArray = MessagingWire.encodePlaintext(
            MessagingPlaintext(
                senderIdentityId = if (direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND) peer.copyOf() else OWNER.copyOf(),
                recipientIdentityId = if (direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND) OWNER.copyOf() else peer.copyOf(),
                messageId = messageId(index),
                sentAtEpochSeconds = sentAt,
                expiresAtEpochSeconds = expiresAt,
                text = text,
            ),
        )

        private fun inboundHandoff(index: Int, peer: ByteArray): SessionMessageHandoff {
            val plaintext = MessagingPlaintext(
                senderIdentityId = peer.copyOf(),
                recipientIdentityId = OWNER.copyOf(),
                messageId = messageId(index),
                sentAtEpochSeconds = 100,
                expiresAtEpochSeconds = 1_000,
                text = "inbound-$index",
            )
            val envelope = MessagingEnvelope(
                senderIdentityId = peer.copyOf(),
                recipientIdentityId = OWNER.copyOf(),
                messageId = messageId(index),
                ciphertext = byteArrayOf(1, 2, 3),
                expiresAtEpochSeconds = 1_000,
            )
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = peer.copyOf(),
                messageId = messageId(index),
                direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
                encodedPlaintext = MessagingWire.encodePlaintext(plaintext),
                encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
            )
        }

        private fun generatedPeer(index: Int): ByteArray = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x40.toByte() }.also {
            it[0] = 0x40
            it[1] = ((index ushr 24) and 0xff).toByte()
            it[2] = ((index ushr 16) and 0xff).toByte()
            it[3] = ((index ushr 8) and 0xff).toByte()
            it[4] = (index and 0xff).toByte()
        }

        private fun messageId(index: Int): ByteArray = ByteArray(MESSAGING_MESSAGE_ID_BYTES).also {
            it[0] = ((index ushr 24) and 0xff).toByte()
            it[1] = ((index ushr 16) and 0xff).toByte()
            it[2] = ((index ushr 8) and 0xff).toByte()
            it[3] = (index and 0xff).toByte()
            if (it.all { value -> value == 0.toByte() }) it[0] = 1
        }

        private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
    }
}
