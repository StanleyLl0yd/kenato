package com.sl.kenato.messaging

import com.sl.kenato.session.NativeSessionMessage
import com.sl.kenato.session.SESSION_OLM_MESSAGE_NORMAL
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageCryptoContext
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingOutboundSendTest {
    @Test
    fun stageTextPersistsExactOutboundBeforeTransport() {
        val fixture = Fixture(messageIds = SequenceMessageIds(messageId(1)))

        val record = fixture.sender.stageText(
            ownerIdentityId = OWNER,
            peerIdentityId = PEER,
            text = "hello",
            ttlSeconds = 60,
        )

        assertEquals(1, fixture.recovery.calls)
        assertEquals(1, fixture.sessions.resolveCount)
        assertEquals(1, fixture.sessions.stageCount)
        assertEquals(1, fixture.historyStore.writeCount)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE, record.deliveryState)

        val handoff = fixture.sessions.lastHandoff!!
        assertArrayEquals(record.messageId, handoff.messageId)
        assertEquals(SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND, handoff.direction)

        val plaintext = MessagingWire.decodePlaintext(handoff.encodedPlaintext)
        assertArrayEquals(OWNER, plaintext.senderIdentityId)
        assertArrayEquals(PEER, plaintext.recipientIdentityId)
        assertArrayEquals(messageId(1), plaintext.messageId)
        assertEquals(100L, plaintext.sentAtEpochSeconds)
        assertEquals(160L, plaintext.expiresAtEpochSeconds)
        assertEquals("hello", plaintext.text)

        val envelope = MessagingWire.decodeEnvelope(handoff.encodedEnvelope)
        assertArrayEquals(OWNER, envelope.senderIdentityId)
        assertArrayEquals(PEER, envelope.recipientIdentityId)
        assertArrayEquals(messageId(1), envelope.messageId)
        assertEquals(160L, envelope.expiresAtEpochSeconds)
        assertArrayEquals(handoff.encodedEnvelope, MessagingWire.encodeEnvelope(envelope))

        val ciphertext = SessionCiphertextWire.decode(envelope.ciphertext)
        assertArrayEquals(OWNER, ciphertext.senderIdentityId)
        assertArrayEquals(PEER, ciphertext.recipientIdentityId)
        assertEquals(7L, ciphertext.senderAccountGeneration)
        assertEquals(8L, ciphertext.recipientAccountGeneration)
        assertEquals(SESSION_OLM_MESSAGE_NORMAL, ciphertext.olmMessageType)
        assertArrayEquals(NATIVE_CIPHERTEXT, ciphertext.olmMessage)
    }

    @Test
    fun queueBoundFailsBeforeSessionLookupOrEncryption() {
        val fixture = Fixture(messageIds = SequenceMessageIds(messageId(1)))
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = List(MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS) { index ->
                MessagingRecoveredSend(
                    peerIdentityId = PEER.copyOf(),
                    messageId = messageId(index + 1),
                    encodedEnvelope = byteArrayOf(1),
                )
            },
            inboundAcks = emptyList(),
        )

        assertThrows(MessagingOutboundSendException::class.java) {
            fixture.sender.stageText(OWNER, PEER, "blocked", 60)
        }

        assertEquals(1, fixture.recovery.calls)
        assertEquals(0, fixture.sessions.resolveCount)
        assertEquals(0, fixture.sessions.stageCount)
        assertEquals(0, fixture.historyStore.writeCount)
    }

    @Test
    fun malformedApplicationInputFailsBeforeRecoveryOrEncryption() {
        val fixture = Fixture(messageIds = SequenceMessageIds(messageId(1)))

        assertThrows(MessagingOutboundSendException::class.java) {
            fixture.sender.stageText(OWNER, PEER, "", 60)
        }
        assertThrows(MessagingOutboundSendException::class.java) {
            fixture.sender.stageText(OWNER, PEER, "message", 0)
        }
        assertThrows(MessagingOutboundSendException::class.java) {
            fixture.sender.stageText(OWNER, OWNER, "message", 60)
        }

        assertEquals(0, fixture.recovery.calls)
        assertEquals(0, fixture.sessions.resolveCount)
        assertEquals(0, fixture.sessions.stageCount)
    }

    @Test
    fun existingOutboundMessageIdIsRetriedBeforeEncryption() {
        val ids = SequenceMessageIds(messageId(1), messageId(2))
        val fixture = Fixture(messageIds = ids)
        val old = outboundHandoff(messageId(1), "old")
        fixture.history.importOutboundPendingAcceptance(OWNER, old)
        fixture.history.markOutboundAccepted(
            OWNER,
            MessagingSendAccepted(PEER.copyOf(), old.messageId.copyOf()),
        )

        val record = fixture.sender.stageText(OWNER, PEER, "new", 60)

        assertEquals(2, ids.calls)
        assertArrayEquals(messageId(2), record.messageId)
        assertEquals(1, fixture.sessions.stageCount)
    }

    @Test
    fun nonPrunableHistoryCapacityFailureOccursBeforeRatchetEncryption() {
        val fullState = ConversationHistoryState(
            ownerIdentityId = OWNER.copyOf(),
            messages = List(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION) { index ->
                historyRecord(index + 1, ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE)
            },
        )
        val fixture = Fixture(
            messageIds = SequenceMessageIds(messageId(2_000)),
            initialHistory = ConversationHistoryStateCodec.encode(fullState),
        )

        assertThrows(ConversationHistoryException::class.java) {
            fixture.sender.stageText(OWNER, PEER, "no-space", 60)
        }

        assertEquals(1, fixture.recovery.calls)
        assertEquals(1, fixture.sessions.resolveCount)
        assertEquals(0, fixture.sessions.stageCount)
        assertEquals(0, fixture.historyStore.writeCount)
    }

    @Test
    fun acceptedHistoryIsDurablyPrunedBeforeRatchetEncryption() {
        val fullState = ConversationHistoryState(
            ownerIdentityId = OWNER.copyOf(),
            messages = List(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION) { index ->
                historyRecord(index + 1, ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED)
            },
        )
        val fixture = Fixture(
            messageIds = SequenceMessageIds(messageId(2_000)),
            initialHistory = ConversationHistoryStateCodec.encode(fullState),
        )

        val record = fixture.sender.stageText(OWNER, PEER, "new-after-prune", 60)

        assertEquals(1, fixture.sessions.stageCount)
        assertEquals(2, fixture.historyStore.writeCount)
        val persisted = fixture.history.currentState(OWNER)!!
        assertEquals(ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION, persisted.messages.size)
        assertFalse(persisted.messages.any { it.messageId.contentEquals(messageId(1)) })
        assertTrue(persisted.messages.any { it.messageId.contentEquals(record.messageId) })
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE, record.deliveryState)
    }

    private class Fixture(
        messageIds: MessagingMessageIdGenerator,
        initialHistory: ByteArray? = null,
    ) {
        val historyStore = FakeHistoryStore(initialHistory)
        val history = ConversationHistoryRepository(historyStore, ConversationHistoryClock { 100 })
        val sessions = FakeOutboundSessions()
        val recovery = FakeRecovery()
        val sender = DurableMessagingOutboundSender(
            sessions = sessions,
            history = history,
            recovery = recovery,
            admission = MessagingOutboundAdmission { _, _, _, _ -> false },
            messageIds = messageIds,
            clock = MessagingOutboundClock { 100 },
        )
    }

    private class FakeHistoryStore(initial: ByteArray?) : ConversationHistoryStore {
        private var value = initial?.copyOf()
        var writeCount = 0

        override fun read(): ByteArray? = value?.copyOf()

        override fun write(value: ByteArray): Boolean {
            this.value = value.copyOf()
            writeCount++
            return true
        }

        override fun clear(): Boolean {
            value = null
            return true
        }
    }

    private class FakeRecovery : MessagingOutboundRecovery {
        var calls = 0
        var plan = MessagingRecoveryPlan(emptyList(), emptyList())

        override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan {
            assertArrayEquals(OWNER, ownerIdentityId)
            calls++
            return plan
        }
    }

    private class FakeOutboundSessions : MessagingOutboundSessionDriver {
        var resolveCount = 0
        var stageCount = 0
        var lastHandoff: SessionMessageHandoff? = null

        override fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray {
            assertArrayEquals(OWNER, ownerIdentityId)
            assertArrayEquals(PEER, peerIdentityId)
            resolveCount++
            return CONTACT.copyOf()
        }

        override fun encryptAndStageMessageHandoff(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            encodedPlaintext: ByteArray,
            buildHandoff: (SessionMessageCryptoContext, NativeSessionMessage) -> SessionMessageHandoff,
        ): SessionMessageHandoff {
            assertArrayEquals(OWNER, ownerIdentityId)
            assertArrayEquals(CONTACT, localContactId)
            stageCount++
            val handoff = buildHandoff(
                SessionMessageCryptoContext(
                    ownerIdentityId = OWNER.copyOf(),
                    localContactId = CONTACT.copyOf(),
                    peerIdentityId = PEER.copyOf(),
                    localAccountGeneration = 7,
                    peerAccountGeneration = 8,
                ),
                NativeSessionMessage(
                    messageType = SESSION_OLM_MESSAGE_NORMAL,
                    ciphertext = NATIVE_CIPHERTEXT.copyOf(),
                ),
            )
            assertArrayEquals(encodedPlaintext, handoff.encodedPlaintext)
            lastHandoff = copyHandoff(handoff)
            return copyHandoff(handoff)
        }
    }

    private class SequenceMessageIds(vararg ids: ByteArray) : MessagingMessageIdGenerator {
        private val values = ids.map(ByteArray::copyOf).toMutableList()
        var calls = 0

        override fun nextMessageId(): ByteArray {
            calls++
            if (values.isEmpty()) return ByteArray(MESSAGING_MESSAGE_ID_BYTES)
            return values.removeAt(0).copyOf()
        }
    }

    companion object {
        private val OWNER = bytes(0x11, MESSAGING_IDENTITY_BYTES)
        private val PEER = bytes(0x22, MESSAGING_IDENTITY_BYTES)
        private val CONTACT = bytes(0x33, SessionStateCodec.LOCAL_CONTACT_ID_BYTES)
        private val NATIVE_CIPHERTEXT = byteArrayOf(9, 8, 7, 6)

        private fun historyRecord(index: Int, deliveryState: Int): ConversationHistoryRecord {
            val id = messageId(index)
            val plaintext = MessagingPlaintext(
                senderIdentityId = OWNER.copyOf(),
                recipientIdentityId = PEER.copyOf(),
                messageId = id.copyOf(),
                sentAtEpochSeconds = index.toLong(),
                expiresAtEpochSeconds = 10_000,
                text = "m$index",
            )
            return ConversationHistoryRecord(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = PEER.copyOf(),
                messageId = id,
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                deliveryState = deliveryState,
                encodedPlaintext = MessagingWire.encodePlaintext(plaintext),
                envelopeDigest = ByteArray(ConversationHistoryStateCodec.ENVELOPE_DIGEST_BYTES) { 0x44.toByte() },
            )
        }

        private fun outboundHandoff(messageId: ByteArray, text: String): SessionMessageHandoff {
            val plaintext = MessagingPlaintext(
                senderIdentityId = OWNER.copyOf(),
                recipientIdentityId = PEER.copyOf(),
                messageId = messageId.copyOf(),
                sentAtEpochSeconds = 100,
                expiresAtEpochSeconds = 200,
                text = text,
            )
            val envelope = MessagingEnvelope(
                senderIdentityId = OWNER.copyOf(),
                recipientIdentityId = PEER.copyOf(),
                messageId = messageId.copyOf(),
                ciphertext = byteArrayOf(1),
                expiresAtEpochSeconds = 200,
            )
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = PEER.copyOf(),
                messageId = messageId.copyOf(),
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                encodedPlaintext = MessagingWire.encodePlaintext(plaintext),
                encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
            )
        }

        private fun copyHandoff(value: SessionMessageHandoff): SessionMessageHandoff = value.copy(
            localContactId = value.localContactId.copyOf(),
            peerIdentityId = value.peerIdentityId.copyOf(),
            messageId = value.messageId.copyOf(),
            encodedPlaintext = value.encodedPlaintext.copyOf(),
            encodedEnvelope = value.encodedEnvelope.copyOf(),
        )

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
