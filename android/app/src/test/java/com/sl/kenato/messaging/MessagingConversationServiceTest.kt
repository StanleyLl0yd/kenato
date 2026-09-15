package com.sl.kenato.messaging

import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class MessagingConversationServiceTest {
    @Test
    fun sendTextPublishesOnlyDurableHistoryThenFlushesLiveWork() {
        val events = ArrayList<String>()
        val store = FakeHistoryStore(events = events)
        val history = ConversationHistoryRepository(store, ConversationHistoryClock { 100 })
        val sender = PersistingSender(history, events)
        val service = MessagingConversationService(
            outbound = sender,
            history = history,
            durableWork = MessagingDurableWorkFlusher { events += "flush" },
        )

        val message = service.sendText(
            ownerIdentityId = OWNER,
            peerIdentityId = PEER_A,
            text = "hello",
            ttlSeconds = 60,
        )

        assertEquals(listOf("stage-start", "history-write", "stage-return", "flush"), events)
        assertEquals(base64(messageId(1)), message.messageId)
        assertEquals(MessagingConversationDirection.OUTBOUND, message.direction)
        assertEquals(MessagingConversationDeliveryState.PENDING_SEND, message.deliveryState)
        assertEquals(100L, message.sentAtEpochSeconds)
        assertEquals(160L, message.expiresAtEpochSeconds)
        assertEquals("hello", message.text)
        assertEquals(1, history.currentState(OWNER)!!.messages.size)
    }

    @Test
    fun durableSendFailureNeverFlushesTransport() {
        var flushCount = 0
        val history = ConversationHistoryRepository(FakeHistoryStore(), ConversationHistoryClock { 100 })
        val service = MessagingConversationService(
            outbound = object : MessagingConversationTextSender {
                override fun stageText(
                    ownerIdentityId: ByteArray,
                    peerIdentityId: ByteArray,
                    text: String,
                    ttlSeconds: Long,
                ): ConversationHistoryRecord {
                    throw ConversationHistoryException("write failed")
                }
            },
            history = history,
            durableWork = MessagingDurableWorkFlusher { flushCount++ },
        )

        assertThrows(ConversationHistoryException::class.java) {
            service.sendText(OWNER, PEER_A, "hello", 60)
        }

        assertEquals(0, flushCount)
        assertEquals(null, history.currentState(OWNER))
    }

    @Test
    fun conversationReadsOnlyPersistedPeerHistoryAndMapsApplicationStates() {
        val state = ConversationHistoryState(
            ownerIdentityId = OWNER.copyOf(),
            messages = listOf(
                record(1, PEER_A, SessionStateCodec.HANDOFF_DIRECTION_INBOUND, ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK, "received", 90, 190),
                record(2, PEER_A, SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND, ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE, "pending", 100, 200),
                record(3, PEER_A, SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND, ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED, "sent", 110, 210),
                record(4, PEER_A, SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND, ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED, "expired", 120, 220),
                record(5, PEER_B, SessionStateCodec.HANDOFF_DIRECTION_INBOUND, ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK, "other", 130, 230),
            ),
        )
        val history = ConversationHistoryRepository(
            FakeHistoryStore(initial = ConversationHistoryStateCodec.encode(state)),
            ConversationHistoryClock { 150 },
        )
        var flushCount = 0
        val service = MessagingConversationService(
            outbound = object : MessagingConversationTextSender {
                override fun stageText(
                    ownerIdentityId: ByteArray,
                    peerIdentityId: ByteArray,
                    text: String,
                    ttlSeconds: Long,
                ): ConversationHistoryRecord = error("read path must not stage outbound work")
            },
            history = history,
            durableWork = MessagingDurableWorkFlusher { flushCount++ },
        )

        val conversation = service.conversation(OWNER, PEER_A)

        assertEquals(base64(PEER_A), conversation.peerIdentityId)
        assertEquals(4, conversation.messages.size)
        assertEquals(listOf("received", "pending", "sent", "expired"), conversation.messages.map { it.text })
        assertEquals(
            listOf(
                MessagingConversationDirection.INBOUND,
                MessagingConversationDirection.OUTBOUND,
                MessagingConversationDirection.OUTBOUND,
                MessagingConversationDirection.OUTBOUND,
            ),
            conversation.messages.map { it.direction },
        )
        assertEquals(
            listOf(
                MessagingConversationDeliveryState.RECEIVED,
                MessagingConversationDeliveryState.PENDING_SEND,
                MessagingConversationDeliveryState.SENT,
                MessagingConversationDeliveryState.EXPIRED_UNCONFIRMED,
            ),
            conversation.messages.map { it.deliveryState },
        )
        assertEquals(listOf(90L, 100L, 110L, 120L), conversation.messages.map { it.sentAtEpochSeconds })
        assertEquals(listOf(190L, 200L, 210L, 220L), conversation.messages.map { it.expiresAtEpochSeconds })
        assertEquals(0, flushCount)
    }

    @Test
    fun emptyConversationDoesNotFabricateApplicationMessages() {
        val history = ConversationHistoryRepository(FakeHistoryStore(), ConversationHistoryClock { 100 })
        val service = MessagingConversationService(
            outbound = unusedSender(),
            history = history,
            durableWork = MessagingDurableWorkFlusher { error("read path must not flush") },
        )

        val state = service.conversation(OWNER, PEER_A)

        assertEquals(base64(PEER_A), state.peerIdentityId)
        assertTrue(state.messages.isEmpty())
    }

    @Test
    fun corruptPersistedHistoryFailsClosedAtApplicationBoundary() {
        val history = ConversationHistoryRepository(
            FakeHistoryStore(initial = byteArrayOf(1, 2, 3)),
            ConversationHistoryClock { 100 },
        )
        val service = MessagingConversationService(
            outbound = unusedSender(),
            history = history,
            durableWork = MessagingDurableWorkFlusher { error("corrupt read must not flush") },
        )

        assertThrows(ConversationHistoryException::class.java) {
            service.conversation(OWNER, PEER_A)
        }
    }

    @Test
    fun invalidConversationIdentityFailsBeforeSenderOrHistoryAccess() {
        var senderCalls = 0
        var flushCalls = 0
        val history = ConversationHistoryRepository(FakeHistoryStore(), ConversationHistoryClock { 100 })
        val service = MessagingConversationService(
            outbound = object : MessagingConversationTextSender {
                override fun stageText(
                    ownerIdentityId: ByteArray,
                    peerIdentityId: ByteArray,
                    text: String,
                    ttlSeconds: Long,
                ): ConversationHistoryRecord {
                    senderCalls++
                    error("invalid context must not reach sender")
                }
            },
            history = history,
            durableWork = MessagingDurableWorkFlusher { flushCalls++ },
        )

        assertThrows(MessagingConversationException::class.java) {
            service.sendText(OWNER, OWNER, "hello", 60)
        }
        assertThrows(MessagingConversationException::class.java) {
            service.conversation(byteArrayOf(1), PEER_A)
        }

        assertEquals(0, senderCalls)
        assertEquals(0, flushCalls)
    }

    private class PersistingSender(
        private val history: ConversationHistoryRepository,
        private val events: MutableList<String>,
    ) : MessagingConversationTextSender {
        private var nextIndex = 1

        override fun stageText(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            text: String,
            ttlSeconds: Long,
        ): ConversationHistoryRecord {
            events += "stage-start"
            val index = nextIndex++
            val handoff = outboundHandoff(index, peerIdentityId, text, 100, 100 + ttlSeconds)
            val result = history.importOutboundPendingAcceptance(ownerIdentityId, handoff)
            events += "stage-return"
            return result
        }
    }

    private class FakeHistoryStore(
        initial: ByteArray? = null,
        private val events: MutableList<String>? = null,
    ) : ConversationHistoryStore {
        private var value = initial?.copyOf()

        override fun read(): ByteArray? = value?.copyOf()

        override fun write(value: ByteArray): Boolean {
            this.value = value.copyOf()
            events?.add("history-write")
            return true
        }

        override fun clear(): Boolean {
            value = null
            return true
        }
    }

    companion object {
        private val OWNER = bytes(0x11, MESSAGING_IDENTITY_BYTES)
        private val PEER_A = bytes(0x22, MESSAGING_IDENTITY_BYTES)
        private val PEER_B = bytes(0x33, MESSAGING_IDENTITY_BYTES)
        private val CONTACT = bytes(0x44, SessionStateCodec.LOCAL_CONTACT_ID_BYTES)
        private val BASE64 = Base64.getUrlEncoder().withoutPadding()

        private fun unusedSender(): MessagingConversationTextSender = object : MessagingConversationTextSender {
            override fun stageText(
                ownerIdentityId: ByteArray,
                peerIdentityId: ByteArray,
                text: String,
                ttlSeconds: Long,
            ): ConversationHistoryRecord = error("sender is not used by this test")
        }

        private fun record(
            index: Int,
            peer: ByteArray,
            direction: Int,
            deliveryState: Int,
            text: String,
            sentAt: Long,
            expiresAt: Long,
        ): ConversationHistoryRecord = ConversationHistoryRecord(
            localContactId = CONTACT.copyOf(),
            peerIdentityId = peer.copyOf(),
            messageId = messageId(index),
            direction = direction,
            deliveryState = deliveryState,
            encodedPlaintext = MessagingWire.encodePlaintext(
                MessagingPlaintext(
                    senderIdentityId = if (direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND) peer.copyOf() else OWNER.copyOf(),
                    recipientIdentityId = if (direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND) OWNER.copyOf() else peer.copyOf(),
                    messageId = messageId(index),
                    sentAtEpochSeconds = sentAt,
                    expiresAtEpochSeconds = expiresAt,
                    text = text,
                ),
            ),
            envelopeDigest = bytes(0x55, ConversationHistoryStateCodec.ENVELOPE_DIGEST_BYTES),
        )

        private fun outboundHandoff(
            index: Int,
            peer: ByteArray,
            text: String,
            sentAt: Long,
            expiresAt: Long,
        ): SessionMessageHandoff {
            val id = messageId(index)
            val plaintext = MessagingPlaintext(
                senderIdentityId = OWNER.copyOf(),
                recipientIdentityId = peer.copyOf(),
                messageId = id.copyOf(),
                sentAtEpochSeconds = sentAt,
                expiresAtEpochSeconds = expiresAt,
                text = text,
            )
            val envelope = MessagingEnvelope(
                senderIdentityId = OWNER.copyOf(),
                recipientIdentityId = peer.copyOf(),
                messageId = id.copyOf(),
                ciphertext = byteArrayOf(1, 2, 3),
                expiresAtEpochSeconds = expiresAt,
            )
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = peer.copyOf(),
                messageId = id,
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                encodedPlaintext = MessagingWire.encodePlaintext(plaintext),
                encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
            )
        }

        private fun messageId(index: Int): ByteArray = ByteArray(MESSAGING_MESSAGE_ID_BYTES).also {
            it[0] = ((index ushr 24) and 0xff).toByte()
            it[1] = ((index ushr 16) and 0xff).toByte()
            it[2] = ((index ushr 8) and 0xff).toByte()
            it[3] = (index and 0xff).toByte()
            if (it.all { value -> value == 0.toByte() }) it[0] = 1
        }

        private fun base64(value: ByteArray): String = BASE64.encodeToString(value)

        private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
    }
}
