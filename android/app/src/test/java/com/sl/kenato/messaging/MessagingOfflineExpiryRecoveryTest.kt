package com.sl.kenato.messaging

import com.sl.kenato.session.NativeSessionMessage
import com.sl.kenato.session.SESSION_OLM_MESSAGE_NORMAL
import com.sl.kenato.session.SessionMessageCryptoContext
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingOfflineExpiryRecoveryTest {
    @Test
    fun expiredRecoveredQueueDoesNotBlockFreshOfflineStage() {
        val historyStore = MemoryHistoryStore()
        val history = ConversationHistoryRepository(historyStore, ConversationHistoryClock { 100 })
        val sessions = FakeOutboundSessions()
        val recovery = FakeOutboundRecovery()
        recovery.plan = MessagingRecoveryPlan(
            outboundSends = List(MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS) { index ->
                MessagingRecoveredSend(
                    peerIdentityId = PEER.copyOf(),
                    messageId = messageId(index + 1),
                    encodedEnvelope = byteArrayOf(1),
                )
            },
            inboundAcks = emptyList(),
        )
        recovery.terminalIds += recovery.plan.outboundSends.map { it.messageId.copyOf() }
        val clock = SingleUseClock(100)
        val sender = DurableMessagingOutboundSender(
            sessions = sessions,
            history = history,
            recovery = recovery,
            messageIds = MessagingMessageIdGenerator { messageId(10_000) },
            clock = clock,
        )

        val staged = sender.stageText(OWNER, PEER, "fresh", ttlSeconds = 60)

        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE, staged.deliveryState)
        assertEquals(MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS, recovery.expiryChecks.size)
        assertTrue(recovery.expiryChecks.all { it.nowEpochSeconds == 100L })
        assertEquals(1, sessions.stageCount)
        assertEquals(1, clock.calls)
    }

    @Test
    fun outboundStageUsesOneClockSnapshotAcrossNativeEncryption() {
        val history = ConversationHistoryRepository(MemoryHistoryStore(), ConversationHistoryClock { 100 })
        val sessions = FakeOutboundSessions()
        val clock = SingleUseClock(100)
        val sender = DurableMessagingOutboundSender(
            sessions = sessions,
            history = history,
            recovery = MessagingOutboundRecovery { MessagingRecoveryPlan(emptyList(), emptyList()) },
            messageIds = MessagingMessageIdGenerator { messageId(20_000) },
            clock = clock,
        )

        val record = sender.stageText(OWNER, PEER, "snapshot", ttlSeconds = 60)
        val handoff = requireNotNull(sessions.lastHandoff)
        val plaintext = MessagingWire.decodePlaintext(handoff.encodedPlaintext)
        val envelope = MessagingWire.decodeEnvelope(handoff.encodedEnvelope)

        assertEquals(1, clock.calls)
        assertEquals(100L, plaintext.sentAtEpochSeconds)
        assertEquals(160L, plaintext.expiresAtEpochSeconds)
        assertEquals(160L, envelope.expiresAtEpochSeconds)
        assertArrayEquals(record.messageId, envelope.messageId)
    }

    @Test
    fun staleExpiryPlanTreatsAlreadyAcceptedAndCleanedSendAsTerminal() {
        val fixture = RecoveryFixture()
        val outbound = outboundHandoff(1)
        fixture.sessions.handoffs += outbound
        val stalePlan = fixture.coordinator.recover(OWNER)
        assertEquals(1, stalePlan.outboundSends.size)

        fixture.coordinator.recordSendAccepted(
            OWNER,
            MessagingSendAccepted(PEER.copyOf(), outbound.messageId.copyOf()),
        )
        assertTrue(fixture.sessions.handoffs.isEmpty())

        val terminal = fixture.coordinator.expireOutboundIfDue(
            OWNER,
            PEER,
            stalePlan.outboundSends.single().messageId,
            nowEpochSeconds = 200,
        )

        assertTrue(terminal)
        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
            fixture.history.currentState(OWNER)!!.messages.single().deliveryState,
        )
    }

    @Test
    fun repeatedExpiryAfterCleanupIsIdempotentlyTerminal() {
        val fixture = RecoveryFixture()
        val outbound = outboundHandoff(2)
        fixture.sessions.handoffs += outbound
        fixture.coordinator.recover(OWNER)

        assertTrue(
            fixture.coordinator.expireOutboundIfDue(
                OWNER,
                PEER,
                outbound.messageId,
                nowEpochSeconds = 200,
            ),
        )
        assertTrue(fixture.sessions.handoffs.isEmpty())

        assertTrue(
            fixture.coordinator.expireOutboundIfDue(
                OWNER,
                PEER,
                outbound.messageId,
                nowEpochSeconds = 200,
            ),
        )
        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED,
            fixture.history.currentState(OWNER)!!.messages.single().deliveryState,
        )
    }

    private data class ExpiryCheck(
        val peerIdentityId: ByteArray,
        val messageId: ByteArray,
        val nowEpochSeconds: Long,
    )

    private class FakeOutboundRecovery : MessagingOutboundRecovery {
        var plan = MessagingRecoveryPlan(emptyList(), emptyList())
        val terminalIds = ArrayList<ByteArray>()
        val expiryChecks = ArrayList<ExpiryCheck>()

        override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan {
            assertArrayEquals(OWNER, ownerIdentityId)
            return plan
        }

        override fun expireOutboundIfDue(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
            nowEpochSeconds: Long,
        ): Boolean {
            assertArrayEquals(OWNER, ownerIdentityId)
            expiryChecks += ExpiryCheck(peerIdentityId.copyOf(), messageId.copyOf(), nowEpochSeconds)
            return terminalIds.any { it.contentEquals(messageId) }
        }
    }

    private class FakeOutboundSessions : MessagingOutboundSessionDriver {
        var stageCount = 0
        var lastHandoff: SessionMessageHandoff? = null

        override fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray {
            assertArrayEquals(OWNER, ownerIdentityId)
            assertArrayEquals(PEER, peerIdentityId)
            return CONTACT.copyOf()
        }

        override fun encryptAndStageMessageHandoff(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            encodedPlaintext: ByteArray,
            buildHandoff: (SessionMessageCryptoContext, NativeSessionMessage) -> SessionMessageHandoff,
        ): SessionMessageHandoff {
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
                    ciphertext = byteArrayOf(9, 8, 7),
                ),
            )
            assertArrayEquals(encodedPlaintext, handoff.encodedPlaintext)
            lastHandoff = copyHandoff(handoff)
            return copyHandoff(handoff)
        }
    }

    private class SingleUseClock(private val value: Long) : MessagingOutboundClock {
        var calls = 0

        override fun nowEpochSeconds(): Long {
            calls++
            if (calls > 1) throw AssertionError("outbound stage clock must be sampled once")
            return value
        }
    }

    private class RecoveryFixture {
        val store = MemoryHistoryStore()
        val history = ConversationHistoryRepository(store, ConversationHistoryClock { 100 })
        val sessions = FakeSessionHandoffs()
        val coordinator = MessagingRecoveryCoordinator(sessions, history)
    }

    private class FakeSessionHandoffs : MessagingSessionHandoffRepository {
        val handoffs = ArrayList<SessionMessageHandoff>()

        override fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff> =
            handoffs.map(::copyHandoff)

        override fun completeMessageHandoff(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
            direction: Int,
        ): Boolean {
            val index = handoffs.indexOfFirst {
                it.direction == direction &&
                    it.peerIdentityId.contentEquals(peerIdentityId) &&
                    it.messageId.contentEquals(messageId)
            }
            if (index < 0) return false
            handoffs.removeAt(index)
            return true
        }
    }

    private class MemoryHistoryStore : ConversationHistoryStore {
        private var value: ByteArray? = null

        override fun read(): ByteArray? = value?.copyOf()

        override fun write(value: ByteArray): Boolean {
            this.value = value.copyOf()
            return true
        }

        override fun clear(): Boolean {
            value = null
            return true
        }
    }

    companion object {
        private val OWNER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x11.toByte() }
        private val PEER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x22.toByte() }
        private val CONTACT = ByteArray(SessionStateCodec.LOCAL_CONTACT_ID_BYTES) { 0x33.toByte() }

        private fun outboundHandoff(index: Int): SessionMessageHandoff {
            val id = messageId(index)
            val plaintext = MessagingPlaintext(
                senderIdentityId = OWNER.copyOf(),
                recipientIdentityId = PEER.copyOf(),
                messageId = id.copyOf(),
                sentAtEpochSeconds = 100,
                expiresAtEpochSeconds = 200,
                text = "message-$index",
            )
            val envelope = MessagingEnvelope(
                senderIdentityId = OWNER.copyOf(),
                recipientIdentityId = PEER.copyOf(),
                messageId = id.copyOf(),
                ciphertext = "ciphertext-$index".toByteArray(),
                expiresAtEpochSeconds = 200,
            )
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = PEER.copyOf(),
                messageId = id,
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
    }
}
