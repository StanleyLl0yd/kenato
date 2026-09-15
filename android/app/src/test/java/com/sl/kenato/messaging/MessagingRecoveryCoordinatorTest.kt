package com.sl.kenato.messaging

import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingRecoveryCoordinatorTest {
    @Test
    fun restartImportsInboundBeforeAckAndRemovesSessionHandoff() {
        val fixture = Fixture()
        val inbound = inboundHandoff(1)
        fixture.sessions.handoffs += inbound

        val plan = fixture.coordinator.recover(OWNER)

        assertEquals(1, fixture.historyStore.writeCount)
        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertTrue(plan.outboundSends.isEmpty())
        assertEquals(1, plan.inboundAcks.size)
        assertArrayEquals(PEER, plan.inboundAcks.single().peerIdentityId)
        assertArrayEquals(inbound.messageId, plan.inboundAcks.single().messageId)
        assertEquals(1, fixture.history.pendingInboundAcks(OWNER).size)
    }

    @Test
    fun failedInboundHistoryWriteLeavesHandoffAndProducesNoAck() {
        val fixture = Fixture()
        val inbound = inboundHandoff(1)
        fixture.sessions.handoffs += inbound
        fixture.historyStore.failWrites = true

        assertThrows(ConversationHistoryException::class.java) {
            fixture.coordinator.recover(OWNER)
        }

        assertEquals(1, fixture.sessions.handoffs.size)
        assertTrue(fixture.sessions.completions.isEmpty())
    }

    @Test
    fun crashAfterInboundHistoryWriteReimportsIdempotentlyThenCompletes() {
        val fixture = Fixture()
        val inbound = inboundHandoff(1)
        fixture.history.importInboundPendingAck(OWNER, inbound)
        fixture.sessions.handoffs += inbound

        val plan = fixture.coordinator.recover(OWNER)

        assertEquals(1, fixture.historyStore.writeCount)
        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertEquals(1, plan.inboundAcks.size)
    }

    @Test
    fun restartReturnsExactStagedOutboundEnvelopeWithoutReEncryption() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2, ciphertext = "exact-staged-ciphertext".toByteArray())
        fixture.sessions.handoffs += outbound

        val first = fixture.coordinator.recover(OWNER)
        val second = fixture.coordinator.recover(OWNER)

        assertEquals(1, fixture.historyStore.writeCount)
        assertEquals(1, fixture.sessions.handoffs.size)
        assertEquals(1, first.outboundSends.size)
        assertEquals(1, second.outboundSends.size)
        assertArrayEquals(outbound.encodedEnvelope, first.outboundSends.single().encodedEnvelope)
        assertArrayEquals(outbound.encodedEnvelope, second.outboundSends.single().encodedEnvelope)
    }

    @Test
    fun expiredOutboundIsPersistedBeforeStagedHandoffRemoval() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2)
        fixture.sessions.handoffs += outbound
        val plan = fixture.coordinator.recover(OWNER)
        assertEquals(1, plan.outboundSends.size)
        fixture.sessions.beforeComplete = {
            assertEquals(
                ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED,
                fixture.history.currentState(OWNER)!!.messages.single().deliveryState,
            )
        }

        val expired = fixture.coordinator.expireOutboundIfDue(
            OWNER,
            PEER,
            outbound.messageId,
            nowEpochSeconds = 200,
        )

        assertTrue(expired)
        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertEquals(2, fixture.historyStore.writeCount)
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED,
            fixture.history.currentState(OWNER)!!.messages.single().deliveryState,
        )
    }

    @Test
    fun failedExpiryWriteRetainsStagedHandoffAndPendingHistory() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2)
        fixture.sessions.handoffs += outbound
        fixture.coordinator.recover(OWNER)
        fixture.historyStore.failWrites = true

        assertThrows(ConversationHistoryException::class.java) {
            fixture.coordinator.expireOutboundIfDue(
                OWNER,
                PEER,
                outbound.messageId,
                nowEpochSeconds = 200,
            )
        }

        fixture.historyStore.failWrites = false
        assertEquals(1, fixture.sessions.handoffs.size)
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE,
            fixture.history.currentState(OWNER)!!.messages.single().deliveryState,
        )
    }

    @Test
    fun crashAfterExpiredHistoryIsRecoveredWithoutResend() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2)
        fixture.sessions.handoffs += outbound
        fixture.coordinator.recover(OWNER)
        fixture.history.expireOutboundIfDue(OWNER, PEER, outbound.messageId, nowEpochSeconds = 200)

        val recovered = fixture.coordinator.recover(OWNER)

        assertTrue(recovered.outboundSends.isEmpty())
        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED,
            fixture.history.currentState(OWNER)!!.messages.single().deliveryState,
        )
    }

    @Test
    fun unexpiredOutboundRemainsRecoverableForExactSend() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2)
        fixture.sessions.handoffs += outbound
        fixture.coordinator.recover(OWNER)

        val expired = fixture.coordinator.expireOutboundIfDue(
            OWNER,
            PEER,
            outbound.messageId,
            nowEpochSeconds = 199,
        )

        assertFalse(expired)
        assertEquals(1, fixture.sessions.handoffs.size)
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE,
            fixture.history.currentState(OWNER)!!.messages.single().deliveryState,
        )
    }

    @Test
    fun acceptedHistoryWithLeftoverHandoffIsCleanedWithoutResend() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2)
        fixture.history.importOutboundPendingAcceptance(OWNER, outbound)
        fixture.history.markOutboundAccepted(
            OWNER,
            MessagingSendAccepted(PEER.copyOf(), outbound.messageId.copyOf()),
        )
        fixture.sessions.handoffs += outbound

        val plan = fixture.coordinator.recover(OWNER)

        assertTrue(plan.outboundSends.isEmpty())
        assertTrue(fixture.sessions.handoffs.isEmpty())
        val state = fixture.history.currentState(OWNER)!!
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED, state.messages.single().deliveryState)
    }

    @Test
    fun sendAcceptedPersistsHistoryBeforeRemovingStagedEnvelope() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2)
        fixture.sessions.handoffs += outbound
        fixture.history.importOutboundPendingAcceptance(OWNER, outbound)
        fixture.sessions.beforeComplete = {
            val record = fixture.history.currentState(OWNER)!!.messages.single()
            assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED, record.deliveryState)
        }

        fixture.coordinator.recordSendAccepted(
            OWNER,
            MessagingSendAccepted(PEER.copyOf(), outbound.messageId.copyOf()),
        )

        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertEquals(2, fixture.historyStore.writeCount)
    }

    @Test
    fun crashWindowAfterAcceptedHistoryIsIdempotentlyRecoverable() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2)
        fixture.sessions.handoffs += outbound
        fixture.history.importOutboundPendingAcceptance(OWNER, outbound)
        fixture.sessions.failCompletions = true

        assertThrows(MessagingRecoveryException::class.java) {
            fixture.coordinator.recordSendAccepted(
                OWNER,
                MessagingSendAccepted(PEER.copyOf(), outbound.messageId.copyOf()),
            )
        }
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED, fixture.history.currentState(OWNER)!!.messages.single().deliveryState)
        assertEquals(1, fixture.sessions.handoffs.size)

        fixture.sessions.failCompletions = false
        val recovered = fixture.coordinator.recover(OWNER)

        assertTrue(recovered.outboundSends.isEmpty())
        assertTrue(fixture.sessions.handoffs.isEmpty())
    }

    @Test
    fun repeatedAcceptedNotificationAfterCleanupIsIdempotent() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2)
        fixture.sessions.handoffs += outbound
        fixture.history.importOutboundPendingAcceptance(OWNER, outbound)
        val accepted = MessagingSendAccepted(PEER.copyOf(), outbound.messageId.copyOf())

        fixture.coordinator.recordSendAccepted(OWNER, accepted)
        fixture.coordinator.recordSendAccepted(OWNER, accepted)

        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertEquals(2, fixture.historyStore.writeCount)
    }

    @Test
    fun pendingOutboundHistoryWithoutStagedEnvelopeFailsClosed() {
        val fixture = Fixture()
        val outbound = outboundHandoff(2)
        fixture.history.importOutboundPendingAcceptance(OWNER, outbound)

        assertThrows(MessagingRecoveryException::class.java) {
            fixture.coordinator.recover(OWNER)
        }
    }

    @Test
    fun conflictingRecoveredOutboundEnvelopeFailsClosed() {
        val fixture = Fixture()
        val original = outboundHandoff(2, ciphertext = "first".toByteArray())
        fixture.history.importOutboundPendingAcceptance(OWNER, original)
        fixture.sessions.handoffs += outboundHandoff(2, ciphertext = "second".toByteArray())

        assertThrows(ConversationHistoryException::class.java) {
            fixture.coordinator.recover(OWNER)
        }
        assertEquals(1, fixture.sessions.handoffs.size)
    }

    private class Fixture {
        val historyStore = FakeHistoryStore()
        val history = ConversationHistoryRepository(historyStore)
        val sessions = FakeSessionHandoffs()
        val coordinator = MessagingRecoveryCoordinator(sessions, history)
    }

    private class FakeHistoryStore : ConversationHistoryStore {
        private var value: ByteArray? = null
        var writeCount = 0
        var failWrites = false

        override fun read(): ByteArray? = value?.copyOf()

        override fun write(value: ByteArray): Boolean {
            if (failWrites) return false
            this.value = value.copyOf()
            writeCount++
            return true
        }

        override fun clear(): Boolean {
            value = null
            return true
        }
    }

    private class FakeSessionHandoffs : MessagingSessionHandoffRepository {
        val handoffs = ArrayList<SessionMessageHandoff>()
        val completions = ArrayList<String>()
        var failCompletions = false
        var beforeComplete: (() -> Unit)? = null

        override fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff> =
            handoffs.map(::copyHandoff)

        override fun completeMessageHandoff(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
            direction: Int,
        ): Boolean {
            beforeComplete?.invoke()
            if (failCompletions) return false
            val index = handoffs.indexOfFirst {
                it.direction == direction &&
                    it.peerIdentityId.contentEquals(peerIdentityId) &&
                    it.messageId.contentEquals(messageId)
            }
            if (index < 0) return false
            handoffs.removeAt(index)
            completions += "$direction:${messageId.joinToString("") { byte -> "%02x".format(byte) }}"
            return true
        }

        private fun copyHandoff(value: SessionMessageHandoff): SessionMessageHandoff = value.copy(
            localContactId = value.localContactId.copyOf(),
            peerIdentityId = value.peerIdentityId.copyOf(),
            messageId = value.messageId.copyOf(),
            encodedPlaintext = value.encodedPlaintext.copyOf(),
            encodedEnvelope = value.encodedEnvelope.copyOf(),
        )
    }

    companion object {
        private val OWNER = bytes(0x11, MESSAGING_IDENTITY_BYTES)
        private val PEER = bytes(0x22, MESSAGING_IDENTITY_BYTES)
        private val CONTACT = bytes(0x33, SessionStateCodec.LOCAL_CONTACT_ID_BYTES)

        private fun inboundHandoff(index: Int): SessionMessageHandoff = handoff(
            index = index,
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
            sender = PEER,
            recipient = OWNER,
        )

        private fun outboundHandoff(
            index: Int,
            ciphertext: ByteArray = "ciphertext-$index".toByteArray(),
        ): SessionMessageHandoff = handoff(
            index = index,
            direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
            sender = OWNER,
            recipient = PEER,
            ciphertext = ciphertext,
        )

        private fun handoff(
            index: Int,
            direction: Int,
            sender: ByteArray,
            recipient: ByteArray,
            ciphertext: ByteArray = "ciphertext-$index".toByteArray(),
        ): SessionMessageHandoff {
            val messageId = messageId(index)
            val plaintext = MessagingPlaintext(
                senderIdentityId = sender.copyOf(),
                recipientIdentityId = recipient.copyOf(),
                messageId = messageId.copyOf(),
                sentAtEpochSeconds = 100,
                expiresAtEpochSeconds = 200,
                text = "message-$index",
            )
            val envelope = MessagingEnvelope(
                senderIdentityId = sender.copyOf(),
                recipientIdentityId = recipient.copyOf(),
                messageId = messageId.copyOf(),
                ciphertext = ciphertext.copyOf(),
                expiresAtEpochSeconds = 200,
            )
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = PEER.copyOf(),
                messageId = messageId,
                direction = direction,
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

        private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
    }
}
