package com.sl.kenato.messaging

import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingOutboundRecoveryIsolationTest {
    @Test
    fun outboundOnlyRecoveryLeavesInboundHandoffAndAckStateUntouched() {
        val store = MemoryHistoryStore()
        val history = ConversationHistoryRepository(store, ConversationHistoryClock { 100 })
        val sessions = FakeSessionHandoffs().also {
            it.handoffs += inboundHandoff(1)
            it.handoffs += outboundHandoff(2)
        }
        val coordinator = MessagingRecoveryCoordinator(sessions, history)
        val recovery = CoordinatorMessagingOutboundRecovery(coordinator)

        val plan = recovery.recover(OWNER)

        assertEquals(1, plan.outboundSends.size)
        assertArrayEquals(messageId(2), plan.outboundSends.single().messageId)
        assertTrue(plan.inboundAcks.isEmpty())
        assertTrue(history.pendingInboundAcks(OWNER).isEmpty())
        assertEquals(1, history.pendingOutboundAcceptances(OWNER).size)
        assertEquals(2, sessions.handoffs.size)
        assertTrue(
            sessions.handoffs.any {
                it.direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND &&
                    it.messageId.contentEquals(messageId(1))
            },
        )
        assertTrue(sessions.completions.isEmpty())
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

    private class FakeSessionHandoffs : MessagingSessionHandoffRepository {
        val handoffs = ArrayList<SessionMessageHandoff>()
        val completions = ArrayList<Int>()

        override fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff> =
            handoffs.map(::copyHandoff)

        override fun completeMessageHandoff(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
            direction: Int,
        ): Boolean {
            completions += direction
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

        private fun outboundHandoff(index: Int): SessionMessageHandoff = handoff(
            index = index,
            direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
            sender = OWNER,
            recipient = PEER,
        )

        private fun handoff(
            index: Int,
            direction: Int,
            sender: ByteArray,
            recipient: ByteArray,
        ): SessionMessageHandoff {
            val id = messageId(index)
            val plaintext = MessagingPlaintext(
                senderIdentityId = sender.copyOf(),
                recipientIdentityId = recipient.copyOf(),
                messageId = id.copyOf(),
                sentAtEpochSeconds = 100,
                expiresAtEpochSeconds = 200,
                text = "message-$index",
            )
            val envelope = MessagingEnvelope(
                senderIdentityId = sender.copyOf(),
                recipientIdentityId = recipient.copyOf(),
                messageId = id.copyOf(),
                ciphertext = "ciphertext-$index".toByteArray(),
                expiresAtEpochSeconds = 200,
            )
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = PEER.copyOf(),
                messageId = id,
                direction = direction,
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
