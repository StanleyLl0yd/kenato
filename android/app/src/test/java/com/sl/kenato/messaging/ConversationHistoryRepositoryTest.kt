package com.sl.kenato.messaging

import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ConversationHistoryRepositoryTest {
    @Test
    fun inboundPendingAckIsDurableBeforeBecomingAckEligible() {
        val fixture = Fixture()
        val handoff = handoff(1)

        val imported = fixture.repository.importInboundPendingAck(OWNER, handoff)

        assertEquals(1, fixture.store.writeCount)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK, imported.deliveryState)
        assertTrue(fixture.repository.containsAuthenticatedInbound(OWNER, PEER, handoff.messageId))
        val restarted = fixture.newRepository()
        val pending = restarted.pendingInboundAcks(OWNER).single()
        assertArrayEquals(handoff.messageId, pending.messageId)
        assertArrayEquals(handoff.encodedPlaintext, pending.encodedPlaintext)
        assertTrue(restarted.containsAuthenticatedInbound(OWNER, PEER, handoff.messageId))
    }

    @Test
    fun identicalInboundReimportIsIdempotent() {
        val fixture = Fixture()
        val handoff = handoff(1)

        fixture.repository.importInboundPendingAck(OWNER, handoff)
        val second = fixture.newRepository().importInboundPendingAck(OWNER, handoff)

        assertEquals(1, fixture.store.writeCount)
        assertEquals(1, fixture.newRepository().currentState(OWNER)!!.messages.size)
        assertArrayEquals(handoff.messageId, second.messageId)
    }

    @Test
    fun conflictingSameKeyPlaintextOrEnvelopeIsRejected() {
        val fixture = Fixture()
        fixture.repository.importInboundPendingAck(OWNER, handoff(1))

        assertThrows(ConversationHistoryException::class.java) {
            fixture.newRepository().importInboundPendingAck(
                OWNER,
                handoff(1, text = "different"),
            )
        }
        assertThrows(ConversationHistoryException::class.java) {
            fixture.newRepository().importInboundPendingAck(
                OWNER,
                handoff(1, ciphertext = "different-ciphertext".toByteArray()),
            )
        }
        assertEquals(1, fixture.store.writeCount)
        assertEquals(1, fixture.newRepository().currentState(OWNER)!!.messages.size)
    }

    @Test
    fun persistedOwnerIdentityMismatchFailsClosed() {
        val fixture = Fixture()
        fixture.repository.importInboundPendingAck(OWNER, handoff(1))

        assertThrows(ConversationHistoryException::class.java) {
            fixture.newRepository().currentState(bytes(0x44, MESSAGING_IDENTITY_BYTES))
        }
    }

    @Test
    fun nonCanonicalPlaintextAndEnvelopeAreRejected() {
        val fixture = Fixture()
        val canonical = handoff(1)

        val plaintextWithUnknownField = canonical.copy(
            encodedPlaintext = canonical.encodedPlaintext + byteArrayOf(0x78, 0x01),
        )
        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.importInboundPendingAck(OWNER, plaintextWithUnknownField)
        }

        val envelopeWithUnknownField = canonical.copy(
            encodedEnvelope = canonical.encodedEnvelope + byteArrayOf(0x78, 0x01),
        )
        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.importInboundPendingAck(OWNER, envelopeWithUnknownField)
        }
        assertEquals(0, fixture.store.writeCount)
    }

    @Test
    fun outboundHandoffCannotEnterPendingAckHistory() {
        val fixture = Fixture()
        val outbound = handoff(1).copy(direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND)

        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.importInboundPendingAck(OWNER, outbound)
        }
        assertEquals(0, fixture.store.writeCount)
    }

    @Test
    fun failedHistoryWriteDoesNotPublishPendingAck() {
        val fixture = Fixture()
        fixture.store.failWrites = true

        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.importInboundPendingAck(OWNER, handoff(1))
        }

        assertEquals(0, fixture.store.writeCount)
        assertEquals(null, fixture.repository.currentState(OWNER))
        assertFalse(fixture.repository.containsAuthenticatedInbound(OWNER, PEER, messageId(1)))
    }

    @Test
    fun returnedRecordsDoNotAliasPersistedHistory() {
        val fixture = Fixture()
        val imported = fixture.repository.importInboundPendingAck(OWNER, handoff(1))
        imported.messageId[0] = 0x7f
        imported.encodedPlaintext[0] = 0x7f
        imported.envelopeDigest[0] = 0x7f

        val persisted = fixture.repository.pendingInboundAcks(OWNER).single()
        assertArrayEquals(messageId(1), persisted.messageId)
        assertArrayEquals(handoff(1).encodedPlaintext, persisted.encodedPlaintext)
    }

    private class Fixture {
        val store = FakeHistoryStore()
        val repository = newRepository()

        fun newRepository(): ConversationHistoryRepository = ConversationHistoryRepository(store)
    }

    private class FakeHistoryStore : ConversationHistoryStore {
        var value: ByteArray? = null
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

    companion object {
        private val OWNER = bytes(0x11, MESSAGING_IDENTITY_BYTES)
        private val PEER = bytes(0x22, MESSAGING_IDENTITY_BYTES)
        private val CONTACT = bytes(0x33, SessionStateCodec.LOCAL_CONTACT_ID_BYTES)

        private fun handoff(
            index: Int,
            text: String = "message-$index",
            ciphertext: ByteArray = "ciphertext-$index".toByteArray(),
        ): SessionMessageHandoff {
            val messageId = messageId(index)
            val plaintext = MessagingPlaintext(
                senderIdentityId = PEER.copyOf(),
                recipientIdentityId = OWNER.copyOf(),
                messageId = messageId.copyOf(),
                sentAtEpochSeconds = 100,
                expiresAtEpochSeconds = 200,
                text = text,
            )
            val envelope = MessagingEnvelope(
                senderIdentityId = PEER.copyOf(),
                recipientIdentityId = OWNER.copyOf(),
                messageId = messageId.copyOf(),
                ciphertext = ciphertext.copyOf(),
                expiresAtEpochSeconds = 200,
            )
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = PEER.copyOf(),
                messageId = messageId,
                direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
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
