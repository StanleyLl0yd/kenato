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
        assertTrue(
            fixture.repository.matchesAuthenticatedInboundEnvelope(
                OWNER,
                handoff.encodedEnvelope,
            ),
        )
        val restarted = fixture.newRepository()
        val pending = restarted.pendingInboundAcks(OWNER).single()
        assertArrayEquals(handoff.messageId, pending.messageId)
        assertArrayEquals(handoff.encodedPlaintext, pending.encodedPlaintext)
        assertTrue(
            restarted.matchesAuthenticatedInboundEnvelope(
                OWNER,
                handoff.encodedEnvelope,
            ),
        )
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
    fun authenticatedDuplicateMatchRequiresExactCanonicalEnvelope() {
        val fixture = Fixture()
        val original = handoff(1)
        fixture.repository.importInboundPendingAck(OWNER, original)

        assertTrue(
            fixture.repository.matchesAuthenticatedInboundEnvelope(
                OWNER,
                original.encodedEnvelope,
            ),
        )
        assertFalse(
            fixture.repository.matchesAuthenticatedInboundEnvelope(
                OWNER,
                handoff(1, ciphertext = "different-ciphertext".toByteArray()).encodedEnvelope,
            ),
        )
        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.matchesAuthenticatedInboundEnvelope(
                OWNER,
                original.encodedEnvelope + byteArrayOf(0x78, 0x01),
            )
        }
    }

    @Test
    fun outboundPendingAcceptanceIsDurableBeforeSend() {
        val fixture = Fixture()
        val handoff = outboundHandoff(2)

        val imported = fixture.repository.importOutboundPendingAcceptance(OWNER, handoff)

        assertEquals(1, fixture.store.writeCount)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE, imported.deliveryState)
        assertEquals(SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND, imported.direction)
        val pending = fixture.newRepository().pendingOutboundAcceptances(OWNER).single()
        assertArrayEquals(handoff.messageId, pending.messageId)
        assertArrayEquals(handoff.encodedPlaintext, pending.encodedPlaintext)
    }

    @Test
    fun identicalOutboundReimportIsIdempotent() {
        val fixture = Fixture()
        val handoff = outboundHandoff(2)

        fixture.repository.importOutboundPendingAcceptance(OWNER, handoff)
        val second = fixture.newRepository().importOutboundPendingAcceptance(OWNER, handoff)

        assertEquals(1, fixture.store.writeCount)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE, second.deliveryState)
        assertEquals(1, fixture.newRepository().currentState(OWNER)!!.messages.size)
    }

    @Test
    fun conflictingOutboundSameKeyPlaintextOrEnvelopeIsRejected() {
        val fixture = Fixture()
        fixture.repository.importOutboundPendingAcceptance(OWNER, outboundHandoff(2))

        assertThrows(ConversationHistoryException::class.java) {
            fixture.newRepository().importOutboundPendingAcceptance(
                OWNER,
                outboundHandoff(2, text = "different"),
            )
        }
        assertThrows(ConversationHistoryException::class.java) {
            fixture.newRepository().importOutboundPendingAcceptance(
                OWNER,
                outboundHandoff(2, ciphertext = "different-ciphertext".toByteArray()),
            )
        }
        assertEquals(1, fixture.store.writeCount)
    }

    @Test
    fun outboundExpiresAtExactBoundaryAndReimportPreservesTerminalState() {
        val fixture = Fixture()
        val handoff = outboundHandoff(2)
        fixture.repository.importOutboundPendingAcceptance(OWNER, handoff)

        fixture.now = 199
        val before = fixture.repository.expireOutboundIfDue(
            OWNER,
            PEER,
            handoff.messageId,
            nowEpochSeconds = fixture.now,
        )
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE, before.deliveryState)
        assertEquals(1, fixture.store.writeCount)

        fixture.now = 200
        val expired = fixture.repository.expireOutboundIfDue(
            OWNER,
            PEER,
            handoff.messageId,
            nowEpochSeconds = fixture.now,
        )
        val recovered = fixture.newRepository().importOutboundPendingAcceptance(OWNER, handoff)

        assertEquals(2, fixture.store.writeCount)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED, expired.deliveryState)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED, recovered.deliveryState)
        assertTrue(fixture.newRepository().pendingOutboundAcceptances(OWNER).isEmpty())
    }

    @Test
    fun failedExpiryWriteLeavesOutboundPending() {
        val fixture = Fixture()
        val handoff = outboundHandoff(2)
        fixture.repository.importOutboundPendingAcceptance(OWNER, handoff)
        fixture.now = 200
        fixture.store.failWrites = true

        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.expireOutboundIfDue(
                OWNER,
                PEER,
                handoff.messageId,
                nowEpochSeconds = fixture.now,
            )
        }

        fixture.store.failWrites = false
        assertEquals(1, fixture.store.writeCount)
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE,
            fixture.newRepository().pendingOutboundAcceptances(OWNER).single().deliveryState,
        )
    }

    @Test
    fun acceptedOutboundNeverTransitionsToExpired() {
        val fixture = Fixture()
        val handoff = outboundHandoff(2)
        fixture.repository.importOutboundPendingAcceptance(OWNER, handoff)
        fixture.repository.markOutboundAccepted(
            OWNER,
            MessagingSendAccepted(PEER.copyOf(), handoff.messageId.copyOf()),
        )
        fixture.now = 10_000

        val record = fixture.repository.expireOutboundIfDue(
            OWNER,
            PEER,
            handoff.messageId,
            nowEpochSeconds = fixture.now,
        )

        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED, record.deliveryState)
        assertEquals(2, fixture.store.writeCount)
    }

    @Test
    fun sendAcceptedIsDurableAndIdempotentBeforeStagedEnvelopeRemoval() {
        val fixture = Fixture()
        val handoff = outboundHandoff(2)
        fixture.repository.importOutboundPendingAcceptance(OWNER, handoff)
        val accepted = MessagingSendAccepted(PEER.copyOf(), handoff.messageId.copyOf())

        val first = fixture.repository.markOutboundAccepted(OWNER, accepted)
        val second = fixture.newRepository().markOutboundAccepted(OWNER, accepted)

        assertEquals(2, fixture.store.writeCount)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED, first.deliveryState)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED, second.deliveryState)
        assertTrue(fixture.newRepository().pendingOutboundAcceptances(OWNER).isEmpty())
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
            fixture.newRepository().currentState(OWNER)!!.messages.single().deliveryState,
        )
    }

    @Test
    fun acceptedOutboundReimportPreservesAcceptanceAcrossCrashWindow() {
        val fixture = Fixture()
        val handoff = outboundHandoff(2)
        fixture.repository.importOutboundPendingAcceptance(OWNER, handoff)
        fixture.repository.markOutboundAccepted(
            OWNER,
            MessagingSendAccepted(PEER.copyOf(), handoff.messageId.copyOf()),
        )

        val recovered = fixture.newRepository().importOutboundPendingAcceptance(OWNER, handoff)

        assertEquals(2, fixture.store.writeCount)
        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED, recovered.deliveryState)
        assertTrue(fixture.newRepository().pendingOutboundAcceptances(OWNER).isEmpty())
    }

    @Test
    fun failedAcceptanceWriteLeavesOutboundPending() {
        val fixture = Fixture()
        val handoff = outboundHandoff(2)
        fixture.repository.importOutboundPendingAcceptance(OWNER, handoff)
        fixture.store.failWrites = true

        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.markOutboundAccepted(
                OWNER,
                MessagingSendAccepted(PEER.copyOf(), handoff.messageId.copyOf()),
            )
        }

        fixture.store.failWrites = false
        assertEquals(1, fixture.store.writeCount)
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE,
            fixture.newRepository().pendingOutboundAcceptances(OWNER).single().deliveryState,
        )
    }

    @Test
    fun unknownOrMalformedSendAcceptedFailsClosed() {
        val fixture = Fixture()
        val handoff = outboundHandoff(2)
        fixture.repository.importOutboundPendingAcceptance(OWNER, handoff)

        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.markOutboundAccepted(
                OWNER,
                MessagingSendAccepted(bytes(0x44, MESSAGING_IDENTITY_BYTES), handoff.messageId.copyOf()),
            )
        }
        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.markOutboundAccepted(
                OWNER,
                MessagingSendAccepted(PEER.copyOf(), handoff.messageId.copyOf(), protocolVersion = 2),
            )
        }
        assertEquals(1, fixture.store.writeCount)
        assertEquals(1, fixture.repository.pendingOutboundAcceptances(OWNER).size)
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
        val outbound = outboundHandoff(2)
        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.importOutboundPendingAcceptance(
                OWNER,
                outbound.copy(encodedEnvelope = outbound.encodedEnvelope + byteArrayOf(0x78, 0x01)),
            )
        }
        assertEquals(0, fixture.store.writeCount)
    }

    @Test
    fun handoffDirectionsCannotEnterTheWrongHistoryState() {
        val fixture = Fixture()

        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.importInboundPendingAck(OWNER, outboundHandoff(2))
        }
        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.importOutboundPendingAcceptance(OWNER, handoff(1))
        }
        assertEquals(0, fixture.store.writeCount)
    }

    @Test
    fun failedHistoryWriteDoesNotPublishPendingAck() {
        val fixture = Fixture()
        fixture.store.failWrites = true
        val handoff = handoff(1)

        assertThrows(ConversationHistoryException::class.java) {
            fixture.repository.importInboundPendingAck(OWNER, handoff)
        }

        assertEquals(0, fixture.store.writeCount)
        assertEquals(null, fixture.repository.currentState(OWNER))
        assertFalse(
            fixture.repository.matchesAuthenticatedInboundEnvelope(
                OWNER,
                handoff.encodedEnvelope,
            ),
        )
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
        var now = 100L
        val repository = newRepository()

        fun newRepository(): ConversationHistoryRepository =
            ConversationHistoryRepository(store, ConversationHistoryClock { now })
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
        ): SessionMessageHandoff = handoff(
            index = index,
            text = text,
            ciphertext = ciphertext,
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
        )

        private fun outboundHandoff(
            index: Int,
            text: String = "message-$index",
            ciphertext: ByteArray = "ciphertext-$index".toByteArray(),
        ): SessionMessageHandoff = handoff(
            index = index,
            text = text,
            ciphertext = ciphertext,
            direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
        )

        private fun handoff(
            index: Int,
            text: String,
            ciphertext: ByteArray,
            direction: Int,
        ): SessionMessageHandoff {
            val messageId = messageId(index)
            val inbound = direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND
            val sender = if (inbound) PEER else OWNER
            val recipient = if (inbound) OWNER else PEER
            val plaintext = MessagingPlaintext(
                senderIdentityId = sender.copyOf(),
                recipientIdentityId = recipient.copyOf(),
                messageId = messageId.copyOf(),
                sentAtEpochSeconds = 100,
                expiresAtEpochSeconds = 200,
                text = text,
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
