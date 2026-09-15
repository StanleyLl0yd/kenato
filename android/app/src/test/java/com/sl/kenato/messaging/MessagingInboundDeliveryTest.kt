package com.sl.kenato.messaging

import com.sl.kenato.session.SESSION_OLM_MESSAGE_NORMAL
import com.sl.kenato.session.SessionCiphertext
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageCryptoContext
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingInboundDeliveryTest {
    @Test
    fun exactDurableDuplicateAcksWithoutSessionLookupOrDecrypt() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(1)
        fixture.persistHistory(envelope)
        fixture.sessions.missingSession = true

        val ack = fixture.handle(envelope)

        assertArrayEquals(PEER, ack.senderIdentityId)
        assertArrayEquals(envelope.messageId, ack.messageId)
        assertEquals(0, fixture.sessions.resolveCount)
        assertEquals(0, fixture.sessions.decryptCount)
        assertEquals(1, fixture.historyStore.writeCount)
    }

    @Test
    fun changedCiphertextWithSameAuthenticatedMessageIdFailsBeforeDecrypt() {
        val fixture = Fixture()
        val original = inboundEnvelope(1, olmMessage = byteArrayOf(1, 2, 3))
        fixture.persistHistory(original)
        val changed = inboundEnvelope(1, olmMessage = byteArrayOf(9, 8, 7))

        assertThrows(MessagingInboundDeliveryException::class.java) {
            fixture.handle(changed)
        }

        assertEquals(0, fixture.sessions.resolveCount)
        assertEquals(0, fixture.sessions.decryptCount)
        assertEquals(1, fixture.historyStore.writeCount)
    }

    @Test
    fun firstDeliveryPersistsHistoryBeforeRemovingAtomicSessionHandoffAndAcking() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(2)
        fixture.sessions.decryptedPlaintext = encodedPlaintext(envelope)
        fixture.sessions.beforeComplete = {
            assertEquals(1, fixture.historyStore.writeCount)
            val pending = fixture.history.pendingInboundAcks(OWNER)
            assertEquals(1, pending.size)
            assertArrayEquals(envelope.messageId, pending.single().messageId)
        }

        val ack = fixture.handle(envelope)

        assertArrayEquals(PEER, ack.senderIdentityId)
        assertArrayEquals(envelope.messageId, ack.messageId)
        assertEquals(1, fixture.sessions.resolveCount)
        assertEquals(1, fixture.sessions.decryptCount)
        assertEquals(1, fixture.sessions.completeCount)
        assertTrue(fixture.sessions.staged.isEmpty())
        assertEquals(1, fixture.historyStore.writeCount)
        val pending = fixture.history.pendingInboundAcks(OWNER)
        assertEquals(1, pending.size)
        assertArrayEquals(CONTACT, pending.single().localContactId)
        assertArrayEquals(PEER, pending.single().peerIdentityId)
    }

    @Test
    fun receiveTimeSnapshotRemainsValidThroughPostDecryptContextCheck() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(11)
        fixture.sessions.decryptedPlaintext = encodedPlaintext(envelope)

        val ack = fixture.handle(envelope, receivedAtEpochSeconds = 199)

        assertArrayEquals(envelope.messageId, ack.messageId)
        assertEquals(1, fixture.sessions.decryptCount)
        assertEquals(1, fixture.history.pendingInboundAcks(OWNER).size)
    }

    @Test
    fun exactExpiryBoundaryFailsBeforeSessionLookupOrDecrypt() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(12)
        fixture.sessions.decryptedPlaintext = encodedPlaintext(envelope)

        assertThrows(MessagingProtocolException::class.java) {
            fixture.handle(envelope, receivedAtEpochSeconds = 200)
        }

        assertEquals(0, fixture.sessions.resolveCount)
        assertEquals(0, fixture.sessions.decryptCount)
        assertEquals(0, fixture.historyStore.writeCount)
    }

    @Test
    fun failedHistoryWriteLeavesAtomicHandoffAndProducesNoAck() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(3)
        fixture.sessions.decryptedPlaintext = encodedPlaintext(envelope)
        fixture.historyStore.failWrites = true

        assertThrows(ConversationHistoryException::class.java) {
            fixture.handle(envelope)
        }

        assertEquals(1, fixture.sessions.decryptCount)
        assertEquals(0, fixture.sessions.completeCount)
        assertEquals(1, fixture.sessions.staged.size)
        assertTrue(fixture.history.currentState(OWNER) == null)
    }

    @Test
    fun cleanupFailureAfterHistoryCommitMakesRetryAckWithoutSecondDecrypt() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(4)
        fixture.sessions.decryptedPlaintext = encodedPlaintext(envelope)
        fixture.sessions.failComplete = true

        assertThrows(MessagingInboundDeliveryException::class.java) {
            fixture.handle(envelope)
        }
        assertEquals(1, fixture.sessions.decryptCount)
        assertEquals(1, fixture.sessions.staged.size)
        assertEquals(1, fixture.history.pendingInboundAcks(OWNER).size)

        val ack = fixture.handle(envelope)

        assertArrayEquals(envelope.messageId, ack.messageId)
        assertEquals(1, fixture.sessions.decryptCount)
        assertEquals(1, fixture.sessions.resolveCount)
        assertEquals(1, fixture.sessions.staged.size)
    }

    @Test
    fun missingPinnedSessionFailsBeforeDecryptAndHistoryWrite() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(5)
        fixture.sessions.missingSession = true

        assertThrows(MessagingInboundDeliveryException::class.java) {
            fixture.handle(envelope)
        }

        assertEquals(1, fixture.sessions.resolveCount)
        assertEquals(0, fixture.sessions.decryptCount)
        assertEquals(0, fixture.historyStore.writeCount)
    }

    @Test
    fun ciphertextIdentityRewriteFailsBeforeSessionLookupOrNativeDecrypt() {
        val fixture = Fixture()
        val wrongCiphertext = SessionCiphertextWire.encode(
            SessionCiphertext(
                senderIdentityId = OTHER.copyOf(),
                recipientIdentityId = OWNER.copyOf(),
                senderAccountGeneration = PEER_GENERATION,
                recipientAccountGeneration = OWNER_GENERATION,
                olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
                olmMessage = byteArrayOf(1, 2, 3),
            ),
        )
        val envelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = messageId(6),
            ciphertext = wrongCiphertext,
            expiresAtEpochSeconds = 200,
        )

        assertThrows(MessagingInboundDeliveryException::class.java) {
            fixture.handle(envelope)
        }

        assertEquals(0, fixture.sessions.resolveCount)
        assertEquals(0, fixture.sessions.decryptCount)
        assertEquals(0, fixture.historyStore.writeCount)
    }

    @Test
    fun innerOuterContextMismatchDoesNotStageRatchetHandoff() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(7)
        fixture.sessions.decryptedPlaintext = MessagingWire.encodePlaintext(
            plaintextFor(envelope).copy(messageId = messageId(99)),
        )

        assertThrows(MessagingProtocolException::class.java) {
            fixture.handle(envelope)
        }

        assertEquals(1, fixture.sessions.decryptCount)
        assertTrue(fixture.sessions.staged.isEmpty())
        assertEquals(0, fixture.sessions.completeCount)
        assertEquals(0, fixture.historyStore.writeCount)
    }

    @Test
    fun nonCanonicalDecryptedPlaintextDoesNotStageRatchetHandoff() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(8)
        fixture.sessions.decryptedPlaintext = encodedPlaintext(envelope) + byteArrayOf(0x78, 0x01)

        assertThrows(MessagingInboundDeliveryException::class.java) {
            fixture.handle(envelope)
        }

        assertEquals(1, fixture.sessions.decryptCount)
        assertTrue(fixture.sessions.staged.isEmpty())
        assertEquals(0, fixture.historyStore.writeCount)
    }

    @Test
    fun malformedSessionCiphertextFailsBeforeSessionLookupOrNativeDecrypt() {
        val fixture = Fixture()
        val envelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = messageId(9),
            ciphertext = byteArrayOf(0x01),
            expiresAtEpochSeconds = 200,
        )

        assertThrows(MessagingInboundDeliveryException::class.java) {
            fixture.handle(envelope)
        }

        assertEquals(0, fixture.sessions.resolveCount)
        assertEquals(0, fixture.sessions.decryptCount)
        assertEquals(0, fixture.historyStore.writeCount)
    }

    @Test
    fun sessionCryptoContextSubstitutionDoesNotStageHandoff() {
        val fixture = Fixture()
        val envelope = inboundEnvelope(10)
        fixture.sessions.decryptedPlaintext = encodedPlaintext(envelope)
        fixture.sessions.contextPeer = OTHER.copyOf()

        assertThrows(MessagingInboundDeliveryException::class.java) {
            fixture.handle(envelope)
        }

        assertEquals(1, fixture.sessions.decryptCount)
        assertTrue(fixture.sessions.staged.isEmpty())
        assertEquals(0, fixture.historyStore.writeCount)
    }

    private class Fixture {
        val historyStore = FakeHistoryStore()
        val history = ConversationHistoryRepository(historyStore)
        val sessions = FakeSessions()
        val handler = DurableMessagingInboundDeliveryHandler(
            sessions = sessions,
            history = history,
        )

        fun handle(
            envelope: MessagingEnvelope,
            receivedAtEpochSeconds: Long = 100,
        ): MessagingDeliveryAck = handler.handle(envelope, receivedAtEpochSeconds)

        fun persistHistory(envelope: MessagingEnvelope) {
            history.importInboundPendingAck(
                OWNER,
                SessionMessageHandoff(
                    localContactId = CONTACT.copyOf(),
                    peerIdentityId = envelope.senderIdentityId.copyOf(),
                    messageId = envelope.messageId.copyOf(),
                    direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
                    encodedPlaintext = encodedPlaintext(envelope),
                    encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
                ),
            )
        }
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

    private class FakeSessions : MessagingInboundSessionDriver {
        var resolveCount = 0
        var decryptCount = 0
        var completeCount = 0
        var missingSession = false
        var failComplete = false
        var decryptedPlaintext = ByteArray(0)
        var contextPeer = PEER.copyOf()
        var beforeComplete: (() -> Unit)? = null
        val staged = ArrayList<SessionMessageHandoff>()

        override fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray {
            resolveCount++
            if (missingSession) {
                throw MessagingInboundDeliveryException("missing session")
            }
            assertArrayEquals(OWNER, ownerIdentityId)
            assertArrayEquals(PEER, peerIdentityId)
            return CONTACT.copyOf()
        }

        override fun decryptAndStageMessageHandoff(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            ciphertext: SessionCiphertext,
            buildHandoff: (SessionMessageCryptoContext, ByteArray) -> SessionMessageHandoff,
        ): SessionMessageHandoff {
            decryptCount++
            assertArrayEquals(OWNER, ownerIdentityId)
            assertArrayEquals(CONTACT, localContactId)
            assertArrayEquals(PEER, ciphertext.senderIdentityId)
            assertArrayEquals(OWNER, ciphertext.recipientIdentityId)
            val handoff = buildHandoff(
                SessionMessageCryptoContext(
                    ownerIdentityId = OWNER.copyOf(),
                    localContactId = CONTACT.copyOf(),
                    peerIdentityId = contextPeer.copyOf(),
                    localAccountGeneration = OWNER_GENERATION,
                    peerAccountGeneration = PEER_GENERATION,
                ),
                decryptedPlaintext.copyOf(),
            )
            staged += handoff.copy(
                localContactId = handoff.localContactId.copyOf(),
                peerIdentityId = handoff.peerIdentityId.copyOf(),
                messageId = handoff.messageId.copyOf(),
                encodedPlaintext = handoff.encodedPlaintext.copyOf(),
                encodedEnvelope = handoff.encodedEnvelope.copyOf(),
            )
            return handoff
        }

        override fun completeInboundMessageHandoff(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
        ): Boolean {
            completeCount++
            beforeComplete?.invoke()
            if (failComplete) return false
            return staged.removeAll {
                it.peerIdentityId.contentEquals(peerIdentityId) && it.messageId.contentEquals(messageId)
            }
        }
    }

    companion object {
        private const val OWNER_GENERATION = 7L
        private const val PEER_GENERATION = 8L
        private val OWNER = bytes(0x11, MESSAGING_IDENTITY_BYTES)
        private val PEER = bytes(0x22, MESSAGING_IDENTITY_BYTES)
        private val OTHER = bytes(0x44, MESSAGING_IDENTITY_BYTES)
        private val CONTACT = bytes(0x33, SessionStateCodec.LOCAL_CONTACT_ID_BYTES)

        private fun inboundEnvelope(
            index: Int,
            olmMessage: ByteArray = byteArrayOf(1, 2, 3),
        ): MessagingEnvelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = messageId(index),
            ciphertext = SessionCiphertextWire.encode(
                SessionCiphertext(
                    senderIdentityId = PEER.copyOf(),
                    recipientIdentityId = OWNER.copyOf(),
                    senderAccountGeneration = PEER_GENERATION,
                    recipientAccountGeneration = OWNER_GENERATION,
                    olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
                    olmMessage = olmMessage.copyOf(),
                ),
            ),
            expiresAtEpochSeconds = 200,
        )

        private fun plaintextFor(envelope: MessagingEnvelope): MessagingPlaintext = MessagingPlaintext(
            senderIdentityId = envelope.senderIdentityId.copyOf(),
            recipientIdentityId = envelope.recipientIdentityId.copyOf(),
            messageId = envelope.messageId.copyOf(),
            sentAtEpochSeconds = 90,
            expiresAtEpochSeconds = envelope.expiresAtEpochSeconds,
            text = "hello",
        )

        private fun encodedPlaintext(envelope: MessagingEnvelope): ByteArray =
            MessagingWire.encodePlaintext(plaintextFor(envelope))

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
