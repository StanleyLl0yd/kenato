package com.sl.kenato.messaging

import com.sl.kenato.call.DurableVoiceSemanticEventRepository
import com.sl.kenato.call.VoiceInboundHandoffRecovery
import com.sl.kenato.call.VoiceInboundPersistenceFacade
import com.sl.kenato.call.VoiceSemanticEncryptedStore
import com.sl.kenato.call.VoiceSemanticClock
import com.sl.kenato.call.VoiceSemanticPayloadCipher
import com.sl.kenato.call.VoiceSignalKind
import com.sl.kenato.call.VoiceSignalPlaintext
import com.sl.kenato.call.VoiceSignalReplayJournal
import com.sl.kenato.call.VoiceSignalReplayStore
import com.sl.kenato.call.VoiceSignalingWire
import com.sl.kenato.session.SESSION_OLM_MESSAGE_NORMAL
import com.sl.kenato.session.SessionCiphertext
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageCryptoContext
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingTypedInboundDeliveryTest {
    @Test
    fun authenticatedVoiceStaysOutOfChatAndPersistsBothStoresBeforeAck() {
        val f = Fixture()
        val envelope = envelope(1)
        f.sessions.decryptedPlaintext = encodedVoice(envelope)
        f.sessions.beforeComplete = {
            assertEquals(1, f.encrypted.writes)
            assertEquals(1, f.replay.writes)
            assertEquals(1, f.recovery.pendingLiveAcknowledgements(OWNER, NOW).size)
            assertEquals(null, f.history.currentState(OWNER))
        }
        val ack = f.handler.handle(envelope, NOW)
        assertArrayEquals(envelope.messageId, ack.messageId)
        assertEquals(1, f.sessions.decryptCount)
        assertEquals(1, f.sessions.completeCount)
        assertTrue(f.sessions.staged.isEmpty())
        assertEquals(0, f.chat.writes)
        assertEquals(1, f.semantic.pendingLiveEvents(OWNER).size)
    }

    @Test
    fun exactVoiceRedeliveryAcksWithoutSecondRatchetDecrypt() {
        val f = Fixture()
        val envelope = envelope(2)
        f.sessions.decryptedPlaintext = encodedVoice(envelope)
        f.handler.handle(envelope, NOW)
        val semanticWrites = f.encrypted.writes
        val replayWrites = f.replay.writes
        f.sessions.missingSession = true
        val ack = f.handler.handle(envelope, NOW)
        assertArrayEquals(envelope.messageId, ack.messageId)
        assertEquals(1, f.sessions.decryptCount)
        assertEquals(semanticWrites, f.encrypted.writes)
        assertEquals(replayWrites, f.replay.writes)
    }

    @Test
    fun changedCiphertextWithSameVoiceMessageIdFailsBeforeRatchet() {
        val f = Fixture()
        val original = envelope(3)
        f.sessions.decryptedPlaintext = encodedVoice(original)
        f.handler.handle(original, NOW)
        assertThrows(IllegalStateException::class.java) {
            f.handler.handle(envelope(3, olmMessage = byteArrayOf(9, 8, 7)), NOW)
        }
        assertEquals(1, f.sessions.decryptCount)
    }

    @Test
    fun missingOrTamperedEncryptedVoiceEventNeverAuthorizesDuplicateAck() {
        val f = Fixture()
        val original = envelope(4)
        f.sessions.decryptedPlaintext = encodedVoice(original)
        f.handler.handle(original, NOW)
        f.encrypted.bytes = f.encrypted.bytes!!.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        assertThrows(IllegalStateException::class.java) { f.handler.handle(original, NOW) }
        assertEquals(1, f.sessions.decryptCount)
    }

    @Test
    fun semanticWriteFailureRetainsAtomicM3HandoffWithoutAckOrReplayReceipt() {
        val f = Fixture()
        val env = envelope(5)
        f.sessions.decryptedPlaintext = encodedVoice(env)
        f.encrypted.failWrites = true
        assertThrows(IllegalStateException::class.java) { f.handler.handle(env, NOW) }
        assertEquals(1, f.sessions.staged.size)
        assertEquals(0, f.sessions.completeCount)
        assertEquals(0, f.replay.writes)
        assertEquals(0, f.chat.writes)
    }

    @Test
    fun replayWriteFailureLeavesSemanticEventButNoAckAndRequiresM3Recovery() {
        val f = Fixture()
        val env = envelope(6)
        f.sessions.decryptedPlaintext = encodedVoice(env)
        f.replay.failWrites = true
        assertThrows(IllegalStateException::class.java) { f.handler.handle(env, NOW) }
        assertEquals(1, f.sessions.staged.size)
        assertEquals(0, f.sessions.completeCount)
        assertEquals(1, f.encrypted.writes)
        assertEquals(0, f.replay.writes)
        assertThrows(IllegalStateException::class.java) { f.handler.handle(env, NOW) }
        assertEquals(1, f.sessions.decryptCount)
    }

    @Test
    fun typedOptInPreservesRegularChatAndRejectsCrossTypeIdCollisions() {
        val f = Fixture()
        val text = envelope(7)
        f.sessions.decryptedPlaintext = MessagingWire.encodePlaintext(
            MessagingPlaintext(
                senderIdentityId = PEER, recipientIdentityId = OWNER,
                messageId = text.messageId, sentAtEpochSeconds = NOW,
                expiresAtEpochSeconds = NOW + 60, text = "chat",
            ),
        )
        f.handler.handle(text, NOW)
        assertEquals(1, f.chat.writes)
        assertEquals(0, f.encrypted.writes)
        assertThrows(MessagingInboundDeliveryException::class.java) {
            f.handler.handle(envelope(7, olmMessage = byteArrayOf(9, 9)), NOW)
        }
        assertEquals(1, f.sessions.decryptCount)

        val second = Fixture()
        val offer = envelope(8)
        second.sessions.decryptedPlaintext = encodedVoice(offer)
        second.handler.handle(offer, NOW)
        assertThrows(IllegalStateException::class.java) {
            second.handler.handle(envelope(8, olmMessage = byteArrayOf(9)), NOW)
        }
        assertEquals(null, second.history.currentState(OWNER))
    }

    @Test
    fun unknownApplicationVersionAndLegacyTextHandlerFailClosed() {
        val f = Fixture()
        val env = envelope(9)
        f.sessions.decryptedPlaintext = byteArrayOf(0x08, 0x03)
        assertThrows(IllegalStateException::class.java) { f.handler.handle(env, NOW) }
        assertTrue(f.sessions.staged.isEmpty())
        assertEquals(0, f.encrypted.writes)
        assertEquals(0, f.chat.writes)
        val legacy = Fixture()
        legacy.sessions.decryptedPlaintext = encodedVoice(env)
        assertThrows(MessagingInboundDeliveryException::class.java) {
            DurableMessagingInboundDeliveryHandler(legacy.sessions, legacy.history).handle(env, NOW)
        }
        assertTrue(legacy.sessions.staged.isEmpty())
    }

    private class Fixture {
        val chat = MemoryChatStore()
        val history = ConversationHistoryRepository(chat)
        val replay = MemoryReplayStore()
        val encrypted = MemoryEncryptedStore()
        val semantic = DurableVoiceSemanticEventRepository(
            encrypted, TestAesGcm(), VoiceSemanticClock { NOW },
        )
        val recovery = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(replay))
        val voice = VoiceInboundPersistenceFacade(recovery, semantic)
        val sessions = FakeSessions()
        val handler = DurableMessagingInboundDeliveryHandler(sessions, history, voice)
    }

    private class MemoryChatStore : ConversationHistoryStore {
        var bytes: ByteArray? = null
        var writes = 0
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(value: ByteArray): Boolean {
            bytes = value.copyOf()
            writes++
            return true
        }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class MemoryReplayStore : VoiceSignalReplayStore {
        var bytes: ByteArray? = null
        var writes = 0
        var failWrites = false
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(bytes: ByteArray): Boolean {
            if (failWrites) return false
            this.bytes = bytes.copyOf()
            writes++
            return true
        }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class MemoryEncryptedStore : VoiceSemanticEncryptedStore {
        var bytes: ByteArray? = null
        var writes = 0
        var failWrites = false
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(value: ByteArray): Boolean {
            if (failWrites) return false
            bytes = value.copyOf()
            writes++
            return true
        }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class TestAesGcm : VoiceSemanticPayloadCipher {
        private val key = SecretKeySpec(ByteArray(32) { 0x22 }, "AES")
        private val random = SecureRandom()
        override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
            val iv = ByteArray(12).also(random::nextBytes)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            c.updateAAD(aad)
            return byteArrayOf(1) + iv + c.doFinal(plaintext)
        }
        override fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypted.copyOfRange(1, 13)))
            c.updateAAD(aad)
            return c.doFinal(encrypted.copyOfRange(13, encrypted.size))
        }
    }

    private class FakeSessions : MessagingInboundSessionDriver {
        var decryptCount = 0
        var completeCount = 0
        var missingSession = false
        var decryptedPlaintext = ByteArray(0)
        var beforeComplete: (() -> Unit)? = null
        val staged = ArrayList<SessionMessageHandoff>()

        override fun localContactIdForPeer(
            ownerIdentityId: ByteArray, peerIdentityId: ByteArray,
        ): ByteArray {
            if (missingSession) error("Session access on exact duplicate")
            assertArrayEquals(OWNER, ownerIdentityId)
            assertArrayEquals(PEER, peerIdentityId)
            return CONTACT.copyOf()
        }

        override fun decryptAndStageMessageHandoff(
            ownerIdentityId: ByteArray, localContactId: ByteArray,
            ciphertext: SessionCiphertext,
            buildHandoff: (SessionMessageCryptoContext, ByteArray) -> SessionMessageHandoff,
        ): SessionMessageHandoff {
            decryptCount++
            val built = buildHandoff(
                SessionMessageCryptoContext(
                    ownerIdentityId = OWNER.copyOf(),
                    localContactId = CONTACT.copyOf(),
                    peerIdentityId = PEER.copyOf(),
                    localAccountGeneration = 7L,
                    peerAccountGeneration = 8L,
                ),
                decryptedPlaintext.copyOf(),
            )
            staged += built
            return built
        }

        override fun completeInboundMessageHandoff(
            ownerIdentityId: ByteArray, peerIdentityId: ByteArray, messageId: ByteArray,
        ): Boolean {
            beforeComplete?.invoke()
            completeCount++
            return staged.removeAll {
                it.peerIdentityId.contentEquals(peerIdentityId) &&
                    it.messageId.contentEquals(messageId)
            }
        }
    }

    private companion object {
        const val NOW = 1_780_000_000L
        val OWNER = ByteArray(32) { 1 }
        val PEER = ByteArray(32) { 2 }
        val CONTACT = ByteArray(SessionStateCodec.LOCAL_CONTACT_ID_BYTES) { 3 }

        fun id(n: Int) = ByteArray(16).also {
            it[0] = (n and 255).toByte()
            it[1] = ((n ushr 8) and 255).toByte()
        }

        fun envelope(
            message: Int,
            olmMessage: ByteArray = byteArrayOf(1, 2, 3),
        ): MessagingEnvelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = id(message),
            expiresAtEpochSeconds = NOW + 60,
            ciphertext = SessionCiphertextWire.encode(
                SessionCiphertext(
                    senderIdentityId = PEER.copyOf(),
                    recipientIdentityId = OWNER.copyOf(),
                    senderAccountGeneration = 8L,
                    recipientAccountGeneration = 7L,
                    olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
                    olmMessage = olmMessage.copyOf(),
                ),
            ),
        )

        fun encodedVoice(envelope: MessagingEnvelope): ByteArray =
            VoiceSignalingWire.encode(
                VoiceSignalPlaintext(
                    senderIdentityId = PEER.copyOf(),
                    recipientIdentityId = OWNER.copyOf(),
                    messageId = envelope.messageId.copyOf(),
                    callId = id(77),
                    sentAtEpochSeconds = NOW,
                    expiresAtEpochSeconds = envelope.expiresAtEpochSeconds,
                    kind = VoiceSignalKind.OFFER,
                    payload = "v=0\r\n".toByteArray(),
                ),
            )
    }
}
