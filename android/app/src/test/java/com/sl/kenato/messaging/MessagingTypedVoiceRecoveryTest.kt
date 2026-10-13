package com.sl.kenato.messaging

import com.sl.kenato.call.VoiceInboundHandoffRecovery
import com.sl.kenato.call.DurableVoiceSemanticEventRepository
import com.sl.kenato.call.VoiceInboundPersistenceFacade
import com.sl.kenato.call.VoiceSemanticClock
import com.sl.kenato.call.VoiceSemanticEncryptedStore
import com.sl.kenato.call.VoiceSemanticPayloadCipher
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import com.sl.kenato.call.VoiceSignalKind
import com.sl.kenato.call.VoiceSignalPlaintext
import com.sl.kenato.call.VoiceSignalReplayJournal
import com.sl.kenato.call.VoiceSignalReplayStore
import com.sl.kenato.call.VoiceSignalingWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import java.security.MessageDigest
import org.junit.Test

class MessagingTypedVoiceRecoveryTest {
    @Test
    fun voiceRestartDoesNotLeakIntoChatAndOnlyAcksAfterDurableReplayImport() {
        val f = Fixture()
        val inbound = voiceHandoff(11)
        f.sessions.handoffs += inbound
        f.sessions.beforeComplete = {
            assertEquals(1, f.semanticStore.writes)
            assertEquals(1, f.voiceStore.writes)
            assertEquals(1, f.voice.pendingLiveAcknowledgements(OWNER, NOW).size)
            assertEquals(null, f.history.currentState(OWNER))
        }
        val first = f.coordinator.recover(OWNER)
        assertTrue(f.sessions.handoffs.isEmpty())
        assertTrue(first.outboundSends.isEmpty())
        assertEquals(1, first.inboundAcks.size)
        assertArrayEquals(PEER, first.inboundAcks.single().peerIdentityId)
        assertArrayEquals(id(11), first.inboundAcks.single().messageId)

        val second = f.coordinator.recover(OWNER)
        assertEquals(1, second.inboundAcks.size)
        assertEquals(1, f.voiceStore.writes)
        assertEquals(null, f.history.currentState(OWNER))
    }

    @Test
    fun expiredVoiceIsRetiredWithoutACKOrChatHistory() {
        val f = Fixture(now = NOW + 60)
        f.sessions.handoffs += voiceHandoff(12)
        val recovered = f.coordinator.recover(OWNER)
        assertTrue(recovered.inboundAcks.isEmpty())
        assertTrue(f.sessions.handoffs.isEmpty())
        assertEquals(0, f.voiceStore.writes)
        assertEquals(0, f.semanticStore.writes)
        assertEquals(null, f.history.currentState(OWNER))
    }

    @Test
    fun voiceJournalWriteFailureLeavesM3HandoffAndNoAck() {
        val f = Fixture()
        f.voiceStore.failWrites = true
        f.sessions.handoffs += voiceHandoff(13)
        assertThrows(IllegalStateException::class.java) { f.coordinator.recover(OWNER) }
        assertEquals(1, f.sessions.handoffs.size)
        assertEquals(1, f.semanticStore.writes)
        assertTrue(f.sessions.completed.isEmpty())
        assertTrue(f.voice.pendingLiveAcknowledgements(OWNER, NOW).isEmpty())
    }

    @Test
    fun semanticSinkWriteFailureLeavesHandoffAndNeverAuthorizesAck() {
        val f = Fixture()
        f.semanticStore.failWrites = true
        f.sessions.handoffs += voiceHandoff(20)
        assertThrows(IllegalStateException::class.java) { f.coordinator.recover(OWNER) }
        assertEquals(1, f.sessions.handoffs.size)
        assertTrue(f.sessions.completed.isEmpty())
        assertEquals(0, f.voiceStore.writes)
        assertTrue(f.voice.pendingLiveAcknowledgements(OWNER, NOW).isEmpty())
    }

    @Test
    fun voiceWithAdapterButWithoutDurableSemanticSinkIsStillFailClosed() {
        val f = Fixture()
        f.sessions.handoffs += voiceHandoff(21)
        val unsafe = MessagingRecoveryCoordinator(
            f.sessions, f.history, f.voice, null, MessagingRecoveryClock { NOW },
        )
        assertThrows(MessagingRecoveryException::class.java) { unsafe.recover(OWNER) }
        assertEquals(1, f.sessions.handoffs.size)
        assertEquals(0, f.voiceStore.writes)
    }

    @Test
    fun crashAfterSemanticSinkPersistButBeforeReplayJournalImportIsIdempotent() {
        val f = Fixture()
        val handoff = voiceHandoff(22)
        f.semanticSink.persistAuthenticatedVoiceEvent(OWNER, handoff)
        f.sessions.handoffs += handoff
        val recovered = f.coordinator.recover(OWNER)
        assertEquals(1, f.semanticStore.writes)
        assertEquals(1, f.voiceStore.writes)
        assertEquals(1, recovered.inboundAcks.size)
    }

    @Test
    fun crashAfterVoiceImportBeforeHandoffCompletionRecoversIdempotently() {
        val f = Fixture()
        val handoff = voiceHandoff(14)
        f.semanticSink.persistAuthenticatedVoiceEvent(OWNER, handoff)
        f.voice.reconcileCommittedHandoff(OWNER, handoff, NOW)
        f.sessions.handoffs += handoff
        val recovered = f.coordinator.recover(OWNER)
        assertEquals(1, f.voiceStore.writes)
        assertEquals(1, recovered.inboundAcks.size)
        assertTrue(f.sessions.handoffs.isEmpty())
    }

    @Test
    fun replayReceiptWithoutSemanticRecordNeverAuthorizesRecoveredAck() {
        val f = Fixture()
        val handoff = voiceHandoff(23)
        f.voice.reconcileCommittedHandoff(OWNER, handoff, NOW)
        assertThrows(MessagingRecoveryException::class.java) {
            f.coordinator.recover(OWNER)
        }
        assertEquals(0, f.semanticStore.writes)
        assertEquals(1, f.voiceStore.writes)
    }

    @Test
    fun tamperedEncryptedSemanticRecordNeverAuthorizesRecoveredAck() {
        val f = Fixture()
        f.sessions.handoffs += voiceHandoff(24)
        assertEquals(1, f.coordinator.recover(OWNER).inboundAcks.size)
        f.semanticStore.bytes = f.semanticStore.bytes!!.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        assertThrows(IllegalStateException::class.java) {
            f.coordinator.recover(OWNER)
        }
    }

    @Test
    fun twoAuthenticatedOffersWithReusedCallIdRetainBothAcksButOnlyOneDispatchPermit() {
        val f = Fixture()
        f.sessions.handoffs += voiceHandoff(26)
        f.sessions.handoffs += voiceHandoff(27)
        val plan = f.coordinator.recover(OWNER)
        assertEquals(2, plan.inboundAcks.size)
        assertEquals(
            1,
            VoiceSignalReplayJournal(f.voiceStore).pendingLiveDispatchPermits(OWNER, NOW).size,
        )
        assertEquals(2, f.semanticSink.pendingLiveEvents(OWNER).size)
    }

    @Test
    fun twoIndependentlyValidStoresWithDifferentEncryptedEnvelopeDigestCannotAuthorizeAck() {
        val f = Fixture()
        val recorded = voiceHandoff(28)
        f.voice.reconcileCommittedHandoff(OWNER, recorded, NOW)
        val changedEnvelope = MessagingWire.encodeEnvelope(
            MessagingWire.decodeEnvelope(recorded.encodedEnvelope).copy(
                ciphertext = byteArrayOf(9, 8, 7, 6),
            ),
        )
        f.semanticSink.persistAuthenticatedVoiceEvent(
            OWNER,
            recorded.copy(encodedEnvelope = changedEnvelope),
        )
        assertThrows(IllegalStateException::class.java) {
            f.coordinator.recover(OWNER)
        }
        assertEquals(1, f.voiceStore.writes)
        assertEquals(1, f.semanticStore.writes)
        assertEquals(0, f.sessions.completed.size)
    }

    @Test
    fun differentReplayAdaptersWithEqualKeysButDifferentCiphertextDigestFailClosed() {
        val f = Fixture()
        val original = voiceHandoff(29)
        f.semanticSink.persistAuthenticatedVoiceEvent(OWNER, original)
        f.voice.reconcileCommittedHandoff(OWNER, original, NOW)

        val substitutedEnvelope = MessagingWire.encodeEnvelope(
            MessagingWire.decodeEnvelope(original.encodedEnvelope).copy(
                ciphertext = byteArrayOf(9, 9, 9, 9),
            ),
        )
        val wrongJournal = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(MemoryVoiceStore()))
        wrongJournal.reconcileCommittedHandoff(
            OWNER, original.copy(encodedEnvelope = substitutedEnvelope), NOW,
        )
        val mismatched = MessagingRecoveryCoordinator(
            f.sessions, f.history, wrongJournal, f.semanticSink,
            MessagingRecoveryClock { NOW }, f.verified,
        )
        assertThrows(MessagingRecoveryException::class.java) {
            mismatched.recover(OWNER)
        }
    }

    @Test
    fun voiceMetadataOnlyRecoveryAdapterFailsClosed() {
        val f = Fixture()
        f.sessions.handoffs += voiceHandoff(25)
        f.coordinator.recover(OWNER)
        val unsafe = MessagingRecoveryCoordinator(
            f.sessions, f.history, f.voice, f.semanticSink, MessagingRecoveryClock { NOW },
        )
        assertThrows(MessagingRecoveryException::class.java) {
            unsafe.recover(OWNER)
        }
    }

    @Test
    fun crossTypeMessageIdCollisionRejectsWithoutAcknowledgeOrCompletion() {
        val first = Fixture()
        first.coordinator.run { first.sessions.handoffs += textHandoff(15); recover(OWNER) }
        first.sessions.handoffs += voiceHandoff(15)
        assertThrows(MessagingRecoveryException::class.java) { first.coordinator.recover(OWNER) }
        assertEquals(1, first.sessions.handoffs.size)
        assertEquals(0, first.voiceStore.writes)

        val second = Fixture()
        second.sessions.handoffs += voiceHandoff(16)
        second.coordinator.recover(OWNER)
        second.sessions.handoffs += textHandoff(16)
        assertThrows(MessagingRecoveryException::class.java) { second.coordinator.recover(OWNER) }
        assertEquals(1, second.sessions.handoffs.size)
        assertTrue(second.history.currentState(OWNER) == null)
    }

    @Test
    fun unknownOrVoiceOutboundHandoffsNeverEnterTextHistory() {
        val f = Fixture()
        f.sessions.handoffs += voiceHandoff(17).copy(direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND)
        assertThrows(MessagingRecoveryException::class.java) { f.coordinator.recoverOutbound(OWNER) }
        assertEquals(null, f.history.currentState(OWNER))
        assertEquals(1, f.sessions.handoffs.size)
        f.sessions.handoffs.clear()
        f.sessions.handoffs += textHandoff(18).copy(encodedPlaintext = byteArrayOf(0x08, 0x03))
        assertThrows(MessagingRecoveryException::class.java) { f.coordinator.recover(OWNER) }
        assertEquals(null, f.history.currentState(OWNER))
    }

    @Test
    fun voiceWithoutExplicitRecoverySupportIsRejectedWithoutRatchetHandoffCompletion() {
        val f = Fixture()
        f.sessions.handoffs += voiceHandoff(19)
        val legacy = MessagingRecoveryCoordinator(f.sessions, f.history)
        assertThrows(MessagingRecoveryException::class.java) { legacy.recover(OWNER) }
        assertEquals(1, f.sessions.handoffs.size)
        assertEquals(null, f.history.currentState(OWNER))
    }

    private class Fixture(now: Long = NOW) {
        val historyStore = MemoryHistoryStore()
        val history = ConversationHistoryRepository(historyStore)
        val voiceStore = MemoryVoiceStore()
        val voice = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(voiceStore))
        val semanticStore = MemoryEncryptedSemanticStore()
        val semanticSink = DurableVoiceSemanticEventRepository(
            semanticStore, AesGcmTestCipher(), VoiceSemanticClock { now },
        )
        val verified = VoiceInboundPersistenceFacade(voice, semanticSink)
        val sessions = FakeSessionHandoffs()
        val coordinator = MessagingRecoveryCoordinator(
            sessions, history, voice, semanticSink, MessagingRecoveryClock { now }, verified,
        )
    }

    private class FakeSessionHandoffs : MessagingSessionHandoffRepository {
        val handoffs = ArrayList<SessionMessageHandoff>()
        val completed = ArrayList<Int>()
        var beforeComplete: (() -> Unit)? = null

        override fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff> =
            handoffs.map {
                it.copy(
                    localContactId = it.localContactId.copyOf(),
                    peerIdentityId = it.peerIdentityId.copyOf(),
                    messageId = it.messageId.copyOf(),
                    encodedPlaintext = it.encodedPlaintext.copyOf(),
                    encodedEnvelope = it.encodedEnvelope.copyOf(),
                )
            }

        override fun completeMessageHandoff(
            ownerIdentityId: ByteArray, peerIdentityId: ByteArray, messageId: ByteArray, direction: Int,
        ): Boolean {
            beforeComplete?.invoke()
            val index = handoffs.indexOfFirst {
                it.direction == direction &&
                    it.peerIdentityId.contentEquals(peerIdentityId) &&
                    it.messageId.contentEquals(messageId)
            }
            if (index < 0) return false
            handoffs.removeAt(index)
            completed += direction
            return true
        }
    }

    private class MemoryEncryptedSemanticStore : VoiceSemanticEncryptedStore {
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

    private class AesGcmTestCipher : VoiceSemanticPayloadCipher {
        private val key = SecretKeySpec(ByteArray(32) { 0x55.toByte() }, "AES")
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

    private class MemoryHistoryStore : ConversationHistoryStore {
        var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(value: ByteArray): Boolean { bytes = value.copyOf(); return true }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class MemoryVoiceStore : VoiceSignalReplayStore {
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

    companion object {
        private const val NOW = 1_780_000_000L
        private val OWNER = ByteArray(32) { 1 }
        private val PEER = ByteArray(32) { 2 }

        private fun id(n: Int) = ByteArray(16).also {
            it[0] = (n and 255).toByte()
            it[1] = ((n ushr 8) and 255).toByte()
        }

        private fun voiceHandoff(n: Int): SessionMessageHandoff {
            val signal = VoiceSignalPlaintext(
                senderIdentityId = PEER, recipientIdentityId = OWNER,
                messageId = id(n), callId = id(100), sentAtEpochSeconds = NOW,
                expiresAtEpochSeconds = NOW + 60, kind = VoiceSignalKind.OFFER,
                payload = "v=0\r\n".toByteArray(),
            )
            return handoff(n, VoiceSignalingWire.encode(signal))
        }

        private fun textHandoff(n: Int): SessionMessageHandoff {
            val plaintext = MessagingPlaintext(
                senderIdentityId = PEER, recipientIdentityId = OWNER,
                messageId = id(n), sentAtEpochSeconds = NOW,
                expiresAtEpochSeconds = NOW + 60, text = "regular chat",
            )
            return handoff(n, MessagingWire.encodePlaintext(plaintext))
        }

        private fun handoff(n: Int, plaintext: ByteArray): SessionMessageHandoff {
            val envelope = MessagingEnvelope(
                senderIdentityId = PEER, recipientIdentityId = OWNER,
                messageId = id(n), ciphertext = byteArrayOf(1, 2, 3),
                expiresAtEpochSeconds = NOW + 60,
            )
            return SessionMessageHandoff(
                localContactId = ByteArray(16) { 3 },
                peerIdentityId = PEER.copyOf(),
                messageId = id(n),
                direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
                encodedPlaintext = plaintext,
                encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
            )
        }
    }
}
