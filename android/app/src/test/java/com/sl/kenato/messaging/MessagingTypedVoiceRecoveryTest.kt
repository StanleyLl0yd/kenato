package com.sl.kenato.messaging

import com.sl.kenato.call.VoiceInboundHandoffRecovery
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
import org.junit.Test

class MessagingTypedVoiceRecoveryTest {
    @Test
    fun voiceRestartDoesNotLeakIntoChatAndOnlyAcksAfterDurableReplayImport() {
        val f = Fixture()
        val inbound = voiceHandoff(11)
        f.sessions.handoffs += inbound
        f.sessions.beforeComplete = {
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
        assertEquals(null, f.history.currentState(OWNER))
    }

    @Test
    fun voiceJournalWriteFailureLeavesM3HandoffAndNoAck() {
        val f = Fixture()
        f.voiceStore.failWrites = true
        f.sessions.handoffs += voiceHandoff(13)
        assertThrows(IllegalStateException::class.java) { f.coordinator.recover(OWNER) }
        assertEquals(1, f.sessions.handoffs.size)
        assertTrue(f.sessions.completed.isEmpty())
        assertTrue(f.voice.pendingLiveAcknowledgements(OWNER, NOW).isEmpty())
    }

    @Test
    fun crashAfterVoiceImportBeforeHandoffCompletionRecoversIdempotently() {
        val f = Fixture()
        val handoff = voiceHandoff(14)
        f.voice.reconcileCommittedHandoff(OWNER, handoff, NOW)
        f.sessions.handoffs += handoff
        val recovered = f.coordinator.recover(OWNER)
        assertEquals(1, f.voiceStore.writes)
        assertEquals(1, recovered.inboundAcks.size)
        assertTrue(f.sessions.handoffs.isEmpty())
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
        val sessions = FakeSessionHandoffs()
        val coordinator = MessagingRecoveryCoordinator(sessions, history, voice, MessagingRecoveryClock { now })
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
