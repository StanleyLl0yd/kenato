package com.sl.kenato.call

import com.sl.kenato.messaging.ConversationHistoryRepository
import com.sl.kenato.messaging.ConversationHistoryStore
import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceInboundHandoffRecoveryTest {
    @Test
    fun liveM3CommittedSignalIsDurableBeforeAckAndCrashRecoveryIsIdempotent() {
        val store = MemoryStore()
        val bridge = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(store))
        val handoff = offer(3)
        assertTrue(bridge.pendingLiveAcknowledgements(OWNER, NOW).isEmpty())
        assertEquals(
            VoiceInboundHandoffRecoveryOutcome.DURABLY_IMPORTED,
            bridge.reconcileCommittedHandoff(OWNER, handoff, NOW),
        )
        assertEquals(1, store.writes)
        val restored = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(store))
        assertEquals(VoiceInboundHandoffRecoveryOutcome.DURABLY_IMPORTED,
            restored.reconcileCommittedHandoff(OWNER, handoff, NOW))
        assertEquals(1, store.writes)
        val ack = restored.pendingLiveAcknowledgements(OWNER, NOW).single()
        assertArrayEquals(PEER, ack.peerIdentityId)
        assertArrayEquals(id(3), ack.messageId)
    }

    @Test
    fun expiredCommittedHandoffCanBeRetiredButNeverRingsOrAcks() {
        val store = MemoryStore()
        val bridge = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(store))
        val old = offer(4)
        assertEquals(VoiceInboundHandoffRecoveryOutcome.EXPIRED_WITHOUT_ACK,
            bridge.reconcileCommittedHandoff(OWNER, old, NOW + 60))
        assertTrue(bridge.pendingLiveAcknowledgements(OWNER, NOW + 60).isEmpty())
        assertEquals(0, store.writes)
        assertEquals(null, store.bytes)
    }

    @Test
    fun liveAckPermissionExpiresStrictlyAndNeverRecoversAfterDeadline() {
        val store = MemoryStore()
        val bridge = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(store))
        bridge.reconcileCommittedHandoff(OWNER, offer(5), NOW)
        assertEquals(1, bridge.pendingLiveAcknowledgements(OWNER, NOW + 59).size)
        assertTrue(bridge.pendingLiveAcknowledgements(OWNER, NOW + 60).isEmpty())
        assertTrue(bridge.pendingLiveAcknowledgements(OWNER, NOW + 600).isEmpty())
    }

    @Test
    fun journalWriteFailureRetainsNoAckAuthorization() {
        val store = MemoryStore()
        store.failWrites = true
        val bridge = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(store))
        assertThrows(VoiceInboundHandoffRecoveryException::class.java) {
            bridge.reconcileCommittedHandoff(OWNER, offer(6), NOW)
        }
        assertTrue(bridge.pendingLiveAcknowledgements(OWNER, NOW).isEmpty())
        assertEquals(null, store.bytes)
    }

    @Test
    fun corruptReplayStateAndOwnerSubstitutionFailClosed() {
        val store = MemoryStore()
        val bridge = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(store))
        bridge.reconcileCommittedHandoff(OWNER, offer(7), NOW)
        store.bytes = store.bytes!!.copyOf().also { it[12] = (it[12].toInt() xor 1).toByte() }
        assertThrows(VoiceSignalReplayException::class.java) {
            bridge.pendingLiveAcknowledgements(OWNER, NOW)
        }
        store.bytes = null
        assertThrows(VoiceInboundHandoffRecoveryException::class.java) {
            bridge.reconcileCommittedHandoff(ByteArray(32) { 9 }, offer(7), NOW)
        }
    }

    @Test
    fun forgedExpiredVoiceBytesMustNotBeRetiredAsAuthentic() {
        val bridge = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(MemoryStore()))
        val handoff = offer(8)
        val tampered = handoff.copy(encodedPlaintext = handoff.encodedPlaintext + byteArrayOf(0x50, 1))
        assertThrows(VoiceInboundHandoffRecoveryException::class.java) {
            bridge.reconcileCommittedHandoff(OWNER, tampered, NOW + 500)
        }
        val wrongPeer = handoff.copy(peerIdentityId = ByteArray(32) { 10 })
        assertThrows(VoiceInboundHandoffRecoveryException::class.java) {
            bridge.reconcileCommittedHandoff(OWNER, wrongPeer, NOW + 500)
        }
        assertThrows(VoiceInboundHandoffRecoveryException::class.java) {
            bridge.reconcileCommittedHandoff(OWNER, handoff.copy(direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND), NOW)
        }
    }

    @Test
    fun unrelatedTextHistoryIsUntouched() {
        val store = MemoryStore()
        val bridge = VoiceInboundHandoffRecovery(VoiceSignalReplayJournal(store))
        val history = ConversationHistoryRepository(object : ConversationHistoryStore {
            override fun read(): ByteArray? = null
            override fun write(value: ByteArray): Boolean = error("Voice must not enter chat")
            override fun clear(): Boolean = true
        })
        bridge.reconcileCommittedHandoff(OWNER, offer(9), NOW)
        assertEquals(null, history.currentState(OWNER))
    }

    private fun offer(number: Int): SessionMessageHandoff {
        val signal = VoiceSignalPlaintext(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = id(number),
            callId = id(100),
            sentAtEpochSeconds = NOW,
            expiresAtEpochSeconds = NOW + 60,
            kind = VoiceSignalKind.OFFER,
            payload = "v=0\r\n".toByteArray(),
        )
        val envelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = id(number),
            ciphertext = byteArrayOf(2, 3, 4),
            expiresAtEpochSeconds = NOW + 60,
        )
        return SessionMessageHandoff(
            localContactId = ByteArray(16) { 3 },
            peerIdentityId = PEER.copyOf(),
            messageId = id(number),
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
            encodedPlaintext = VoiceSignalingWire.encode(signal),
            encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
        )
    }

    private fun id(n: Int) = ByteArray(16).also {
        it[0] = (n and 255).toByte()
        it[1] = ((n ushr 8) and 255).toByte()
    }

    private class MemoryStore : VoiceSignalReplayStore {
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

    private companion object {
        const val NOW = 1_780_000_000L
        val OWNER = ByteArray(32) { 1 }
        val PEER = ByteArray(32) { 2 }
    }
}
