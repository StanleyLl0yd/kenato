package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceSignalReplayJournalTest {
    @Test
    fun duplicateEnvelopeSurvivesProcessRestartWithoutSecondEffect() {
        val store = MemoryStore()
        val first = handoff()
        val journal = VoiceSignalReplayJournal(store)
        assertEquals(VoiceSignalReplayDecision.NEW_EVENT, journal.importAuthenticatedInboundHandoff(OWNER, first, NOW))
        val before = store.bytes!!.copyOf()
        assertEquals(
            VoiceSignalReplayDecision.DUPLICATE_EVENT,
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, first, NOW),
        )
        assertArrayEquals(before, store.bytes)
        assertEquals(1, VoiceSignalReplayStateCodec.decode(before).records.size)
        assertFalse(before.toString(Charsets.ISO_8859_1).contains("candidate:"))
    }

    @Test
    fun reusedCallIdWithFreshAuthenticatedEnvelopeCannotRingAgainAfterRestart() {
        val store = MemoryStore()
        assertEquals(VoiceSignalReplayDecision.NEW_EVENT,
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, handoff(message = 1), NOW))
        assertEquals(VoiceSignalReplayDecision.SUPPRESSED_REUSED_CALL_ID,
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, handoff(message = 2), NOW))
        val state = VoiceSignalReplayStateCodec.decode(store.bytes!!)
        assertEquals(2, state.records.size)
        assertEquals(VoiceSignalReplayDecision.DUPLICATE_EVENT,
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, handoff(message = 2), NOW))
    }

    @Test
    fun samePeerAndMessageIdWithDifferentAuthenticatedEnvelopeIsRejected() {
        val store = MemoryStore()
        VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, handoff(message = 1), NOW)
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(
                OWNER, handoff(message = 1, ciphertext = byteArrayOf(9, 8, 7)), NOW,
            )
        }
    }

    @Test
    fun tamperedStateWrongOwnerAndWriteFailureFailClosed() {
        val store = MemoryStore()
        VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, handoff(), NOW)
        val original = store.bytes!!.copyOf()
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(ByteArray(32) { 6 }, handoff(), NOW)
        }
        store.bytes = original.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, handoff(message = 3), NOW)
        }
        store.bytes = null
        store.failWrite = true
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, handoff(), NOW)
        }
        assertEquals(null, store.bytes)
    }

    @Test
    fun bindingAndShortExpiryValidatedBeforeAnyJournalWrite() {
        val store = MemoryStore()
        val mismatch = handoff(message = 1, embeddedMessage = 3)
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, mismatch, NOW)
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, handoff(), NOW + 60)
        }
        assertEquals(null, store.bytes)
    }

    @Test
    fun expiredEntriesPruneAndLiveCapacityFailsClosedWithoutEviction() {
        val store = MemoryStore()
        val journal = VoiceSignalReplayJournal(store)
        repeat(VoiceSignalReplayStateCodec.MAX_RECORDS) { index ->
            assertEquals(
                VoiceSignalReplayDecision.NEW_EVENT,
                journal.importAuthenticatedInboundHandoff(OWNER, handoff(message = index + 1, call = index + 1), NOW),
            )
        }
        val before = store.bytes!!.copyOf()
        assertThrows(VoiceSignalReplayException::class.java) {
            journal.importAuthenticatedInboundHandoff(OWNER, handoff(message = 900, call = 900), NOW)
        }
        assertArrayEquals(before, store.bytes)

        assertEquals(
            VoiceSignalReplayDecision.NEW_EVENT,
            journal.importAuthenticatedInboundHandoff(
                OWNER,
                handoff(message = 901, call = 901, sentAt = NOW + 61),
                NOW + 61,
            ),
        )
        assertEquals(1, VoiceSignalReplayStateCodec.decode(store.bytes!!).records.size)
    }

    @Test
    fun codecRejectsDuplicateIdsTruncationAndUnknownKind() {
        val valid = VoiceSignalReplayState(OWNER, listOf(record(1)))
        val bytes = VoiceSignalReplayStateCodec.encode(valid)
        assertEquals(1, VoiceSignalReplayStateCodec.decode(bytes).records.size)
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayStateCodec.encode(VoiceSignalReplayState(OWNER, listOf(record(1), record(1))))
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayStateCodec.decode(bytes.copyOfRange(0, bytes.size - 1))
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayStateCodec.decode(ByteArray(VoiceSignalReplayStateCodec.MAX_STATE_BYTES + 1))
        }
    }

    private fun record(message: Int) = VoiceSignalReplayRecord(
        peerIdentityId = PEER,
        messageId = id(message),
        callId = id(77),
        kind = VoiceSignalKind.OFFER,
        expiresAtEpochSeconds = NOW + 60,
        envelopeDigest = ByteArray(32) { 2 },
    )

    private fun handoff(
        message: Int = 1,
        call: Int = 77,
        sentAt: Long = NOW,
        embeddedMessage: Int = message,
        ciphertext: ByteArray = byteArrayOf(1, 2, 3),
    ): SessionMessageHandoff {
        val signal = VoiceSignalPlaintext(
            senderIdentityId = PEER,
            recipientIdentityId = OWNER,
            messageId = id(embeddedMessage),
            callId = id(call),
            kind = VoiceSignalKind.OFFER,
            sentAtEpochSeconds = sentAt,
            expiresAtEpochSeconds = sentAt + 60,
            payload = "v=0\r\n".toByteArray(),
        )
        val envelope = MessagingEnvelope(
            senderIdentityId = PEER,
            recipientIdentityId = OWNER,
            messageId = id(message),
            expiresAtEpochSeconds = sentAt + 60,
            ciphertext = ciphertext,
        )
        return SessionMessageHandoff(
            localContactId = ByteArray(16) { 4 },
            peerIdentityId = PEER.copyOf(),
            messageId = id(message),
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
            encodedPlaintext = VoiceSignalingWire.encode(signal),
            encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
        )
    }

    private fun id(number: Int): ByteArray =
        ByteArray(16).also { it[0] = (number and 255).toByte(); it[1] = ((number ushr 8) and 255).toByte() }

    private class MemoryStore : VoiceSignalReplayStore {
        var bytes: ByteArray? = null
        var failWrite = false
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(bytes: ByteArray): Boolean {
            if (failWrite) return false
            this.bytes = bytes.copyOf()
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
