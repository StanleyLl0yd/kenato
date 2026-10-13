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
        assertFalse(state.records[0].suppressedOffer)
        assertTrue(state.records[1].suppressedOffer)
        assertEquals(1, VoiceSignalReplayJournal(store).pendingLiveDispatchPermits(OWNER, NOW).size)
        assertEquals(2, VoiceSignalReplayJournal(store).pendingLiveAcknowledgements(OWNER, NOW).size)
        assertEquals(VoiceSignalReplayDecision.DUPLICATE_EVENT,
            VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(OWNER, handoff(message = 2), NOW))
    }


    @Test
    fun suppressionNeverResurrectsAfterOriginalOfferExpires() {
        val store = MemoryStore()
        val journal = VoiceSignalReplayJournal(store)
        assertEquals(
            VoiceSignalReplayDecision.NEW_EVENT,
            journal.importAuthenticatedInboundHandoff(
                OWNER, handoff(message = 30, expiry = NOW + 30), NOW,
            ),
        )
        assertEquals(
            VoiceSignalReplayDecision.SUPPRESSED_REUSED_CALL_ID,
            journal.importAuthenticatedInboundHandoff(
                OWNER, handoff(message = 31, expiry = NOW + 80), NOW,
            ),
        )
        assertEquals(1, VoiceSignalReplayJournal(store).pendingLiveDispatchPermits(OWNER, NOW).size)
        assertEquals(0, VoiceSignalReplayJournal(store).pendingLiveDispatchPermits(OWNER, NOW + 31).size)
        assertEquals(1, VoiceSignalReplayJournal(store).pendingLiveAcknowledgements(OWNER, NOW + 31).size)
        assertTrue(VoiceSignalReplayStateCodec.decode(store.bytes!!).records.last().suppressedOffer)
        assertEquals(
            VoiceSignalReplayDecision.SUPPRESSED_REUSED_CALL_ID,
            journal.importAuthenticatedInboundHandoff(
                OWNER, handoff(message = 32, expiry = NOW + 85), NOW + 31,
            ),
        )
        assertEquals(0, VoiceSignalReplayJournal(store).pendingLiveDispatchPermits(OWNER, NOW + 31).size)
        assertTrue(VoiceSignalReplayStateCodec.decode(store.bytes!!).records.all { it.suppressedOffer })
    }

    @Test
    fun v1LegacyOffersConservativelyLoseEffectPermissionButKeepAck() {
        val old = record(40)
        val content = java.io.ByteArrayOutputStream().use { bytes ->
            java.io.DataOutputStream(bytes).use { output ->
                output.write(byteArrayOf('K'.code.toByte(), 'N'.code.toByte(), 'V'.code.toByte(), '5'.code.toByte()))
                output.writeInt(1)
                output.write(OWNER)
                output.writeInt(1)
                output.write(old.peerIdentityId)
                output.write(old.messageId)
                output.write(old.callId)
                output.writeInt(old.kind.number)
                output.writeLong(old.expiresAtEpochSeconds)
                output.write(old.envelopeDigest)
            }
            bytes.toByteArray()
        }
        val legacy = content + java.security.MessageDigest.getInstance("SHA-256").digest(content)
        val store = MemoryStore()
        store.bytes = legacy
        val journal = VoiceSignalReplayJournal(store)
        assertEquals(1, journal.pendingLiveAcknowledgements(OWNER, NOW).size)
        assertTrue(journal.pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
        val migrated = VoiceSignalReplayStateCodec.encode(VoiceSignalReplayStateCodec.decode(legacy))
        assertTrue(VoiceSignalReplayStateCodec.decode(migrated).records.single().suppressedOffer)
        assertTrue(VoiceSignalReplayJournal(MemoryStore().also { it.bytes = migrated })
            .pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
    }

    @Test
    fun invalidPersistedSuppressionForControlSignalFailsClosed() {
        val wrong = VoiceSignalReplayRecord(
            peerIdentityId = PEER, messageId = id(45), callId = id(77),
            kind = VoiceSignalKind.HANGUP, expiresAtEpochSeconds = NOW + 60,
            envelopeDigest = ByteArray(32) { 5 }, suppressedOffer = true,
        )
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceSignalReplayStateCodec.encode(VoiceSignalReplayState(OWNER, listOf(wrong)))
        }
    }

    @Test
    fun claimingEffectIsDurableOnceWithoutRevokingReceiptAck() {
        val store = MemoryStore()
        val journal = VoiceSignalReplayJournal(store)
        journal.importAuthenticatedInboundHandoff(OWNER, handoff(message = 46), NOW)
        val permit = journal.pendingLiveDispatchPermits(OWNER, NOW).single()
        assertTrue(journal.claimLiveDispatchPermit(OWNER, permit, NOW))
        assertFalse(VoiceSignalReplayJournal(store).claimLiveDispatchPermit(OWNER, permit, NOW))
        assertTrue(VoiceSignalReplayJournal(store).pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
        assertEquals(1, VoiceSignalReplayJournal(store).pendingLiveAcknowledgements(OWNER, NOW).size)
        assertTrue(VoiceSignalReplayStateCodec.decode(store.bytes!!).records.single().dispatchClaimed)
    }

    @Test
    fun differentJournalInstancesCannotClaimTheSameEventConcurrently() {
        val store = MemoryStore()
        VoiceSignalReplayJournal(store).importAuthenticatedInboundHandoff(
            OWNER, handoff(message = 59), NOW,
        )
        val permit = VoiceSignalReplayJournal(store).pendingLiveDispatchPermits(OWNER, NOW).single()
        val workers = java.util.concurrent.Executors.newFixedThreadPool(2)
        val release = java.util.concurrent.CountDownLatch(1)
        try {
            val attempts = (1..2).map {
                workers.submit<Boolean> {
                    release.await()
                    VoiceSignalReplayJournal(store).claimLiveDispatchPermit(OWNER, permit, NOW)
                }
            }
            release.countDown()
            val results = attempts.map {
                it.get(10, java.util.concurrent.TimeUnit.SECONDS)
            }
            assertEquals(1, results.count { it })
            assertEquals(1, results.count { !it })
            assertEquals(1, VoiceSignalReplayJournal(store).pendingLiveAcknowledgements(OWNER, NOW).size)
        } finally {
            workers.shutdownNow()
        }
    }

    @Test
    fun failedClaimWriteDoesNotConsumeOrPermitAnEffect() {
        val store = MemoryStore()
        val journal = VoiceSignalReplayJournal(store)
        journal.importAuthenticatedInboundHandoff(OWNER, handoff(message = 47), NOW)
        val permit = journal.pendingLiveDispatchPermits(OWNER, NOW).single()
        val before = store.bytes!!.copyOf()
        store.failWrite = true
        assertThrows(VoiceSignalReplayException::class.java) {
            journal.claimLiveDispatchPermit(OWNER, permit, NOW)
        }
        assertArrayEquals(before, store.bytes)
        store.failWrite = false
        assertTrue(journal.claimLiveDispatchPermit(OWNER, permit, NOW))
    }

    @Test
    fun wrongDigestWrongOwnerSuppressedOrExpiredClaimsFailClosed() {
        val store = MemoryStore()
        val journal = VoiceSignalReplayJournal(store)
        journal.importAuthenticatedInboundHandoff(OWNER, handoff(message = 48), NOW)
        journal.importAuthenticatedInboundHandoff(OWNER, handoff(message = 49), NOW)
        val permit = journal.pendingLiveDispatchPermits(OWNER, NOW).single()
        val wrong = VoiceSignalReplayDispatchPermit(
            permit.peerIdentityId, permit.messageId, permit.callId, permit.kind,
            permit.envelopeDigest.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() },
        )
        assertThrows(VoiceSignalReplayException::class.java) {
            journal.claimLiveDispatchPermit(OWNER, wrong, NOW)
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            journal.claimLiveDispatchPermit(ByteArray(32) { 7 }, permit, NOW)
        }
        assertFalse(journal.claimLiveDispatchPermit(OWNER, permit, NOW + 60))
        assertTrue(journal.claimLiveDispatchPermit(OWNER, permit, NOW))
        assertEquals(2, journal.pendingLiveAcknowledgements(OWNER, NOW).size)
    }

    @Test
    fun v2UpgradeKeepsAcknowledgementsButRetiresAllLegacyEffectPermissions() {
        val old = record(50)
        val content = java.io.ByteArrayOutputStream().use { bytes ->
            java.io.DataOutputStream(bytes).use { output ->
                output.write(byteArrayOf(75, 78, 86, 53))
                output.writeInt(2)
                output.write(OWNER)
                output.writeInt(1)
                output.write(old.peerIdentityId)
                output.write(old.messageId)
                output.write(old.callId)
                output.writeInt(old.kind.number)
                output.writeLong(old.expiresAtEpochSeconds)
                output.write(old.envelopeDigest)
                output.writeByte(0)
            }
            bytes.toByteArray()
        }
        val checksum = java.security.MessageDigest.getInstance("SHA-256").digest(content)
        val store = MemoryStore().also { it.bytes = content + checksum }
        val journal = VoiceSignalReplayJournal(store)
        assertTrue(journal.pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
        assertEquals(1, journal.pendingLiveAcknowledgements(OWNER, NOW).size)
        val migrated = VoiceSignalReplayStateCodec.encode(
            VoiceSignalReplayStateCodec.decode(store.bytes!!),
        )
        val decoded = VoiceSignalReplayStateCodec.decode(migrated)
        assertFalse(decoded.records.single().suppressedOffer)
        assertTrue(decoded.records.single().dispatchClaimed)
        assertTrue(VoiceSignalReplayJournal(MemoryStore().also { it.bytes = migrated })
            .pendingLiveDispatchPermits(OWNER, NOW).isEmpty())
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
        expiry: Long = sentAt + 60,
    ): SessionMessageHandoff {
        val signal = VoiceSignalPlaintext(
            senderIdentityId = PEER,
            recipientIdentityId = OWNER,
            messageId = id(embeddedMessage),
            callId = id(call),
            kind = VoiceSignalKind.OFFER,
            sentAtEpochSeconds = sentAt,
            expiresAtEpochSeconds = expiry,
            payload = "v=0\r\n".toByteArray(),
        )
        val envelope = MessagingEnvelope(
            senderIdentityId = PEER,
            recipientIdentityId = OWNER,
            messageId = id(message),
            expiresAtEpochSeconds = expiry,
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
