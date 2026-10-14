package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingWire
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

class RestorableVoiceSignalMatcherTest {
    @Test
    fun onlyDurablyAdmittedOfferIsRestorableEvenAfterCrash() {
        val f = Fixture()
        f.accept(handoff(1, expiry = NOW + 30))
        f.accept(handoff(2, expiry = NOW + 80))
        assertEquals(2, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
        val live = f.matcher().restorableCandidates(OWNER, NOW)
        assertEquals(1, live.size)
        assertArrayEquals(id(1), live.single().messageId)
        assertEquals("v=0\r\n", live.single().payload.toString(Charsets.UTF_8))
        // No call resurrection when first offer expires and only a suppressed one remains.
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW + 31).isEmpty())
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW + 31).size)
    }

    @Test
    fun verifiedClaimReturnsDecryptedEventAtMostOnceAcrossRestarts() {
        val f = Fixture()
        f.accept(handoff(51))
        val claimed = f.matcher().claimRestorableCandidate(OWNER, PEER, id(51), NOW)
        assertArrayEquals(id(51), claimed!!.messageId)
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW).isEmpty())
        assertEquals(null, f.matcher().claimRestorableCandidate(OWNER, PEER, id(51), NOW))
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW).size)
    }

    @Test
    fun receiptChangedAfterSemanticPairingCannotClaimDifferentCall() {
        val f = Fixture()
        f.accept(handoff(61, call = 77))
        f.replayStore.afterReadOnce = {
            val state = VoiceSignalReplayStateCodec.decode(f.replayStore.read()!!)
            val original = state.records.single()
            val replacement = VoiceSignalReplayRecord(
                peerIdentityId = original.peerIdentityId.copyOf(),
                messageId = original.messageId.copyOf(),
                callId = id(99),
                kind = original.kind,
                expiresAtEpochSeconds = original.expiresAtEpochSeconds,
                envelopeDigest = original.envelopeDigest.copyOf(),
            )
            f.replayStore.write(VoiceSignalReplayStateCodec.encode(
                VoiceSignalReplayState(OWNER.copyOf(), listOf(replacement)),
            ))
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.matcher().claimRestorableCandidate(OWNER, PEER, id(61), NOW)
        }
        val state = VoiceSignalReplayStateCodec.decode(f.replayStore.read()!!)
        assertArrayEquals(id(99), state.records.single().callId)
        assertEquals(false, state.records.single().dispatchClaimed)
    }

    @Test
    fun noSemanticPayloadCannotClaimReplayPermission() {
        val f = Fixture()
        f.journal.importAuthenticatedInboundHandoff(OWNER, handoff(52), NOW)
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().claimRestorableCandidate(OWNER, PEER, id(52), NOW)
        }
        assertEquals(1, f.journal.pendingLiveDispatchPermits(OWNER, NOW).size)
    }

    @Test
    fun suppressedAndExpiredOffersCannotClaimAnEffect() {
        val f = Fixture()
        f.accept(handoff(53, expiry = NOW + 30))
        f.accept(handoff(54, expiry = NOW + 80))
        assertEquals(null, f.matcher().claimRestorableCandidate(OWNER, PEER, id(54), NOW))
        assertEquals(null, f.matcher().claimRestorableCandidate(OWNER, PEER, id(53), NOW + 30))
        assertEquals(1, f.journal.pendingLiveAcknowledgements(OWNER, NOW + 31).size)
    }

    @Test
    fun replayReceiptWithoutDurableSemanticPayloadFailsClosed() {
        val f = Fixture()
        f.journal.importAuthenticatedInboundHandoff(OWNER, handoff(3), NOW)
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
    }

    @Test
    fun semanticPayloadWithoutAdmittedReplayReceiptCannotBeDispatched() {
        val f = Fixture()
        f.semantic.persistAuthenticatedVoiceEvent(OWNER, handoff(4))
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW).isEmpty())
        assertTrue(f.journal.pendingLiveAcknowledgements(OWNER, NOW).isEmpty())
    }

    @Test
    fun mismatchedPersistedCallForSameAuthenticatedMessageIdFailsClosed() {
        val f = Fixture()
        f.journal.importAuthenticatedInboundHandoff(OWNER, handoff(5, call = 100), NOW)
        f.semantic.persistAuthenticatedVoiceEvent(OWNER, handoff(5, call = 101))
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
    }

    @Test
    fun samePeerMessageAndCallWithDifferentAuthenticatedEnvelopeDigestFailClosed() {
        val f = Fixture()
        f.journal.importAuthenticatedInboundHandoff(OWNER, handoff(8), NOW)
        f.semantic.persistAuthenticatedVoiceEvent(
            OWNER, handoff(8, ciphertext = byteArrayOf(7, 8, 9)),
        )
        assertThrows(RestorableVoiceSignalMismatchException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
    }

    @Test
    fun tamperedSemanticCiphertextAndWrongOwnerDoNotYieldEffects() {
        val f = Fixture()
        f.accept(handoff(6))
        f.semanticStore.bytes = f.semanticStore.bytes!!.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        assertThrows(VoiceSemanticEventException::class.java) {
            f.matcher().restorableCandidates(OWNER, NOW)
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            f.matcher().restorableCandidates(ByteArray(32) { 9 }, NOW)
        }
    }

    @Test
    fun exactExpiryBoundaryUsesOneSnapshotAcrossStores() {
        val f = Fixture()
        f.accept(handoff(7, expiry = NOW + 60))
        assertEquals(1, f.matcher().restorableCandidates(OWNER, NOW + 59).size)
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW + 60).isEmpty())
        assertTrue(f.matcher().restorableCandidates(OWNER, NOW + 360).isEmpty())
    }

    private class Fixture {
        val replayStore = MemoryReplayStore()
        val semanticStore = MemoryEncryptedStore()
        val journal = VoiceSignalReplayJournal(replayStore)
        val cipher = JvmAesGcmCipher()
        val semantic = DurableVoiceSemanticEventRepository(
            semanticStore, cipher, VoiceSemanticClock { NOW },
        )
        fun accept(event: SessionMessageHandoff) {
            semantic.persistAuthenticatedVoiceEvent(OWNER, event)
            journal.importAuthenticatedInboundHandoff(OWNER, event, NOW)
        }
        fun matcher() = RestorableVoiceSignalMatcher(
            VoiceSignalReplayJournal(replayStore),
            DurableVoiceSemanticEventRepository(
                semanticStore, cipher, VoiceSemanticClock { NOW },
            ),
        )
    }

    private class MemoryReplayStore : VoiceSignalReplayStore {
        private var bytes: ByteArray? = null
        var afterReadOnce: (() -> Unit)? = null
        override fun read(): ByteArray? {
            val snapshot = bytes?.copyOf()
            val callback = afterReadOnce
            afterReadOnce = null
            callback?.invoke()
            return snapshot
        }
        override fun write(bytes: ByteArray): Boolean {
            this.bytes = bytes.copyOf()
            return true
        }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class MemoryEncryptedStore : VoiceSemanticEncryptedStore {
        var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(value: ByteArray): Boolean {
            bytes = value.copyOf()
            return true
        }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class JvmAesGcmCipher : VoiceSemanticPayloadCipher {
        private val key = SecretKeySpec(ByteArray(32) { 0x31.toByte() }, "AES")
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

    private fun handoff(
        message: Int,
        call: Int = 77,
        expiry: Long = NOW + 60,
        ciphertext: ByteArray = byteArrayOf(1, 2, 3),
    ): SessionMessageHandoff {
        val signal = VoiceSignalPlaintext(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = id(message),
            callId = id(call),
            sentAtEpochSeconds = NOW,
            expiresAtEpochSeconds = expiry,
            kind = VoiceSignalKind.OFFER,
            payload = "v=0\r\n".toByteArray(),
        )
        val envelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = id(message),
            expiresAtEpochSeconds = expiry,
            ciphertext = ciphertext,
        )
        return SessionMessageHandoff(
            localContactId = ByteArray(16) { 3 },
            peerIdentityId = PEER.copyOf(),
            messageId = id(message),
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
            encodedPlaintext = VoiceSignalingWire.encode(signal),
            encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
        )
    }

    private companion object {
        const val NOW = 1_780_000_000L
        val OWNER = ByteArray(32) { 1 }
        val PEER = ByteArray(32) { 2 }
        fun id(n: Int) = ByteArray(16).also {
            it[0] = (n and 255).toByte()
            it[1] = ((n ushr 8) and 255).toByte()
        }
    }
}
