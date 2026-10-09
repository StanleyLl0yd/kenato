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
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class VoiceSemanticEventRepositoryTest {
    @Test
    fun encryptedSemanticOfferSurvivesRestartWithoutStoringSdpInClear() {
        val store = MemoryStore()
        val cipher = JvmTestAesGcmCipher()
        val first = DurableVoiceSemanticEventRepository(store, cipher, VoiceSemanticClock { NOW })
        first.persistAuthenticatedVoiceEvent(OWNER, offer(1))
        assertEquals(1, store.writes)
        assertTrue(store.bytes!!.size > 50)
        assertFalse(store.bytes!!.contentEquals(offer(1).encodedPlaintext))
        val restarted = DurableVoiceSemanticEventRepository(store, cipher, VoiceSemanticClock { NOW + 3 })
        val events = restarted.pendingLiveEvents(OWNER)
        assertEquals(1, events.size)
        assertEquals(VoiceSignalKind.OFFER, events.single().kind)
        assertArrayEquals(id(1), events.single().messageId)
        assertEquals("v=0\r\n", events.single().payload.toString(Charsets.UTF_8))
        restarted.persistAuthenticatedVoiceEvent(OWNER, offer(1))
        assertEquals(1, store.writes)
    }

    @Test
    fun exactEnvelopeConflictFailsClosedWithoutReplacingLiveEvent() {
        val store = MemoryStore()
        val repo = DurableVoiceSemanticEventRepository(store, JvmTestAesGcmCipher(), VoiceSemanticClock { NOW })
        repo.persistAuthenticatedVoiceEvent(OWNER, offer(2))
        assertThrows(VoiceSemanticEventException::class.java) {
            repo.persistAuthenticatedVoiceEvent(OWNER, offer(2, ciphertext = byteArrayOf(9, 9, 9)))
        }
        assertEquals(1, store.writes)
        assertEquals(1, repo.pendingLiveEvents(OWNER).size)
    }

    @Test
    fun failedAtomicWriteHasNoRecoverableSemanticEvent() {
        val store = MemoryStore()
        store.failWrites = true
        val repo = DurableVoiceSemanticEventRepository(store, JvmTestAesGcmCipher(), VoiceSemanticClock { NOW })
        assertThrows(VoiceSemanticEventException::class.java) {
            repo.persistAuthenticatedVoiceEvent(OWNER, offer(3))
        }
        assertEquals(null, store.bytes)
        assertTrue(repo.pendingLiveEvents(OWNER).isEmpty())
    }

    @Test
    fun ciphertextTamperingAndWrongOwnerAadFailAuthentication() {
        val store = MemoryStore()
        val repo = DurableVoiceSemanticEventRepository(store, JvmTestAesGcmCipher(), VoiceSemanticClock { NOW })
        repo.persistAuthenticatedVoiceEvent(OWNER, offer(4))
        assertThrows(VoiceSemanticEventException::class.java) {
            repo.pendingLiveEvents(ByteArray(32) { 6 })
        }
        store.bytes = store.bytes!!.copyOf().also {
            it[it.size - 1] = (it.last().toInt() xor 1).toByte()
        }
        assertThrows(VoiceSemanticEventException::class.java) { repo.pendingLiveEvents(OWNER) }
    }

    @Test
    fun missingOrRotatedKeystoreKeyCannotDecryptPreviousEvents() {
        val store = MemoryStore()
        val original = DurableVoiceSemanticEventRepository(
            store, JvmTestAesGcmCipher(), VoiceSemanticClock { NOW },
        )
        original.persistAuthenticatedVoiceEvent(OWNER, offer(77))
        val rotated = DurableVoiceSemanticEventRepository(
            store, JvmTestAesGcmCipher(ByteArray(32) { 0x44.toByte() }),
            VoiceSemanticClock { NOW },
        )
        assertThrows(VoiceSemanticEventException::class.java) {
            rotated.pendingLiveEvents(OWNER)
        }
    }

    @Test
    fun expiredEventIsNotRestoredAndNewlyExpiredHandoffIsRejected() {
        val store = MemoryStore()
        val cipher = JvmTestAesGcmCipher()
        val repo = DurableVoiceSemanticEventRepository(store, cipher, VoiceSemanticClock { NOW })
        repo.persistAuthenticatedVoiceEvent(OWNER, offer(5))
        val later = DurableVoiceSemanticEventRepository(store, cipher, VoiceSemanticClock { NOW + 60 })
        assertTrue(later.pendingLiveEvents(OWNER).isEmpty())
        assertThrows(VoiceSemanticEventException::class.java) {
            later.persistAuthenticatedVoiceEvent(OWNER, offer(5))
        }
    }

    @Test
    fun malformedUnboundAndOutboundHandoffsFailBeforeDiskWrite() {
        val store = MemoryStore()
        val repo = DurableVoiceSemanticEventRepository(store, JvmTestAesGcmCipher(), VoiceSemanticClock { NOW })
        val handoff = offer(6)
        for (bad in listOf(
            handoff.copy(direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND),
            handoff.copy(peerIdentityId = ByteArray(32) { 9 }),
            handoff.copy(encodedPlaintext = handoff.encodedPlaintext + byteArrayOf(0x50, 1)),
            handoff.copy(messageId = id(99)),
            handoff.copy(encodedEnvelope = handoff.encodedEnvelope + byteArrayOf(0)),
        )) {
            assertThrows(VoiceSemanticEventException::class.java) {
                repo.persistAuthenticatedVoiceEvent(OWNER, bad)
            }
        }
        assertEquals(0, store.writes)
    }

    @Test
    fun liveCapacityFailsClosedAndExpiryPrunesWithoutEvictingActiveEvents() {
        val store = MemoryStore()
        val cipher = JvmTestAesGcmCipher()
        val clock = MutableClock(NOW)
        val repo = DurableVoiceSemanticEventRepository(store, cipher, VoiceSemanticClock { clock.value })
        repeat(VoiceSemanticEventStateCodec.MAX_RECORDS) { index ->
            repo.persistAuthenticatedVoiceEvent(OWNER, offer(index + 1))
        }
        assertEquals(VoiceSemanticEventStateCodec.MAX_RECORDS, repo.pendingLiveEvents(OWNER).size)
        val before = store.bytes!!.copyOf()
        assertThrows(VoiceSemanticEventException::class.java) {
            repo.persistAuthenticatedVoiceEvent(OWNER, offer(999))
        }
        assertArrayEquals(before, store.bytes)
        clock.value = NOW + 61
        assertTrue(repo.pendingLiveEvents(OWNER).isEmpty())
        val newOffer = offer(1000, sent = NOW + 61)
        repo.persistAuthenticatedVoiceEvent(OWNER, newOffer)
        assertEquals(1, repo.pendingLiveEvents(OWNER).size)
    }

    @Test
    fun pureCodecRejectsTruncationDuplicatedKeysAndWrongBinding() {
        val first = offer(40)
        val valid = VoiceSemanticEventState(
            OWNER,
            listOf(
                VoiceSemanticEventRecord(
                    peerIdentityId = PEER,
                    messageId = first.messageId,
                    expiresAtEpochSeconds = NOW + 60,
                    envelopeDigest = ByteArray(32) { 1 },
                    encodedPlaintext = first.encodedPlaintext,
                ),
            ),
        )
        val encoded = VoiceSemanticEventStateCodec.encode(valid)
        assertEquals(1, VoiceSemanticEventStateCodec.decode(encoded).records.size)
        assertThrows(VoiceSemanticEventException::class.java) {
            VoiceSemanticEventStateCodec.decode(encoded.copyOfRange(0, encoded.size - 1))
        }
        assertThrows(VoiceSemanticEventException::class.java) {
            VoiceSemanticEventStateCodec.encode(VoiceSemanticEventState(OWNER, valid.records + valid.records[0]))
        }
        assertThrows(VoiceSemanticEventException::class.java) {
            VoiceSemanticEventStateCodec.encode(VoiceSemanticEventState(ByteArray(32) { 8 }, valid.records))
        }
    }

    private fun offer(
        n: Int,
        sent: Long = NOW,
        ciphertext: ByteArray = byteArrayOf(1, 2, 3),
    ): SessionMessageHandoff {
        val inner = VoiceSignalPlaintext(
            senderIdentityId = PEER,
            recipientIdentityId = OWNER,
            messageId = id(n),
            callId = id(200),
            kind = VoiceSignalKind.OFFER,
            sentAtEpochSeconds = sent,
            expiresAtEpochSeconds = sent + 60,
            payload = "v=0\r\n".toByteArray(),
        )
        val env = MessagingEnvelope(
            senderIdentityId = PEER,
            recipientIdentityId = OWNER,
            messageId = id(n),
            ciphertext = ciphertext,
            expiresAtEpochSeconds = sent + 60,
        )
        return SessionMessageHandoff(
            localContactId = ByteArray(16) { 5 },
            peerIdentityId = PEER.copyOf(),
            messageId = id(n),
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
            encodedPlaintext = VoiceSignalingWire.encode(inner),
            encodedEnvelope = MessagingWire.encodeEnvelope(env),
        )
    }

    private class MutableClock(var value: Long)

    private class MemoryStore : VoiceSemanticEncryptedStore {
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

    /** JVM test-only implementation; Android production uses non-exportable Keystore keys. */
    private class JvmTestAesGcmCipher(
        keyBytes: ByteArray = ByteArray(32) { 0x35.toByte() },
    ) : VoiceSemanticPayloadCipher {
        private val key = SecretKeySpec(keyBytes.copyOf(), "AES")
        private val random = SecureRandom()

        override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
            val nonce = ByteArray(12).also(random::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            return byteArrayOf(1) + nonce + cipher.doFinal(plaintext)
        }

        override fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray {
            if (encrypted.size < 30 || encrypted[0] != 1.toByte()) {
                throw VoiceSemanticEventException("Invalid test AEAD envelope")
            }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypted.copyOfRange(1, 13)),
            )
            cipher.updateAAD(aad)
            return cipher.doFinal(encrypted.copyOfRange(13, encrypted.size))
        }
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
