package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceCapabilityConsentRepositoryTest {
    @Test
    fun approvedPinnedPeerProofIsDurableAndCannotReuseConsumedChallenge() {
        val f = Fixture()
        assertFalse(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
        val challenge = f.issue()
        assertArrayEquals(OWNER, challenge.ownerIdentityId)
        assertArrayEquals(f.peer, challenge.peerIdentityId)
        assertEquals(NOW + 300L, challenge.expiresAtEpochSeconds)
        f.repository.confirmSignedProof(
            OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true,
        )
        assertTrue(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
        val restarted = f.newRepository()
        assertTrue(restarted.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
        assertThrows(VoiceCapabilityConsentException::class.java) {
            restarted.confirmSignedProof(
                OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true,
            )
        }
        assertThrows(VoiceCapabilityConsentException::class.java) { restarted.issueChallenge(OWNER, f.peer, f.keys.public.encoded) }
        val state = VoiceCapabilityConsentStateCodec.decode(f.decryptState())
        assertTrue(state.entries.single().challenge.all { it == 0.toByte() })
        assertEquals(NOW, state.entries.single().approvedAt)
    }

    @Test
    fun sameOneTimeChallengeCannotBeConfirmedByTwoRepositoryInstances() {
        val f = Fixture()
        val challenge = f.issue()
        val proof = f.sign(challenge)
        val executor = java.util.concurrent.Executors.newFixedThreadPool(2)
        val release = java.util.concurrent.CountDownLatch(1)
        try {
            val requests = (1..2).map {
                executor.submit<Boolean> {
                    release.await()
                    try {
                        f.newRepository().confirmSignedProof(
                            OWNER, f.peer, f.keys.public.encoded, proof, true,
                        )
                        true
                    } catch (_: VoiceCapabilityConsentException) {
                        false
                    }
                }
            }
            release.countDown()
            val outcomes = requests.map { it.get(10, java.util.concurrent.TimeUnit.SECONDS) }
            assertEquals(1, outcomes.count { it })
            assertEquals(1, outcomes.count { !it })
            assertTrue(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun consentIsExplicitAndUnsignedOrWrongChallengeCannotAuthorizeSupport() {
        val f = Fixture()
        val challenge = f.issue()
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), false)
        }
        assertFalse(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
        val corruptSignature = f.sign(challenge).copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, corruptSignature, true)
        }
        assertFalse(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
        f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true)
        assertTrue(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
    }

    @Test
    fun rotatingChallengeRejectsOldSignedAttestationEvenIfItsSignatureIsGenuine() {
        val f = Fixture()
        val first = f.issue()
        val second = f.issue()
        assertFalse(first.challenge.contentEquals(second.challenge))
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(first), true)
        }
        f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(second), true)
        assertTrue(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
    }

    @Test
    fun expiredChallengeAndSubstitutedPublicKeyFailClosed() {
        val f = Fixture()
        val challenge = f.issue()
        val attacker = Fixture()
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.repository.confirmSignedProof(OWNER, f.peer, attacker.keys.public.encoded, f.sign(challenge), true)
        }
        f.now = NOW + 300L
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true)
        }
        assertFalse(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
    }

    @Test
    fun failedAtomicCommitCannotGrantSupportAndIsSafelyRetryable() {
        val f = Fixture()
        f.store.failWrites = true
        assertThrows(VoiceCapabilityConsentException::class.java) { f.issue() }
        assertEquals(null, f.store.bytes)
        f.store.failWrites = false
        val challenge = f.issue()
        val pendingBytes = f.store.bytes!!.copyOf()
        f.store.failWrites = true
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true)
        }
        assertArrayEquals(pendingBytes, f.store.bytes)
        assertFalse(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
        f.store.failWrites = false
        f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true)
        assertTrue(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
    }

    @Test
    fun tamperWrongOwnerAndWrongAadNeverExposeSupportOrChallenge() {
        val f = Fixture()
        val challenge = f.issue()
        f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true)
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.repository.isVoiceVersion2Confirmed(ByteArray(32) { 9 }, f.peer, f.keys.public.encoded)
        }
        f.store.bytes = f.store.bytes!!.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded)
        }
    }

    @Test
    fun revocationAndIdentityRecoveryRemoveVerifiedCapability() {
        val f = Fixture()
        val challenge = f.issue()
        f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true)
        f.repository.revoke(OWNER, f.peer)
        assertFalse(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
        f.issue()
        f.repository.clearForIdentityRecovery()
        assertTrue(f.cipher.keyDestroyed)
        assertEquals(null, f.store.bytes)
        assertFalse(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
    }

    @Test
    fun restoredEncryptedGrantCannotSurviveIdentityKeyDeletion() {
        val f = Fixture()
        val challenge = f.issue()
        f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true)
        val staleEncryptedGrant = f.store.bytes!!.copyOf()
        f.repository.clearForIdentityRecovery()
        f.store.bytes = staleEncryptedGrant
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newRepository().isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded)
        }
    }

    @Test
    fun failedKeystoreDeletionAbortsIdentityClearWithoutSilentlyAuthorizingReset() {
        val f = Fixture()
        val challenge = f.issue()
        f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true)
        f.cipher.failKeyDeletion = true
        val before = f.store.bytes!!.copyOf()
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.repository.clearForIdentityRecovery()
        }
        assertArrayEquals(before, f.store.bytes)
        assertFalse(f.cipher.keyDestroyed)
        // Destructive identity recovery must not proceed after this failure.
        assertTrue(f.repository.isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded))
    }

    @Test
    fun failedAtomicFileClearAfterKeyDeletionCannotRestoreOldConsent() {
        val f = Fixture()
        val challenge = f.issue()
        f.repository.confirmSignedProof(OWNER, f.peer, f.keys.public.encoded, f.sign(challenge), true)
        f.store.failClear = true
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.repository.clearForIdentityRecovery()
        }
        assertTrue(f.cipher.keyDestroyed)
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newRepository().isVoiceVersion2Confirmed(OWNER, f.peer, f.keys.public.encoded)
        }
    }

    @Test
    fun codecRejectsDuplicatePeerIdsAndAllNoncanonicalEntryShapes() {
        val f = Fixture()
        f.issue()
        val state = VoiceCapabilityConsentStateCodec.decode(f.decryptState())
        val entry = state.entries.single()
        assertThrows(VoiceCapabilityConsentException::class.java) {
            VoiceCapabilityConsentStateCodec.encode(
                VoiceCapabilityConsentState(OWNER, listOf(entry, entry)),
            )
        }
        val invalid = VoiceCapabilityConsentEntry(
            entry.peerIdentityId, entry.peerPublicKeyDigest,
            entry.challenge, entry.challengeIssuedAt, entry.challengeExpiresAt,
            approvedAt = NOW,
        )
        assertThrows(VoiceCapabilityConsentException::class.java) {
            VoiceCapabilityConsentStateCodec.encode(VoiceCapabilityConsentState(OWNER, listOf(invalid)))
        }
        val encoded = VoiceCapabilityConsentStateCodec.encode(state)
        assertThrows(VoiceCapabilityConsentException::class.java) {
            VoiceCapabilityConsentStateCodec.decode(encoded + byteArrayOf(0))
        }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            VoiceCapabilityConsentStateCodec.decode(encoded.copyOf(encoded.size - 1))
        }
    }

    private class Fixture {
        val keys = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val peer = ContactCrypto.identityId(keys.public.encoded)
        val store = MemoryStore()
        val cipher = TestAesGcm()
        var now: Long = NOW
        val repository = newRepository()

        fun newRepository() = DurableVoiceCapabilityConsentRepository(
            store, cipher, SecureRandom(), VoiceCapabilityConsentClock { now },
        )

        fun issue() = repository.issueChallenge(OWNER, peer, keys.public.encoded)

        fun sign(challenge: VoiceCapabilityChallenge): ByteArray =
            VoiceCapabilityProofWire.encode(
                VoiceCapabilityProofWire.sign(
                    peer, OWNER, challenge.challenge,
                    NOW, NOW + 300L,
                ) { payload ->
                    Signature.getInstance("SHA256withECDSA").run {
                        initSign(keys.private)
                        update(payload)
                        sign()
                    }
                },
            )

        fun decryptState(): ByteArray = cipher.decrypt(
            store.bytes!!,
            "KENATO-M5-VOICE-CAPABILITY-CONSENT-V1\u0000".toByteArray(Charsets.UTF_8) + OWNER,
        )
    }

    private class MemoryStore : VoiceCapabilityEncryptedStore {
        var bytes: ByteArray? = null
        var failWrites = false
        var failClear = false
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(bytes: ByteArray): Boolean {
            if (failWrites) return false
            this.bytes = bytes.copyOf()
            return true
        }
        override fun clear(): Boolean {
            if (failClear) return false
            bytes = null
            return true
        }
    }

    private class TestAesGcm : VoiceCapabilityPayloadCipher {
        var keyDestroyed = false
        var failKeyDeletion = false
        override fun deleteCapabilityKeyForIdentityRecovery() {
            if (failKeyDeletion) throw VoiceCapabilityConsentException("Keystore alias deletion failed")
            keyDestroyed = true
        }
        private val key = SecretKeySpec(ByteArray(32) { 0x22.toByte() }, "AES")
        private val random = SecureRandom()
        override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
            val nonce = ByteArray(12).also(random::nextBytes)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
            c.updateAAD(aad)
            return byteArrayOf(1) + nonce + c.doFinal(plaintext)
        }
        override fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray {
            if (keyDestroyed) throw VoiceCapabilityConsentException("Destroyed capability key unavailable")
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypted.copyOfRange(1, 13)))
            c.updateAAD(aad)
            return c.doFinal(encrypted.copyOfRange(13, encrypted.size))
        }
    }

    private companion object {
        const val NOW = 1_780_000_000L
        val OWNER = ByteArray(32) { 1 }
    }
}
