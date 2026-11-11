package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Offline fault injection only, NOT Android Keystore or physical P23 evidence. */
class EpochBoundVoiceConsentStoreTest {
    @Test
    fun verifiedSignedConsentCannotReappearFromAnAuthenticRestoredGrant() {
        val f = Fixture()
        val owner = ByteArray(32) { 1 }
        val identity = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val peer = ContactCrypto.identityId(identity.public.encoded)
        val now = 1_780_000_000L
        val cipher = InnerAesGcmCipher()
        fun consent() = DurableVoiceCapabilityConsentRepository(
            f.newStore(), cipher, SecureRandom(), VoiceCapabilityConsentClock { now },
        )
        val repo = consent()
        val challenge = repo.issueChallenge(owner, peer, identity.public.encoded)
        val proof = VoiceCapabilityProofWire.encode(
            VoiceCapabilityProofWire.sign(
                peer, owner, challenge.challenge, now, now + 300,
            ) { payload ->
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(identity.private)
                    update(payload)
                    sign()
                }
            },
        )
        repo.confirmSignedProof(owner, peer, identity.public.encoded, proof, true)
        assertTrue(consent().isVoiceVersion2Confirmed(owner, peer, identity.public.encoded))
        val authenticPositiveFile = f.backing.bytes!!.clone()
        repo.revoke(owner, peer)
        assertEquals(false, consent().isVoiceVersion2Confirmed(owner, peer, identity.public.encoded))
        f.backing.bytes = authenticPositiveFile
        assertThrows(VoiceCapabilityConsentException::class.java) {
            consent().isVoiceVersion2Confirmed(owner, peer, identity.public.encoded)
        }
    }

    @Test
    fun authenticOlderConsentFileIsRejectedAfterRevocationCommit() {
        val f = Fixture()
        val grant = byteArrayOf(1, 2, 3)
        val revoked = byteArrayOf(4, 5, 6)
        assertTrue(f.store.commitEncryptedConsent(grant))
        val olderAuthenticFile = f.backing.bytes!!.clone()
        assertTrue(f.store.commitEncryptedConsent(revoked))
        assertArrayEquals(revoked, f.newStore().readEncryptedConsent())
        f.backing.bytes = olderAuthenticFile
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().readEncryptedConsent()
        }
    }

    @Test
    fun freshAndExistingEpochsPersistAcrossObjectRecreation() {
        val f = Fixture()
        assertEquals(null, f.store.readEncryptedConsent())
        f.store.commitEncryptedConsent(byteArrayOf(1))
        assertArrayEquals(byteArrayOf(1), f.newStore().readEncryptedConsent())
        f.newStore().commitEncryptedConsent(byteArrayOf(2))
        assertArrayEquals(byteArrayOf(2), f.newStore().readEncryptedConsent())
        assertEquals(1, f.keys.epochIds().size)
    }

    @Test
    fun orphanKeyOrMissingFileIsNotTreatedAsFreshInstall() {
        val f = Fixture()
        f.store.commitEncryptedConsent(byteArrayOf(1))
        f.backing.bytes = null
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().readEncryptedConsent()
        }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().commitEncryptedConsent(byteArrayOf(2))
        }
    }

    @Test
    fun extraAliasOrLostActiveKeyFailsClosed() {
        val f = Fixture()
        f.store.commitEncryptedConsent(byteArrayOf(3))
        val active = f.keys.epochIds().single()
        f.keys.createEpoch()
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().readEncryptedConsent()
        }
        f.keys.retire(active)
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().readEncryptedConsent()
        }
    }

    @Test
    fun failedWriteLeavesUncertainNamespaceAndCannotReturnAnOldGrant() {
        for (failure in listOf("before", "after")) {
            val f = Fixture()
            f.store.commitEncryptedConsent(byteArrayOf(7))
            f.backing.failure = failure
            assertThrows(Exception::class.java) {
                f.store.commitEncryptedConsent(byteArrayOf(8))
            }
            assertThrows(VoiceCapabilityConsentException::class.java) {
                f.store.readEncryptedConsent()
            }
            assertThrows(VoiceCapabilityConsentException::class.java) {
                f.newStore().readEncryptedConsent()
            }
        }
    }

    @Test
    fun retirementErrorLeavesNoApprovableState() {
        val f = Fixture()
        f.store.commitEncryptedConsent(byteArrayOf(9))
        f.keys.failRetirement = true
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.store.commitEncryptedConsent(byteArrayOf(10))
        }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().readEncryptedConsent()
        }
    }

    @Test
    fun createKeyFailureAfterCreationDoesNotAllowASecondMutation() {
        val f = Fixture()
        f.keys.failAfterCreation = true
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.store.commitEncryptedConsent(byteArrayOf(1))
        }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().readEncryptedConsent()
        }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.store.commitEncryptedConsent(byteArrayOf(2))
        }
    }

    @Test
    fun tamperedAndLegacyEnvelopeNeverTriggersImplicitMigration() {
        val f = Fixture()
        f.store.commitEncryptedConsent(byteArrayOf(1))
        val original = f.backing.bytes!!.clone()
        f.backing.bytes = original.clone().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().readEncryptedConsent()
        }
        f.backing.bytes = byteArrayOf(1, 2, 3)
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().readEncryptedConsent()
        }
        f.backing.bytes = original + ByteArray(VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES + 128)
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.newStore().readEncryptedConsent()
        }
    }

    @Test
    fun concurrentConsentStoresSerializeEpochCommitAndReadWithinOneProcess() {
        val f = Fixture()
        val release = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(8)
        try {
            val writes = (1..8).map { n ->
                pool.submit(Callable {
                    check(release.await(10, TimeUnit.SECONDS))
                    f.newStore().commitEncryptedConsent(byteArrayOf(n.toByte()))
                })
            }
            release.countDown()
            writes.forEach { assertTrue(it.get(20, TimeUnit.SECONDS)) }
            assertEquals(1, f.keys.epochIds().size)
            val latest = requireNotNull(f.newStore().readEncryptedConsent())
            assertTrue(latest.single().toInt() in 1..8)
        } finally {
            release.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun destructiveClearIsExplicitlyUnimplemented() {
        val f = Fixture()
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.store.clearForIdentityRecovery()
        }
    }

    private class InnerAesGcmCipher : VoiceCapabilityPayloadCipher {
        private val key = SecretKeySpec(ByteArray(32) { 17 }, "AES")
        private val random = SecureRandom()
        override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
            val iv = ByteArray(12).also(random::nextBytes)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            c.updateAAD(aad)
            return byteArrayOf(1) + iv + c.doFinal(plaintext)
        }
        override fun encryptExisting(plaintext: ByteArray, aad: ByteArray): ByteArray =
            encrypt(plaintext, aad)
        override fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypted.copyOfRange(1, 13)))
            c.updateAAD(aad)
            return c.doFinal(encrypted.copyOfRange(13, encrypted.size))
        }
        override fun deleteCapabilityKeyForIdentityRecovery() {
            throw VoiceCapabilityConsentException("KCE2 recovery is not implemented")
        }
    }

    private class Fixture {
        val backing = MemoryRaw()
        val keys = TestKeys()
        val store = newStore()
        fun newStore() = EpochBoundVoiceConsentStore(backing, keys)
    }

    private class MemoryRaw : VoiceConsentEpochRawStore {
        var bytes: ByteArray? = null
        var failure: String? = null
        override fun read(): ByteArray? = bytes?.clone()
        override fun write(bytes: ByteArray): Boolean {
            if (failure == "before") return false
            this.bytes = bytes.clone()
            if (failure == "after") throw IllegalStateException("Simulated uncertain disk return")
            return true
        }
    }

    private class TestKeys : VoiceConsentEpochKeys {
        private val random = SecureRandom()
        private val epochKeys = linkedMapOf<String, SecretKeySpec>()
        private var next = 1
        var failAfterCreation = false
        var failRetirement = false

        override fun epochIds(): Set<String> = epochKeys.keys.toSet()
        override fun createEpoch(): String {
            val epoch = next++.toString(16).padStart(32, '0')
            epochKeys[epoch] = SecretKeySpec(ByteArray(32).also(random::nextBytes), "AES")
            if (failAfterCreation) throw VoiceCapabilityConsentException("Uncertain Keystore creation")
            return epoch
        }

        override fun seal(epoch: String, ciphertext: ByteArray, aad: ByteArray): ByteArray {
            val iv = ByteArray(12).also(random::nextBytes)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, requireNotNull(epochKeys[epoch]), GCMParameterSpec(128, iv))
            c.updateAAD(aad)
            return iv + c.doFinal(ciphertext)
        }

        override fun open(epoch: String, envelope: ByteArray, aad: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(
                Cipher.DECRYPT_MODE,
                requireNotNull(epochKeys[epoch]),
                GCMParameterSpec(128, envelope.copyOfRange(0, 12)),
            )
            c.updateAAD(aad)
            return c.doFinal(envelope.copyOfRange(12, envelope.size))
        }

        override fun retire(epoch: String) {
            if (failRetirement) throw VoiceCapabilityConsentException("Keystore retire failed")
            check(epochKeys.remove(epoch) != null)
        }
    }
}
