package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import com.sl.kenato.contact.PinnedContact
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceCapabilityOutOfBandServiceTest {
    @Test
    fun offlineTwoPhonePinnedP256ProofIsConsumedExactlyOnce() {
        val f = Fixture()
        val challenge = f.aliceService().issueChallengeQr(f.bobId)
        val proof = f.bobService().approveAndSignChallengeQr(
            f.aliceId, challenge, explicitUserApproval = true,
        )
        assertFalse(f.aliceConsent.isVoiceVersion2Confirmed(f.aliceId, f.bobId, f.bob.public.encoded))
        f.aliceService().approveAndImportProofQr(
            f.bobId, proof, explicitUserApproval = true,
        )
        assertTrue(f.aliceConsent.isVoiceVersion2Confirmed(f.aliceId, f.bobId, f.bob.public.encoded))
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.aliceService().approveAndImportProofQr(f.bobId, proof, true)
        }
    }

    @Test
    fun userRefusalNeverSignsOrConfirms() {
        val f = Fixture()
        val qr = f.aliceService().issueChallengeQr(f.bobId)
        assertThrows(VoiceCapabilityExchangeException::class.java) {
            f.bobService().approveAndSignChallengeQr(f.aliceId, qr, false)
        }
        assertFalse(f.aliceConsent.isVoiceVersion2Confirmed(f.aliceId, f.bobId, f.bob.public.encoded))
        val signed = f.bobService().approveAndSignChallengeQr(f.aliceId, qr, true)
        assertThrows(VoiceCapabilityExchangeException::class.java) {
            f.aliceService().approveAndImportProofQr(f.bobId, signed, false)
        }
        assertFalse(f.aliceConsent.isVoiceVersion2Confirmed(f.aliceId, f.bobId, f.bob.public.encoded))
        f.aliceService().approveAndImportProofQr(f.bobId, signed, true)
        assertTrue(f.aliceConsent.isVoiceVersion2Confirmed(f.aliceId, f.bobId, f.bob.public.encoded))
    }

    @Test
    fun unknownOrReplacedPinnedPeerCannotSignOrImportProof() {
        val f = Fixture()
        val challenge = f.aliceService().issueChallengeQr(f.bobId)
        val proof = f.bobService().approveAndSignChallengeQr(f.aliceId, challenge, true)
        f.bobContact = null
        assertThrows(VoiceCapabilityExchangeException::class.java) {
            f.aliceService().approveAndImportProofQr(f.bobId, proof, true)
        }
        f.bobContact = f.contact(f.bobId, f.bob)
        f.aliceContact = f.contact(f.aliceId, f.alice).copy(
            identityPublicKey = newKeys().public.encoded,
        )
        assertThrows(VoiceCapabilityExchangeException::class.java) {
            f.bobService().approveAndSignChallengeQr(f.aliceId, challenge, true)
        }
    }

    @Test
    fun crossIdentityQrCannotInduceSigning() {
        val f = Fixture()
        val challenge = f.aliceService().issueChallengeQr(f.bobId)
        val otherId = ByteArray(32) { 9 }
        assertThrows(VoiceCapabilityExchangeException::class.java) {
            f.bobService().approveAndSignChallengeQr(otherId, challenge, true)
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            f.aliceService().approveAndSignChallengeQr(f.bobId, challenge, true)
        }
    }

    @Test
    fun proofMustMatchTheCurrentlyPersistedVerifierNonce() {
        val f = Fixture()
        val firstQr = f.aliceService().issueChallengeQr(f.bobId)
        val oldProof = f.bobService().approveAndSignChallengeQr(f.aliceId, firstQr, true)
        val secondQr = f.aliceService().issueChallengeQr(f.bobId)
        assertTrue(firstQr != secondQr)
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.aliceService().approveAndImportProofQr(f.bobId, oldProof, true)
        }
        val latestProof = f.bobService().approveAndSignChallengeQr(f.aliceId, secondQr, true)
        f.aliceService().approveAndImportProofQr(f.bobId, latestProof, true)
        assertTrue(f.aliceConsent.isVoiceVersion2Confirmed(f.aliceId, f.bobId, f.bob.public.encoded))
    }

    private class Fixture {
        val alice = newKeys()
        val bob = newKeys()
        val aliceId = ContactCrypto.identityId(alice.public.encoded)
        val bobId = ContactCrypto.identityId(bob.public.encoded)
        val aliceConsent = newConsent()
        val bobConsent = newConsent()
        var bobContact: PinnedContact? = contact(bobId, bob)
        var aliceContact: PinnedContact? = contact(aliceId, alice)

        fun contact(id: ByteArray, keys: KeyPair): PinnedContact = PinnedContact(
            localId = ByteArray(16) { 5 },
            identityId = id.copyOf(),
            identityPublicKey = keys.public.encoded.copyOf(),
            pinnedAtEpochSeconds = NOW,
        )

        fun aliceService() = VoiceCapabilityOutOfBandService(
            identity = signer(alice, aliceId),
            pinned = VoicePinnedContactSource { owner, peer ->
                if (owner.contentEquals(aliceId) && peer.contentEquals(bobId)) bobContact else null
            },
            consent = aliceConsent,
            clock = VoiceCapabilityExchangeClock { NOW },
        )

        fun bobService() = VoiceCapabilityOutOfBandService(
            identity = signer(bob, bobId),
            pinned = VoicePinnedContactSource { owner, peer ->
                if (owner.contentEquals(bobId) && peer.contentEquals(aliceId)) aliceContact else null
            },
            consent = bobConsent,
            clock = VoiceCapabilityExchangeClock { NOW },
        )

        fun signer(keys: KeyPair, id: ByteArray) = object : VoiceCapabilityLocalSigner {
            override fun localIdentityId(): ByteArray = id.copyOf()
            override fun signProtocolPayload(payload: ByteArray): ByteArray =
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(keys.private)
                    update(payload)
                    sign()
                }
        }

        fun newConsent() = DurableVoiceCapabilityConsentRepository(
            MemoryStore(), JvmCipher(), SecureRandom(),
            VoiceCapabilityConsentClock { NOW },
        )
    }

    private class MemoryStore : VoiceCapabilityEncryptedStore {
        private var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(bytes: ByteArray): Boolean { this.bytes = bytes.copyOf(); return true }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class JvmCipher : VoiceCapabilityPayloadCipher {
        private val key = SecretKeySpec(ByteArray(32) { 0x41.toByte() }, "AES")
        private val random = SecureRandom()
        override fun deleteCapabilityKeyForIdentityRecovery() = Unit
        override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
            val iv = ByteArray(12).also(random::nextBytes)
            return Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
                updateAAD(aad)
                byteArrayOf(1) + iv + doFinal(plaintext)
            }
        }
        override fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray =
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypted.copyOfRange(1, 13)))
                updateAAD(aad)
                doFinal(encrypted.copyOfRange(13, encrypted.size))
            }
    }

    private companion object {
        const val NOW = 1_780_000_000L
        fun newKeys() = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
    }
}
