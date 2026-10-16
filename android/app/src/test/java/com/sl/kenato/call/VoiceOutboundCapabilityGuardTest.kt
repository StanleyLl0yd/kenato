package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import com.sl.kenato.contact.PinnedContact
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceOutboundCapabilityGuardTest {
    @Test
    fun legacyOrUnknownPeerDeniedWithoutNetworkOrRatchetSideEffects() {
        val f = Fixture()
        assertThrows(VoiceOutboundEligibilityException::class.java) {
            f.guard().requireEligiblePeer(OWNER, f.peer)
        }
        assertTrue(f.capabilityStore.bytes == null)
        assertTrue(f.pinnedLookups > 0)
        assertTrue(f.sessionLookups > 0)
    }

    @Test
    fun genuineOneTimePeerAttestationAndMatchingPinnedM3BindingGrantOnlyPreflight() {
        val f = Fixture()
        f.approve()
        val verified = f.guard().requireEligiblePeer(OWNER, f.peer)
        assertArrayEquals(OWNER, verified.ownerIdentityId)
        assertArrayEquals(f.peer, verified.peerIdentityId)
        assertArrayEquals(CONTACT_ID, verified.localContactId)
        verified.localContactId[0] = 100
        assertArrayEquals(CONTACT_ID, f.currentContact!!.localId)
        assertArrayEquals(CONTACT_ID, f.activeLocalContactId!!)
    }

    @Test
    fun missingContactOrSessionOrDifferentSessionBindingNeverAllowsCall() {
        val f = Fixture()
        f.approve()
        f.currentContact = null
        assertThrows(VoiceOutboundEligibilityException::class.java) { f.guard().requireEligiblePeer(OWNER, f.peer) }
        f.currentContact = f.validContact()
        f.activeLocalContactId = null
        assertThrows(VoiceOutboundEligibilityException::class.java) { f.guard().requireEligiblePeer(OWNER, f.peer) }
        f.activeLocalContactId = ByteArray(16) { 9 }
        assertThrows(VoiceOutboundEligibilityException::class.java) { f.guard().requireEligiblePeer(OWNER, f.peer) }
    }

    @Test
    fun pinnedKeyOrLocalIdentitySubstitutionCannotBypassSignedConsent() {
        val f = Fixture()
        f.approve()
        val alien = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        f.currentContact = f.validContact().copy(identityPublicKey = alien.public.encoded)
        assertThrows(VoiceOutboundEligibilityException::class.java) { f.guard().requireEligiblePeer(OWNER, f.peer) }
        f.currentContact = f.validContact().copy(identityId = OWNER.copyOf())
        assertThrows(VoiceOutboundEligibilityException::class.java) { f.guard().requireEligiblePeer(OWNER, f.peer) }
        f.currentContact = f.validContact()
        assertThrows(VoiceOutboundEligibilityException::class.java) {
            f.guard().requireEligiblePeer(f.peer, f.peer)
        }
        assertThrows(VoiceOutboundEligibilityException::class.java) {
            f.guard().requireEligiblePeer(ByteArray(32), f.peer)
        }
    }

    @Test
    fun revocationAndEncryptedStateTamperingImmediatelyFailClosed() {
        val f = Fixture()
        f.approve()
        assertArrayEquals(CONTACT_ID, f.guard().requireEligiblePeer(OWNER, f.peer).localContactId)
        f.consent.revoke(OWNER, f.peer)
        assertThrows(VoiceOutboundEligibilityException::class.java) { f.guard().requireEligiblePeer(OWNER, f.peer) }

        val next = f.consent.issueChallenge(OWNER, f.peer, f.keys.public.encoded)
        f.confirm(next)
        f.capabilityStore.bytes = f.capabilityStore.bytes!!.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            f.guard().requireEligiblePeer(OWNER, f.peer)
        }
    }

    private class Fixture {
        val keys = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val peer: ByteArray = ContactCrypto.identityId(keys.public.encoded)
        val capabilityStore = MemoryStore()
        val consent = DurableVoiceCapabilityConsentRepository(
            capabilityStore, JvmCapabilityCipher(), SecureRandom(),
            VoiceCapabilityConsentClock { NOW },
        )
        var currentContact: PinnedContact? = validContact()
        var activeLocalContactId: ByteArray? = CONTACT_ID.copyOf()
        var pinnedLookups = 0
        var sessionLookups = 0

        fun validContact() = PinnedContact(
            localId = CONTACT_ID.copyOf(),
            identityId = peer.copyOf(),
            identityPublicKey = keys.public.encoded.copyOf(),
            pinnedAtEpochSeconds = NOW,
        )

        fun guard() = VoiceOutboundCapabilityGuard(
            pinned = VoicePinnedContactSource { owner, peerId ->
                pinnedLookups++
                if (owner.contentEquals(OWNER) && peerId.contentEquals(peer)) currentContact else null
            },
            sessions = VoiceSessionContactSource { owner, peerId ->
                sessionLookups++
                if (owner.contentEquals(OWNER) && peerId.contentEquals(peer)) {
                    activeLocalContactId?.copyOf()
                } else null
            },
            consent = consent,
        )

        fun approve() {
            val challenge = consent.issueChallenge(OWNER, peer, keys.public.encoded)
            confirm(challenge)
        }

        fun confirm(challenge: VoiceCapabilityChallenge) {
            val proof = VoiceCapabilityProofWire.sign(
                peer, OWNER, challenge.challenge, NOW, NOW + 300,
            ) { message ->
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(keys.private)
                    update(message)
                    sign()
                }
            }
            consent.confirmSignedProof(
                OWNER, peer, keys.public.encoded,
                VoiceCapabilityProofWire.encode(proof), true,
            )
        }
    }

    private class MemoryStore : VoiceCapabilityEncryptedStore {
        var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(bytes: ByteArray): Boolean {
            this.bytes = bytes.copyOf()
            return true
        }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class JvmCapabilityCipher : VoiceCapabilityPayloadCipher {
        private val key = SecretKeySpec(ByteArray(32) { 0x2A.toByte() }, "AES")
        private val random = SecureRandom()
        override fun deleteCapabilityKeyForIdentityRecovery() = Unit
        // This JVM-only fixture uses a stable test key; the Android implementation
        // enforces the no-key-creation replacement rule separately.
        override fun encryptExisting(plaintext: ByteArray, aad: ByteArray): ByteArray =
            encrypt(plaintext, aad)

        override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
            val nonce = ByteArray(12).also(random::nextBytes)
            return Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
                updateAAD(aad)
                byteArrayOf(1) + nonce + doFinal(plaintext)
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
        val OWNER = ByteArray(32) { 1 }
        val CONTACT_ID = ByteArray(16) { 3 }
    }
}
