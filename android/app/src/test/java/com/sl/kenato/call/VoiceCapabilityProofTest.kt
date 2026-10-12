package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceCapabilityProofTest {
    @Test
    fun pinnedP256SignedChallengeAuthenticatesOnlyExactPeerAndApplicationVersion() {
        val f = Fixture()
        val encoded = f.encoded()
        val verified = f.verify(encoded)
        assertArrayEquals(f.peer, verified.signerIdentityId)
        assertArrayEquals(f.owner, verified.verifierIdentityId)
        assertArrayEquals(f.challenge, verified.verifierChallenge)
        assertEquals(2, verified.applicationProtocolVersion)
        assertArrayEquals(encoded, VoiceCapabilityProofWire.encode(VoiceCapabilityProofWire.decode(encoded)))
    }

    @Test
    fun unknownOrLegacyPeerHasNoImplicitCallSupport() {
        val f = Fixture()
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.verify(byteArrayOf())
        }
        val encoded = f.encoded()
        assertThrows(VoiceCapabilityProofException::class.java) {
            VoiceCapabilityProofWire.verifyForPinnedContact(
                encoded, f.owner, f.peer, ByteArray(42) { 1 }, f.challenge, NOW,
            )
        }
    }

    @Test
    fun wrongVerifierPeerOrFreshChallengeRejectWithoutFallback() {
        val f = Fixture()
        val encoded = f.encoded()
        assertThrows(VoiceCapabilityProofException::class.java) {
            VoiceCapabilityProofWire.verifyForPinnedContact(
                encoded, ByteArray(32) { 0x55.toByte() },
                f.peer, f.keys.public.encoded, f.challenge, NOW,
            )
        }
        assertThrows(VoiceCapabilityProofException::class.java) {
            VoiceCapabilityProofWire.verifyForPinnedContact(
                encoded, f.owner, ByteArray(32) { 0x77.toByte() },
                f.keys.public.encoded, f.challenge, NOW,
            )
        }
        assertThrows(VoiceCapabilityProofException::class.java) {
            VoiceCapabilityProofWire.verifyForPinnedContact(
                encoded, f.owner, f.peer, f.keys.public.encoded,
                ByteArray(16) { 0x66.toByte() }, NOW,
            )
        }
    }

    @Test
    fun expiredFutureDatedAndOversizedLifetimeReject() {
        val f = Fixture()
        val encoded = f.encoded()
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.verify(encoded, now = NOW + 300)
        }
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.verify(f.encoded(issued = NOW + 31, expiry = NOW + 300))
        }
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.encoded(issued = NOW, expiry = NOW + 301)
        }
        assertTrue(f.verify(f.encoded(issued = NOW + 30, expiry = NOW + 300)).expiresAtEpochSeconds > NOW)
    }

    @Test
    fun tamperReplayOrUnknownVersionFailsClosed() {
        val f = Fixture()
        val encoded = f.encoded()
        val signatureCorrupt = encoded.copyOf().also { it[it.size - 1] = (it.last().toInt() xor 1).toByte() }
        assertThrows(VoiceCapabilityProofException::class.java) { f.verify(signatureCorrupt) }
        val versionCorrupt = encoded.copyOf().also { it[7] = 3 }
        assertThrows(VoiceCapabilityProofException::class.java) { f.verify(versionCorrupt) }
        assertThrows(VoiceCapabilityProofException::class.java) { f.verify(encoded + byteArrayOf(0)) }
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.verify(encoded.copyOf(encoded.size - 1))
        }
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.verify(encoded.copyOf().also { it[0] = 0 })
        }
    }

    @Test
    fun signedButSubstitutedPublicKeyCannotImpersonatePinnedPeer() {
        val f = Fixture()
        val alien = Fixture()
        assertThrows(VoiceCapabilityProofException::class.java) {
            VoiceCapabilityProofWire.verifyForPinnedContact(
                f.encoded(), f.owner, f.peer, alien.keys.public.encoded, f.challenge, NOW,
            )
        }
        val stolenNonce = alien.proofWithIds(f.peer, f.owner, f.challenge)
        assertThrows(VoiceCapabilityProofException::class.java) { f.verify(stolenNonce) }
    }

    @Test
    fun zeroAndSelfIdentityProofsCannotBeSigned() {
        val f = Fixture()
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.proofWithIds(ByteArray(32), f.owner, f.challenge)
        }
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.proofWithIds(f.peer, f.peer, f.challenge)
        }
        assertThrows(VoiceCapabilityProofException::class.java) {
            f.proofWithIds(f.peer, f.owner, ByteArray(16))
        }
    }

    private class Fixture {
        val keys = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val peer = ContactCrypto.identityId(keys.public.encoded)
        val owner = ByteArray(32) { 0x22.toByte() }
        val challenge = ByteArray(16) { 0x33.toByte() }

        fun encoded(issued: Long = NOW, expiry: Long = NOW + 300): ByteArray =
            proofWithIds(peer, owner, challenge, issued, expiry)

        fun proofWithIds(
            signer: ByteArray,
            verifier: ByteArray,
            challenge: ByteArray,
            issued: Long = NOW,
            expiry: Long = NOW + 300,
        ): ByteArray = VoiceCapabilityProofWire.encode(
            VoiceCapabilityProofWire.sign(
                signer, verifier, challenge, issued, expiry,
            ) { payload ->
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(keys.private)
                    update(payload)
                    sign()
                }
            },
        )

        fun verify(proof: ByteArray, now: Long = NOW): VoiceCapabilityProof =
            VoiceCapabilityProofWire.verifyForPinnedContact(
                proof, owner, peer, keys.public.encoded, challenge, now,
            )
    }

    private companion object {
        const val NOW = 1_780_000_000L
    }
}
