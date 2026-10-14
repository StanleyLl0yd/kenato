package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceCapabilityQrWireTest {
    @Test
    fun canonicalQrChallengeAndRealPinnedSignedProofRoundTrip() {
        val verifierKeys = newIdentity()
        val signerKeys = newIdentity()
        val verifier = ContactCrypto.identityId(verifierKeys.public.encoded)
        val signer = ContactCrypto.identityId(signerKeys.public.encoded)
        val original = VoiceCapabilityChallenge(verifier, signer, NONCE, NOW + 300)

        val challengeQr = VoiceCapabilityQrWire.encodeChallenge(original)
        assertTrue(challengeQr.startsWith("kenato-voice-v2:challenge:"))
        assertEquals(challengeQr, VoiceCapabilityQrWire.encodeChallenge(
            VoiceCapabilityQrWire.decodeChallenge(challengeQr, verifier, signer, NOW),
        ))
        val decoded = VoiceCapabilityQrWire.decodeChallenge(challengeQr, verifier, signer, NOW)
        assertArrayEquals(NONCE, decoded.challenge)

        // The signer must separately confirm the pinned verifier and approve
        // disclosure. Only the proof's P-256 signature is authenticated.
        val signed = VoiceCapabilityProofWire.sign(
            signer, verifier, decoded.challenge, NOW, NOW + 300,
        ) { payload ->
            Signature.getInstance("SHA256withECDSA").run {
                initSign(signerKeys.private)
                update(payload)
                sign()
            }
        }
        val proofQr = VoiceCapabilityQrWire.encodeProof(signed)
        val importedBytes = VoiceCapabilityQrWire.decodeProof(proofQr)
        val authenticated = VoiceCapabilityProofWire.verifyForPinnedContact(
            importedBytes, verifier, signer, signerKeys.public.encoded, NONCE, NOW,
        )
        assertArrayEquals(signer, authenticated.signerIdentityId)
        assertArrayEquals(NONCE, authenticated.verifierChallenge)
    }

    @Test
    fun wrongIdentityExpiredChallengeAndUnknownQrTypesFailClosed() {
        val verifier = ByteArray(32) { 1 }
        val signer = ByteArray(32) { 2 }
        val record = VoiceCapabilityQrWire.encodeChallenge(
            VoiceCapabilityChallenge(verifier, signer, NONCE, NOW + 300),
        )
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeChallenge(record, signer, verifier, NOW)
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeChallenge(record, verifier, signer, NOW + 300)
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeChallenge(record, verifier, signer, NOW - 1)
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeProof(record)
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeChallenge("kenato-voice-v3:challenge:" + "A".repeat(120), verifier, signer, NOW)
        }
    }

    @Test
    fun malformedOversizedAndNoncanonicalBase64AreRejected() {
        val verifier = ByteArray(32) { 1 }
        val signer = ByteArray(32) { 2 }
        val valid = VoiceCapabilityQrWire.encodeChallenge(
            VoiceCapabilityChallenge(verifier, signer, NONCE, NOW + 300),
        )
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeChallenge(valid + "=", verifier, signer, NOW)
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeChallenge(valid + "%2F", verifier, signer, NOW)
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeChallenge(valid + "A".repeat(513), verifier, signer, NOW)
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeChallenge(valid + "\n", verifier, signer, NOW)
        }
    }

    @Test
    fun structurallyCorruptedQrPayloadCannotBecomeChallengeOrProof() {
        val verifier = ByteArray(32) { 1 }
        val signer = ByteArray(32) { 2 }
        val valid = VoiceCapabilityQrWire.encodeChallenge(
            VoiceCapabilityChallenge(verifier, signer, NONCE, NOW + 300),
        )
        val prefix = "kenato-voice-v2:challenge:"
        val bytes = Base64.getUrlDecoder().decode(valid.substring(prefix.length))
        bytes[0] = (bytes[0].toInt() xor 1).toByte()
        val corrupted = prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.decodeChallenge(corrupted, verifier, signer, NOW)
        }
        assertThrows(VoiceCapabilityProofException::class.java) {
            VoiceCapabilityQrWire.decodeProof(
                "kenato-voice-v2:proof:" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
            )
        }
    }

    @Test
    fun zeroOrDuplicateIdentityCannotBeExportedAsChallenge() {
        val owner = ByteArray(32) { 1 }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.encodeChallenge(
                VoiceCapabilityChallenge(owner, owner, NONCE, NOW + 300),
            )
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.encodeChallenge(
                VoiceCapabilityChallenge(owner, ByteArray(32), NONCE, NOW + 300),
            )
        }
        assertThrows(VoiceCapabilityQrException::class.java) {
            VoiceCapabilityQrWire.encodeChallenge(
                VoiceCapabilityChallenge(owner, ByteArray(32) { 2 }, ByteArray(16), NOW + 300),
            )
        }
    }

    private fun newIdentity() = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    private companion object {
        const val NOW = 1_780_000_000L
        val NONCE = ByteArray(16) { 7 }
    }
}
