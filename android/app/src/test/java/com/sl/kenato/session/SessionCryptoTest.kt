package com.sl.kenato.session

import com.sl.kenato.contact.ContactCrypto
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertThrows
import org.junit.Test

class SessionCryptoTest {
    @Test
    fun signedBootstrapVerifiesOnlyAgainstPinnedIdentity() {
        val owner = keyPair()
        val identityId = ContactCrypto.identityId(owner.public.encoded)
        val unsigned = bundle(identityId, ByteArray(0))
        val signed = unsigned.copy(
            bindingSignature = sign(owner.private, SessionCanonical.bootstrapPayload(unsigned)),
        )

        SessionCrypto.verifyBootstrapBundle(signed, identityId, owner.public.encoded)

        val attacker = keyPair()
        assertThrows(SessionStateException::class.java) {
            SessionCrypto.verifyBootstrapBundle(signed, identityId, attacker.public.encoded)
        }
    }

    @Test
    fun modifiedSessionMaterialBreaksPinnedBinding() {
        val owner = keyPair()
        val identityId = ContactCrypto.identityId(owner.public.encoded)
        val unsigned = bundle(identityId, ByteArray(0))
        val signed = unsigned.copy(
            bindingSignature = sign(owner.private, SessionCanonical.bootstrapPayload(unsigned)),
        )
        val substituted = signed.copy(
            olmCurve25519IdentityKey = ByteArray(32) { 0x23 },
        )

        assertThrows(SessionStateException::class.java) {
            SessionCrypto.verifyBootstrapBundle(substituted, identityId, owner.public.encoded)
        }
    }

    private fun bundle(identityId: ByteArray, signature: ByteArray): SessionBootstrapBundle =
        SessionBootstrapBundle(
            identityId = identityId,
            accountGeneration = 1,
            publicationRevision = 1,
            olmEd25519IdentityKey = ByteArray(32) { 0x21 },
            olmCurve25519IdentityKey = ByteArray(32) { 0x22 },
            oneTimePreKeys = listOf(SessionOneTimePreKey(1, ByteArray(32) { 0x31 })),
            bindingSignature = signature,
        )

    private fun keyPair() = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    private fun sign(privateKey: java.security.PrivateKey, payload: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(payload)
            sign()
        }
}
