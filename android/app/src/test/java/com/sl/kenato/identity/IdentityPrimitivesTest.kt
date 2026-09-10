package com.sl.kenato.identity

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityPrimitivesTest {
    @Test
    fun identityIdMatchesDeterministicVector() {
        val publicKey = byteArrayOf(1, 2, 3, 4, 5)

        assertEquals(
            "dPgf4WfZm0y0HW0MzagieMrunz4vJdXlo5Nv89zsYNA",
            IdentityPrimitives.identityId(publicKey),
        )
    }

    @Test
    fun signedPreKeyPayloadMatchesDeterministicVector() {
        val payload = IdentityPrimitives.signedPreKeyPayload(
            id = 7,
            publicKey = byteArrayOf(1, 2, 3, 4, 5),
        )

        assertEquals(
            "4b454e41544f2d5349474e45442d5052454b45592d56310000000007000000050102030405",
            payload.toHex(),
        )
    }

    @Test
    fun p256SignatureVerifierAcceptsValidSignatureAndRejectsTampering() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = generator.generateKeyPair()
        val payload = "kenato-identity-test".toByteArray()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(payload)
            sign()
        }

        assertTrue(
            IdentityPrimitives.verifyP256Signature(
                keyPair.public.encoded,
                payload,
                signature,
            ),
        )
        assertFalse(
            IdentityPrimitives.verifyP256Signature(
                keyPair.public.encoded,
                payload + byteArrayOf(1),
                signature,
            ),
        )
    }

    private fun ByteArray.toHex(): String =
        joinToString(separator = "") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}
