package com.sl.kenato.contact

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ContactProtocolTest {
    @Test
    fun publicationCanonicalPayloadMatchesM2Vector() {
        val bundle = M2PublicIdentityBundle(
            identityId = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            identityPublicKey = hex("010203"),
            publicationRevision = 3,
            signedPreKey = M2SignedPreKey(
                id = 7,
                publicKey = hex("040506"),
                signature = hex("070809"),
                createdAtEpochSeconds = 10,
            ),
            oneTimePreKeys = listOf(
                M2OneTimePreKey(8, hex("0a0b"), 11),
                M2OneTimePreKey(9, hex("0c"), 12),
            ),
            publicationSignature = ByteArray(0),
        )

        assertArrayEquals(
            hex(
                "4b454e41544f2d5055424c49434154494f4e2d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "00000000000000030000000301020300000007000000000000000a" +
                    "00000003040506000000030708090000000200000008000000000000000b" +
                    "000000020a0b00000009000000000000000c000000010c",
            ),
            ContactCanonical.publicationPayload(bundle),
        )
    }

    @Test
    fun inviteRedemptionAndClaimPayloadsMatchM2Vectors() {
        val creator = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        val token = hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
        val redeemer = hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")

        assertArrayEquals(
            hex(
                "4b454e41544f2d494e564954452d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            ),
            ContactCanonical.invitePayload(creator, token),
        )
        assertArrayEquals(
            hex(
                "4b454e41544f2d52454445454d2d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            ),
            ContactCanonical.redemptionPayload(creator, redeemer, token),
        )
        assertArrayEquals(
            hex(
                "4b454e41544f2d434c41494d2d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            ),
            ContactCanonical.claimPayload(creator, token),
        )
    }

    @Test
    fun inviteUriMatchesVectorAndRoundTrips() {
        val invite = M2InviteDescriptor(
            creatorIdentityId = ByteArray(CONTACT_ID_BYTES) { it.toByte() },
            token = ByteArray(INVITE_TOKEN_BYTES) { (it + 0x20).toByte() },
            signature = byteArrayOf(0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte()),
        )
        val expected = "kenato://invite/v1/" +
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8/" +
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8/qrvM"

        val encoded = InviteUriCodec.encode(invite)
        val decoded = InviteUriCodec.decode(encoded)

        assertEquals(expected, encoded)
        assertArrayEquals(invite.creatorIdentityId, decoded.creatorIdentityId)
        assertArrayEquals(invite.token, decoded.token)
        assertArrayEquals(invite.signature, decoded.signature)
    }

    @Test
    fun inviteUriRejectsNonCanonicalAndUnexpectedStructure() {
        val valid = "kenato://invite/v1/" +
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8/" +
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8/qrvM"
        val invalid = listOf(
            valid.replace("kenato://", "https://"),
            valid.replace("invite/v1", "other/v1"),
            valid.replace("/v1/", "/v2/"),
            "$valid/extra",
            "$valid?x=1",
            "$valid#fragment",
            valid.replace("qrvM", "qrvM="),
            valid.replace("qrvM", "%71rvM"),
        )

        invalid.forEach { value ->
            assertThrows(ContactProtocolException::class.java) { InviteUriCodec.decode(value) }
        }
    }

    @Test
    fun bundleVerificationRejectsIdentitySubstitutionAndBadCurve() {
        val identity = newKeyPair("secp256r1")
        val signedPreKey = newKeyPair("secp256r1")
        val oneTimePreKey = newKeyPair("secp256r1")
        val identityId = ContactCrypto.identityId(identity.public.encoded)
        val signed = M2SignedPreKey(
            id = 7,
            publicKey = signedPreKey.public.encoded,
            signature = sign(identity, ContactCanonical.signedPreKeyPayload(7, signedPreKey.public.encoded)),
            createdAtEpochSeconds = 10,
        )
        var bundle = M2PublicIdentityBundle(
            identityId = identityId,
            identityPublicKey = identity.public.encoded,
            publicationRevision = 1,
            signedPreKey = signed,
            oneTimePreKeys = listOf(M2OneTimePreKey(8, oneTimePreKey.public.encoded, 11)),
            publicationSignature = ByteArray(0),
        )
        bundle = bundle.copy(publicationSignature = sign(identity, ContactCanonical.publicationPayload(bundle)))
        ContactCrypto.verifyPublicIdentityBundle(bundle)

        val substitutedId = bundle.identityId.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertThrows(ContactProtocolException::class.java) {
            ContactCrypto.verifyPublicIdentityBundle(bundle.copy(identityId = substitutedId))
        }

        val p384 = newKeyPair("secp384r1")
        assertThrows(ContactProtocolException::class.java) {
            ContactCrypto.canonicalP256PublicKey(p384.public.encoded)
        }
    }

    private fun newKeyPair(curve: String): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec(curve))
        generateKeyPair()
    }

    private fun sign(keyPair: KeyPair, payload: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(payload)
            sign()
        }

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0)
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
