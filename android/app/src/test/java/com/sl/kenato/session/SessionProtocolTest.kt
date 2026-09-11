package com.sl.kenato.session

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SessionProtocolTest {
    @Test
    fun bootstrapPayloadMatchesM3Vector() {
        val bundle = SessionBootstrapBundle(
            identityId = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            accountGeneration = 2,
            publicationRevision = 3,
            olmEd25519IdentityKey = hex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"),
            olmCurve25519IdentityKey = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            oneTimePreKeys = listOf(
                SessionOneTimePreKey(7, hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")),
                SessionOneTimePreKey(8, hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")),
            ),
            bindingSignature = ByteArray(0),
        )

        assertArrayEquals(
            hex(
                "4b454e41544f2d53455353494f4e2d424f4f5453545241502d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "00000000000000020000000000000003" +
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
                    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                    "000000020000000000000007" +
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                    "0000000000000008" +
                    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
            ),
            SessionCanonical.bootstrapPayload(bundle),
        )
    }

    @Test
    fun reservationPayloadMatchesM3Vector() {
        assertArrayEquals(
            hex(
                "4b454e41544f2d53455353494f4e2d524553455256452d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            ),
            SessionCanonical.reservePayload(creatorId(), redeemerId(), inviteToken()),
        )
    }

    @Test
    fun submitPayloadMatchesM3Vector() {
        val request = SessionSubmitInit(
            creatorIdentityId = creatorId(),
            redeemerIdentityId = redeemerId(),
            inviteToken = inviteToken(),
            creatorAccountGeneration = 2,
            creatorOneTimePreKeyId = 7,
            redeemerAccountGeneration = 4,
            olmMessageType = 0,
            olmMessage = "opaque-pre-key-frame".toByteArray(),
        )

        assertArrayEquals(
            hex(
                "4b454e41544f2d53455353494f4e2d494e49542d5355424d49542d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
                    "00000000000000020000000000000007000000000000000400000000" +
                    "cfaac14d99379ff5a9887f3342cca9eaaa70803f570bf7e8913aef9b0403e9e4",
            ),
            SessionCanonical.submitPayload(request),
        )
    }

    @Test
    fun initControlPayloadMatchesM3Vector() {
        assertArrayEquals(
            hex(
                "4b454e41544f2d53455353494f4e2d494e49542d434f4e54524f4c2d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                    "ca2a4fe727faaecf16ecd130a86e0885c5540c05375340445071c0657555fd42" +
                    "000000000000000200000000000000070000000000000004",
            ),
            SessionCanonical.initControlPayload(
                creatorId(),
                redeemerId(),
                inviteToken(),
                2,
                7,
                4,
            ),
        )
    }

    @Test
    fun claimPayloadMatchesM3Vector() {
        assertArrayEquals(
            hex(
                "4b454e41544f2d53455353494f4e2d434c41494d2d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            ),
            SessionCanonical.claimPayload(creatorId(), inviteToken()),
        )
    }

    @Test
    fun malformedBootstrapAndSubmitShapesFailClosed() {
        val duplicateKey = ByteArray(32) { 0x31 }
        val invalidBundle = SessionBootstrapBundle(
            identityId = creatorId(),
            accountGeneration = 1,
            publicationRevision = 1,
            olmEd25519IdentityKey = ByteArray(32) { 0x21 },
            olmCurve25519IdentityKey = ByteArray(32) { 0x22 },
            oneTimePreKeys = listOf(
                SessionOneTimePreKey(1, duplicateKey),
                SessionOneTimePreKey(2, duplicateKey.copyOf()),
            ),
            bindingSignature = ByteArray(0),
        )
        assertThrows(SessionStateException::class.java) {
            SessionCanonical.bootstrapPayload(invalidBundle)
        }

        assertThrows(SessionStateException::class.java) {
            SessionCanonical.submitPayload(
                SessionSubmitInit(
                    creatorId(),
                    redeemerId(),
                    inviteToken(),
                    1,
                    1,
                    1,
                    SESSION_OLM_MESSAGE_NORMAL,
                    byteArrayOf(1),
                ),
            )
        }
    }

    private fun creatorId(): ByteArray = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

    private fun redeemerId(): ByteArray = hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")

    private fun inviteToken(): ByteArray = hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0)
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
