package com.sl.kenato.messaging

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class MessagingProtocolTest {
    @Test
    fun authPayloadMatchesM4Vector() {
        assertArrayEquals(
            hex(
                "4b454e41544f2d4d4553534147494e472d415554482d563100" +
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                    "000000006553f11e",
            ),
            MessagingProtocol.authPayload(sequence(0x00, 32), sequence(0x20, 32), 1_700_000_030L),
        )
    }

    @Test
    fun authResponseIsBoundToExactConnectionChallenge() {
        val challenge = MessagingAuthChallenge(sequence(1, 32), 1_030)
        val response = MessagingAuthResponse(sequence(0x40, 32), challenge.challenge.copyOf(), 1_030, byteArrayOf(1))
        MessagingProtocol.validateAuthResponseForChallenge(response, challenge, 1_000)

        val mismatch = response.copy(challenge = response.challenge.copyOf().also { it[0] = (it[0].toInt() xor 0xff).toByte() })
        assertThrows(MessagingProtocolException::class.java) {
            MessagingProtocol.validateAuthResponseForChallenge(mismatch, challenge, 1_000)
        }
        assertThrows(MessagingProtocolException::class.java) {
            MessagingProtocol.validateAuthChallenge(challenge, 1_030)
        }
    }

    @Test
    fun deliveryContextRejectsRelayMetadataRewrite() {
        val now = 1_700_000_000L
        val sender = sequence(0x00, 32)
        val recipient = sequence(0x20, 32)
        val messageId = sequence(0x40, 16)
        val expires = now + 3_600
        val envelope = MessagingEnvelope(sender, recipient, messageId, byteArrayOf(1, 2, 3), expires)
        val plaintext = MessagingPlaintext(sender.copyOf(), recipient.copyOf(), messageId.copyOf(), now, expires, "hello")
        MessagingProtocol.validateDeliveryContext(envelope, plaintext, now)

        val rewritten = plaintext.copy(messageId = plaintext.messageId.copyOf().also { it[0] = (it[0].toInt() xor 0xff).toByte() })
        assertThrows(MessagingProtocolException::class.java) {
            MessagingProtocol.validateDeliveryContext(envelope, rewritten, now)
        }
    }

    @Test
    fun ttlAndTextBoundsFailClosed() {
        val now = 10_000L
        val validEnvelope = MessagingEnvelope(
            sequence(0x00, 32),
            sequence(0x20, 32),
            sequence(0x40, 16),
            byteArrayOf(1),
            now + MESSAGING_MAX_TTL_SECONDS,
        )
        MessagingProtocol.validateEnvelope(validEnvelope, now)
        assertThrows(MessagingProtocolException::class.java) {
            MessagingProtocol.validateEnvelope(validEnvelope.copy(expiresAtEpochSeconds = validEnvelope.expiresAtEpochSeconds + 1), now)
        }
        assertThrows(MessagingProtocolException::class.java) {
            MessagingProtocol.validateEnvelope(validEnvelope.copy(expiresAtEpochSeconds = now), now)
        }

        val plaintext = MessagingPlaintext(
            sequence(0x00, 32),
            sequence(0x20, 32),
            sequence(0x40, 16),
            now,
            now + 1,
            "x",
        )
        MessagingProtocol.validatePlaintext(plaintext)
        assertThrows(MessagingProtocolException::class.java) {
            MessagingProtocol.validatePlaintext(plaintext.copy(text = "x".repeat(MESSAGING_MAX_TEXT_BYTES + 1)))
        }
    }

    private fun sequence(start: Int, size: Int): ByteArray = ByteArray(size) { index -> (start + index).toByte() }

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0)
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
