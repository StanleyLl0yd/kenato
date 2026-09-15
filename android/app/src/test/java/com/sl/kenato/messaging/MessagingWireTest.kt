package com.sl.kenato.messaging

import com.sl.kenato.session.SESSION_OLM_MESSAGE_NORMAL
import com.sl.kenato.session.SessionCiphertext
import com.sl.kenato.session.SessionCiphertextWire
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingWireTest {
    @Test
    fun plaintextAndEnvelopeUseCanonicalFieldOrderAndRoundTrip() {
        val sender = bytes(0x11, 32)
        val recipient = bytes(0x22, 32)
        val messageId = bytes(0x33, 16)
        val plaintext = MessagingPlaintext(
            senderIdentityId = sender,
            recipientIdentityId = recipient,
            messageId = messageId,
            sentAtEpochSeconds = 1_700_000_000,
            expiresAtEpochSeconds = 1_700_003_600,
            text = "hello µ",
        )
        val encodedPlaintext = MessagingWire.encodePlaintext(plaintext)
        assertArrayEquals(
            proto {
                uint(1, 1)
                bytes(2, sender)
                bytes(3, recipient)
                bytes(4, messageId)
                uint(5, 1_700_000_000)
                uint(6, 1_700_003_600)
                bytes(7, "hello µ".toByteArray(StandardCharsets.UTF_8))
            },
            encodedPlaintext,
        )
        val decodedPlaintext = MessagingWire.decodePlaintext(encodedPlaintext)
        assertEquals(plaintext.text, decodedPlaintext.text)
        assertArrayEquals(messageId, decodedPlaintext.messageId)

        val crypto = SessionCiphertextWire.encode(
            SessionCiphertext(
                senderIdentityId = sender,
                recipientIdentityId = recipient,
                senderAccountGeneration = 3,
                recipientAccountGeneration = 4,
                olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
                olmMessage = byteArrayOf(1, 2, 3),
            ),
        )
        val envelope = MessagingEnvelope(
            senderIdentityId = sender,
            recipientIdentityId = recipient,
            messageId = messageId,
            ciphertext = crypto,
            expiresAtEpochSeconds = 1_700_003_600,
        )
        val encodedEnvelope = MessagingWire.encodeEnvelope(envelope)
        assertArrayEquals(
            proto {
                uint(1, 1)
                bytes(2, recipient)
                bytes(3, messageId)
                bytes(4, crypto)
                uint(5, 1_700_003_600)
                bytes(6, sender)
            },
            encodedEnvelope,
        )
        val decodedEnvelope = MessagingWire.decodeEnvelope(encodedEnvelope)
        assertArrayEquals(sender, decodedEnvelope.senderIdentityId)
        assertArrayEquals(recipient, decodedEnvelope.recipientIdentityId)
        assertArrayEquals(crypto, decodedEnvelope.ciphertext)
    }

    @Test
    fun allClientAndServerFrameVariantsRoundTrip() {
        val sender = bytes(0x11, 32)
        val recipient = bytes(0x22, 32)
        val messageId = bytes(0x33, 16)
        val challenge = bytes(0x44, 32)
        val envelope = MessagingEnvelope(
            senderIdentityId = sender,
            recipientIdentityId = recipient,
            messageId = messageId,
            ciphertext = byteArrayOf(1),
            expiresAtEpochSeconds = 1234,
        )

        val clientFrames = listOf(
            MessagingClientFrame(
                authResponse = MessagingAuthResponse(
                    identityId = sender,
                    challenge = challenge,
                    expiresAtEpochSeconds = 120,
                    signature = byteArrayOf(0x30, 1),
                ),
            ),
            MessagingClientFrame(send = envelope),
            MessagingClientFrame(ack = MessagingDeliveryAck(sender, messageId)),
        )
        clientFrames.forEach { frame ->
            val decoded = MessagingWire.decodeClientFrame(MessagingWire.encodeClientFrame(frame))
            assertEquals(frame.protocolVersion, decoded.protocolVersion)
            when {
                frame.authResponse != null -> assertNotNull(decoded.authResponse)
                frame.send != null -> assertNotNull(decoded.send)
                frame.ack != null -> assertNotNull(decoded.ack)
            }
        }

        val serverFrames = listOf(
            MessagingServerFrame(authChallenge = MessagingAuthChallenge(challenge, 120)),
            MessagingServerFrame(authenticated = true),
            MessagingServerFrame(delivery = envelope),
            MessagingServerFrame(sendAccepted = MessagingSendAccepted(recipient, messageId)),
            MessagingServerFrame(error = MessagingWireError(MESSAGING_ERROR_RETRY_LATER, messageId)),
        )
        serverFrames.forEach { frame ->
            val decoded = MessagingWire.decodeServerFrame(MessagingWire.encodeServerFrame(frame))
            assertEquals(frame.protocolVersion, decoded.protocolVersion)
            when {
                frame.authChallenge != null -> assertNotNull(decoded.authChallenge)
                frame.authenticated -> assertTrue(decoded.authenticated)
                frame.delivery != null -> assertNotNull(decoded.delivery)
                frame.sendAccepted != null -> assertNotNull(decoded.sendAccepted)
                frame.error != null -> assertNotNull(decoded.error)
            }
        }
    }

    @Test
    fun unknownOuterFieldsAreCompatibleButDuplicatePayloadsFailClosed() {
        val sender = bytes(0x11, 32)
        val challenge = bytes(0x22, 32)
        val auth = MessagingAuthResponse(sender, challenge, 123, byteArrayOf(1))
        val encoded = MessagingWire.encodeClientFrame(MessagingClientFrame(authResponse = auth))
        val compatible = encoded + proto { uint(30, 9) }
        assertNotNull(MessagingWire.decodeClientFrame(compatible).authResponse)

        val nested = proto {
            uint(1, 1)
            bytes(2, sender)
            bytes(3, challenge)
            uint(4, 123)
            bytes(5, byteArrayOf(1))
        }
        val duplicatePayload = proto {
            uint(1, 1)
            bytes(2, nested)
            bytes(2, nested)
        }
        assertThrows(MessagingProtocolException::class.java) {
            MessagingWire.decodeClientFrame(duplicatePayload)
        }

        val duplicateNested = proto {
            uint(1, 1)
            bytes(2, sender)
            bytes(2, sender)
            bytes(3, challenge)
            uint(4, 123)
            bytes(5, byteArrayOf(1))
        }
        assertThrows(MessagingProtocolException::class.java) {
            MessagingWire.decodeClientFrame(proto {
                uint(1, 1)
                bytes(2, duplicateNested)
            })
        }
    }

    @Test
    fun malformedUtf8AndOversizedFramesFailClosed() {
        val malformedPlaintext = proto {
            uint(1, 1)
            bytes(2, bytes(0x11, 32))
            bytes(3, bytes(0x22, 32))
            bytes(4, bytes(0x33, 16))
            uint(5, 1)
            uint(6, 2)
            bytes(7, byteArrayOf(0xc3.toByte(), 0x28))
        }
        assertThrows(MessagingProtocolException::class.java) {
            MessagingWire.decodePlaintext(malformedPlaintext)
        }
        assertThrows(MessagingProtocolException::class.java) {
            MessagingWire.decodeServerFrame(ByteArray(MESSAGING_MAX_WIRE_FRAME_BYTES + 1))
        }
    }

    @Test
    fun m4EnvelopeAppliesTighterBoundThanM3SessionCiphertextCodec() {
        val sender = bytes(0x11, 32)
        val recipient = bytes(0x22, 32)
        val encodedM3 = SessionCiphertextWire.encode(
            SessionCiphertext(
                senderIdentityId = sender,
                recipientIdentityId = recipient,
                senderAccountGeneration = 1,
                recipientAccountGeneration = 2,
                olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
                olmMessage = ByteArray(MESSAGING_MAX_CIPHERTEXT_BYTES) { 1 },
            ),
        )
        assertTrue(encodedM3.size > MESSAGING_MAX_CIPHERTEXT_BYTES)
        assertThrows(MessagingProtocolException::class.java) {
            MessagingWire.encodeEnvelope(
                MessagingEnvelope(
                    senderIdentityId = sender,
                    recipientIdentityId = recipient,
                    messageId = bytes(0x33, 16),
                    ciphertext = encodedM3,
                    expiresAtEpochSeconds = 123,
                ),
            )
        }
    }

    private class ProtoBuilder {
        private val output = ByteArrayOutputStream()

        fun uint(field: Int, value: Long) {
            varint((field.toLong() shl 3) or 0)
            varint(value)
        }

        fun bytes(field: Int, value: ByteArray) {
            varint((field.toLong() shl 3) or 2)
            varint(value.size.toLong())
            output.write(value)
        }

        fun result(): ByteArray = output.toByteArray()

        private fun varint(value: Long) {
            var remaining = value
            while (remaining and -128L != 0L) {
                output.write(((remaining and 0x7f) or 0x80).toInt())
                remaining = remaining ushr 7
            }
            output.write(remaining.toInt())
        }
    }

    private fun proto(block: ProtoBuilder.() -> Unit): ByteArray = ProtoBuilder().apply(block).result()

    private fun bytes(value: Int, count: Int): ByteArray = ByteArray(count) { value.toByte() }
}
