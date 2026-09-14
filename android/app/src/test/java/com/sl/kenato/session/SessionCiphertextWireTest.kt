package com.sl.kenato.session

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SessionCiphertextWireTest {
    @Test
    fun ciphertextRoundTripsAndUsesCanonicalFieldOrder() {
        val original = SessionCiphertext(
            senderIdentityId = bytes(0x11, 32),
            recipientIdentityId = bytes(0x22, 32),
            senderAccountGeneration = 3,
            recipientAccountGeneration = 7,
            olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
            olmMessage = byteArrayOf(0x31, 0x32, 0x33),
        )

        val encoded = SessionCiphertextWire.encode(original)
        val expected = proto {
            uint(1, SESSION_PROTOCOL_VERSION.toLong())
            bytes(2, original.senderIdentityId)
            bytes(3, original.recipientIdentityId)
            uint(4, 3)
            uint(5, 7)
            uint(6, SESSION_OLM_MESSAGE_NORMAL.toLong())
            bytes(7, original.olmMessage)
        }
        assertArrayEquals(expected, encoded)

        val decoded = SessionCiphertextWire.decode(encoded)
        assertEquals(SESSION_PROTOCOL_VERSION, decoded.protocolVersion)
        assertArrayEquals(original.senderIdentityId, decoded.senderIdentityId)
        assertArrayEquals(original.recipientIdentityId, decoded.recipientIdentityId)
        assertEquals(3, decoded.senderAccountGeneration)
        assertEquals(7, decoded.recipientAccountGeneration)
        assertEquals(SESSION_OLM_MESSAGE_NORMAL, decoded.olmMessageType)
        assertArrayEquals(original.olmMessage, decoded.olmMessage)
    }

    @Test
    fun unknownFieldsAreIgnoredButDuplicateKnownFieldsFailClosed() {
        val value = SessionCiphertext(
            senderIdentityId = bytes(0x11, 32),
            recipientIdentityId = bytes(0x22, 32),
            senderAccountGeneration = 1,
            recipientAccountGeneration = 2,
            olmMessageType = SESSION_OLM_MESSAGE_PRE_KEY,
            olmMessage = byteArrayOf(0x41),
        )
        val compatible = SessionCiphertextWire.encode(value) + proto { uint(31, 9) }
        assertEquals(1, SessionCiphertextWire.decode(compatible).senderAccountGeneration)

        val duplicate = SessionCiphertextWire.encode(value) + proto { uint(4, 1) }
        assertThrows(SessionStateException::class.java) {
            SessionCiphertextWire.decode(duplicate)
        }
    }

    @Test
    fun invalidContextAndBoundsFailClosed() {
        val sender = bytes(0x11, 32)
        val recipient = bytes(0x22, 32)
        val valid = SessionCiphertext(
            senderIdentityId = sender,
            recipientIdentityId = recipient,
            senderAccountGeneration = 1,
            recipientAccountGeneration = 2,
            olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
            olmMessage = byteArrayOf(1),
        )

        assertThrows(SessionStateException::class.java) {
            SessionCiphertextWire.encode(valid.copy(recipientIdentityId = sender.copyOf()))
        }
        assertThrows(SessionStateException::class.java) {
            SessionCiphertextWire.encode(valid.copy(senderAccountGeneration = 0))
        }
        assertThrows(SessionStateException::class.java) {
            SessionCiphertextWire.encode(valid.copy(olmMessageType = 2))
        }
        assertThrows(SessionStateException::class.java) {
            SessionCiphertextWire.encode(valid.copy(olmMessage = ByteArray(SESSION_MAX_OLM_MESSAGE_BYTES + 1)))
        }
        assertThrows(SessionStateException::class.java) {
            SessionCiphertextWire.decode(ByteArray(SessionCiphertextWire.MAX_ENCODED_BYTES + 1))
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
