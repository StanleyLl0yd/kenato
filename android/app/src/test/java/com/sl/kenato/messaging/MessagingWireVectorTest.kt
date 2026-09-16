package com.sl.kenato.messaging

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class MessagingWireVectorTest {
    @Test
    fun serverVisibleWireMatchesSharedM4Vectors() {
        val envelope = MessagingEnvelope(
            senderIdentityId = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x11 },
            recipientIdentityId = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x22 },
            messageId = ByteArray(MESSAGING_MESSAGE_ID_BYTES) { 0x33 },
            ciphertext = byteArrayOf(0x01, 0x02, 0x03, 0x04),
            expiresAtEpochSeconds = 2_000_000_060L,
        )

        assertArrayEquals(hex(ENVELOPE_HEX), MessagingWire.encodeEnvelope(envelope))
        assertArrayEquals(
            hex(CLIENT_SEND_HEX),
            MessagingWire.encodeClientFrame(MessagingClientFrame(send = envelope)),
        )
        assertArrayEquals(
            hex(SERVER_DELIVERY_HEX),
            MessagingWire.encodeServerFrame(MessagingServerFrame(delivery = envelope)),
        )

        val decodedClient = MessagingWire.decodeClientFrame(hex(CLIENT_SEND_HEX))
        val decodedServer = MessagingWire.decodeServerFrame(hex(SERVER_DELIVERY_HEX))
        assertNotNull(decodedClient.send)
        assertNotNull(decodedServer.delivery)
        assertArrayEquals(envelope.senderIdentityId, requireNotNull(decodedClient.send).senderIdentityId)
        assertArrayEquals(envelope.recipientIdentityId, requireNotNull(decodedServer.delivery).recipientIdentityId)
        assertArrayEquals(envelope.messageId, requireNotNull(decodedClient.send).messageId)
    }

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0)
        return ByteArray(value.length / 2) { index ->
            val high = value[index * 2].digitToInt(16)
            val low = value[index * 2 + 1].digitToInt(16)
            ((high shl 4) or low).toByte()
        }
    }

    companion object {
        private const val ENVELOPE_HEX =
            "080112202222222222222222222222222222222222222222222222222222222222222222" +
                "1a103333333333333333333333333333333322040102030428bca8d6b907" +
                "32201111111111111111111111111111111111111111111111111111111111111111"
        private const val CLIENT_SEND_HEX =
            "08011a64" + ENVELOPE_HEX
        private const val SERVER_DELIVERY_HEX =
            "08012264" + ENVELOPE_HEX
    }
}
