package com.sl.kenato.contact

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class InviteQrTest {
    @Test
    fun encodesCanonicalInviteIntoBoundedQrMatrix() {
        val invite = M2InviteDescriptor(
            creatorIdentityId = ByteArray(CONTACT_ID_BYTES) { it.toByte() },
            token = ByteArray(INVITE_TOKEN_BYTES) { (it + 32).toByte() },
            signature = byteArrayOf(1, 2, 3),
        )
        val matrix = InviteQr.encode(InviteUriCodec.encode(invite), 256)

        assertEquals(256, matrix.width)
        assertEquals(256, matrix.height)
        assertTrue((0 until matrix.height).any { y -> (0 until matrix.width).any { x -> matrix[x, y] } })
    }

    @Test
    fun rejectsInvalidInvitePayloadAndUnboundedDimensions() {
        assertThrows(ContactProtocolException::class.java) {
            InviteQr.encode("https://example.test/not-an-invite")
        }

        val invite = InviteUriCodec.encode(
            M2InviteDescriptor(
                creatorIdentityId = ByteArray(CONTACT_ID_BYTES) { 1 },
                token = ByteArray(INVITE_TOKEN_BYTES) { 2 },
                signature = byteArrayOf(3),
            ),
        )
        assertThrows(ContactProtocolException::class.java) {
            InviteQr.encode(invite, InviteQr.MIN_SIDE_PIXELS - 1)
        }
        assertThrows(ContactProtocolException::class.java) {
            InviteQr.encode(invite, InviteQr.MAX_SIDE_PIXELS + 1)
        }
    }
}
