package com.sl.kenato.session

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SessionWireTest {
    @Test
    fun publishResponseDecodesAndRejectsDuplicateFields() {
        val response = proto {
            uint(1, 1)
            uint(2, 3)
            uint(3, 7)
        }
        assertEquals(SessionPublishWireResponse(3, 7), SessionWire.decodePublishBootstrapResponse(response))

        val duplicate = proto {
            uint(1, 1)
            uint(1, 1)
            uint(2, 3)
            uint(3, 7)
        }
        assertThrows(SessionStateException::class.java) {
            SessionWire.decodePublishBootstrapResponse(duplicate)
        }
    }

    @Test
    fun signedBootstrapBundleRoundTripsExactly() {
        val original = SessionBootstrapBundle(
            identityId = bytes(0x11, 32),
            accountGeneration = 2,
            publicationRevision = 4,
            olmEd25519IdentityKey = bytes(0x21, 32),
            olmCurve25519IdentityKey = bytes(0x22, 32),
            oneTimePreKeys = listOf(
                SessionOneTimePreKey(7, bytes(0x31, 32)),
                SessionOneTimePreKey(8, bytes(0x32, 32)),
            ),
            bindingSignature = bytes(0x40, 70),
        )

        val decoded = SessionWire.decodeBootstrapBundle(SessionWire.encodeBootstrapBundle(original))

        assertArrayEquals(original.identityId, decoded.identityId)
        assertEquals(original.accountGeneration, decoded.accountGeneration)
        assertEquals(original.publicationRevision, decoded.publicationRevision)
        assertArrayEquals(original.olmEd25519IdentityKey, decoded.olmEd25519IdentityKey)
        assertArrayEquals(original.olmCurve25519IdentityKey, decoded.olmCurve25519IdentityKey)
        assertEquals(2, decoded.oneTimePreKeys.size)
        assertArrayEquals(original.bindingSignature, decoded.bindingSignature)
    }

    @Test
    fun reserveResponseRequiresReservedKeyInsideAuthenticatedBundle() {
        val bundle = SessionBootstrapBundle(
            identityId = bytes(0x11, 32),
            accountGeneration = 1,
            publicationRevision = 1,
            olmEd25519IdentityKey = bytes(0x21, 32),
            olmCurve25519IdentityKey = bytes(0x22, 32),
            oneTimePreKeys = listOf(SessionOneTimePreKey(1, bytes(0x31, 32))),
            bindingSignature = bytes(0x40, 70),
        )
        val response = proto {
            uint(1, 1)
            bytes(2, SessionWire.encodeBootstrapBundle(bundle))
            bytes(3, proto {
                uint(1, 2)
                bytes(2, bytes(0x32, 32))
            })
        }

        assertThrows(SessionStateException::class.java) {
            SessionWire.decodeReserveBootstrapResponse(response)
        }
    }

    @Test
    fun oversizedAndUnsupportedWireValuesFailClosed() {
        assertThrows(SessionStateException::class.java) {
            SessionWire.decodePublishBootstrapResponse(ByteArray(SESSION_MAX_WIRE_BYTES + 1))
        }
        val unsupported = proto {
            uint(1, 2)
            uint(2, 1)
            uint(3, 1)
        }
        assertThrows(SessionStateException::class.java) {
            SessionWire.decodePublishBootstrapResponse(unsupported)
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

    private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
}
