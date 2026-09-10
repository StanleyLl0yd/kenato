package com.sl.kenato.contact

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ContactWireTest {
    @Test
    fun publishResponseAcceptsSupportedUnknownFields() {
        val response = TestProto().apply {
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            fixed64(20, 0x0102030405060708L)
            bytes(21, byteArrayOf(1, 2, 3))
            fixed32(22, 0x01020304)
            uint(2, 7)
            uint(23, 99)
        }.bytes()

        assertEquals(7L, ContactWire.decodePublishIdentityResponse(response).acceptedRevision)
    }

    @Test
    fun responseRejectsDuplicateSingularField() {
        val response = TestProto().apply {
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            uint(2, 1)
        }.bytes()

        assertThrows(ContactProtocolException::class.java) {
            ContactWire.decodePublishIdentityResponse(response)
        }
    }

    @Test
    fun responseRejectsUnsupportedVersionAndWrongWireType() {
        val wrongVersion = TestProto().apply {
            uint(1, 2)
            uint(2, 1)
        }.bytes()
        val wrongType = TestProto().apply {
            bytes(1, byteArrayOf(1))
            uint(2, 1)
        }.bytes()

        assertThrows(ContactProtocolException::class.java) {
            ContactWire.decodePublishIdentityResponse(wrongVersion)
        }
        assertThrows(ContactProtocolException::class.java) {
            ContactWire.decodePublishIdentityResponse(wrongType)
        }
    }

    @Test
    fun responseRejectsMalformedTagsTruncationOverflowAndOversize() {
        val invalidFieldZero = byteArrayOf(0)
        val invalidFieldAboveProtobufMaximum = TestProto().apply {
            rawTag(536_870_912, 0)
            rawVarint(1)
        }.bytes()
        val truncatedVarint = byteArrayOf(0x08, 0x80.toByte())
        val overflowingVarint = byteArrayOf(
            0x08,
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(),
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0x02,
        )
        val oversized = ByteArray(MAX_CONTACT_WIRE_BYTES + 1)

        listOf(
            invalidFieldZero,
            invalidFieldAboveProtobufMaximum,
            truncatedVarint,
            overflowingVarint,
            oversized,
        ).forEach { value ->
            assertThrows(ContactProtocolException::class.java) {
                ContactWire.decodePublishIdentityResponse(value)
            }
        }
    }

    @Test
    fun responseRejectsUnknownGroupsAndTruncatedUnknownFields() {
        val group = TestProto().apply {
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            uint(2, 1)
            rawTag(10, 3)
        }.bytes()
        val truncatedFixed64 = TestProto().apply {
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            uint(2, 1)
            rawTag(10, 1)
            raw(byteArrayOf(1, 2))
        }.bytes()
        val truncatedBytes = TestProto().apply {
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            uint(2, 1)
            rawTag(10, 2)
            rawVarint(10)
            raw(byteArrayOf(1, 2))
        }.bytes()

        listOf(group, truncatedFixed64, truncatedBytes).forEach { value ->
            assertThrows(ContactProtocolException::class.java) {
                ContactWire.decodePublishIdentityResponse(value)
            }
        }
    }

    @Test
    fun createInviteResponseRequiresPositiveExpiry() {
        val valid = TestProto().apply {
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            uint(2, 1_789_003_600L)
        }.bytes()
        val zero = TestProto().apply {
            uint(1, CONTACT_PROTOCOL_VERSION.toLong())
            uint(2, 0)
        }.bytes()

        assertEquals(1_789_003_600L, ContactWire.decodeCreateInviteResponse(valid).expiresAtEpochSeconds)
        assertThrows(ContactProtocolException::class.java) {
            ContactWire.decodeCreateInviteResponse(zero)
        }
    }
}

private class TestProto {
    private val output = ByteArrayOutputStream()

    fun uint(field: Int, value: Long) {
        rawTag(field, 0)
        rawVarint(value)
    }

    fun bytes(field: Int, value: ByteArray) {
        rawTag(field, 2)
        rawVarint(value.size.toLong())
        raw(value)
    }

    fun fixed64(field: Int, value: Long) {
        rawTag(field, 1)
        repeat(8) { shift -> output.write((value ushr (shift * 8)).toInt() and 0xff) }
    }

    fun fixed32(field: Int, value: Int) {
        rawTag(field, 5)
        repeat(4) { shift -> output.write((value ushr (shift * 8)) and 0xff) }
    }

    fun rawTag(field: Int, wireType: Int) {
        rawVarint((field.toLong() shl 3) or wireType.toLong())
    }

    fun rawVarint(value: Long) {
        var remaining = value
        while (remaining and -128L != 0L) {
            output.write(((remaining and 0x7f) or 0x80).toInt())
            remaining = remaining ushr 7
        }
        output.write(remaining.toInt())
    }

    fun raw(value: ByteArray) {
        output.write(value)
    }

    fun bytes(): ByteArray = output.toByteArray()
}
