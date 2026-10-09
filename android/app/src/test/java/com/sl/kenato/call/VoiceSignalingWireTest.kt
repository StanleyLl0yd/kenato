package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingProtocolException
import com.sl.kenato.messaging.MessagingWire
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class VoiceSignalingWireTest {
    @Test
    fun everyKindRoundTripsAndEnvelopeBindingIsExact() {
        for (kind in VoiceSignalKind.entries) {
            val source = signal(kind)
            val encoded = VoiceSignalingWire.encode(source)
            val decoded = VoiceSignalingWire.decode(encoded, binding(source), NOW)
            assertEquals(kind, decoded.kind)
            assertArrayEquals(source.callId, decoded.callId)
            assertArrayEquals(source.payload, decoded.payload)
            assertArrayEquals(encoded, VoiceSignalingWire.encode(decoded))
        }
    }

    @Test
    fun olderTextDecoderRejectsVersionTwoApplicationRecord() {
        val wire = VoiceSignalingWire.encode(signal(VoiceSignalKind.OFFER))
        assertThrows(MessagingProtocolException::class.java) {
            MessagingWire.decodePlaintext(wire)
        }
        val downgraded = wire.copyOf().also { it[1] = 1 }
        assertRejected(downgraded)
    }

    @Test
    fun nonCanonicalDuplicateUnknownAndTruncatedFieldsFailClosed() {
        val valid = VoiceSignalingWire.encode(signal(VoiceSignalKind.OFFER))
        val nonMinimalVersion = byteArrayOf(8, 0x82.toByte(), 0) + valid.copyOfRange(2, valid.size)
        assertRejected(nonMinimalVersion)
        assertRejected(valid + byteArrayOf(0x4a, 0))
        assertRejected(valid + byteArrayOf(0x50, 1))
        assertRejected(valid.copyOfRange(0, valid.size - 1))
        assertRejected(valid.copyOfRange(0, 10))
        assertRejected(ByteArray(24 * 1024 + 1))
    }

    @Test
    fun identityMessageIdCallIdAndExpiryCannotBeSubstituted() {
        val original = signal(VoiceSignalKind.OFFER)
        val encoded = VoiceSignalingWire.encode(original)
        val binding = binding(original)
        val changes = listOf(
            VoiceSignalEnvelopeBinding(ByteArray(32) { 7 }, binding.recipientIdentityId, binding.messageId, binding.expiresAtEpochSeconds),
            VoiceSignalEnvelopeBinding(binding.senderIdentityId, ByteArray(32) { 8 }, binding.messageId, binding.expiresAtEpochSeconds),
            VoiceSignalEnvelopeBinding(binding.senderIdentityId, binding.recipientIdentityId, ByteArray(16) { 9 }, binding.expiresAtEpochSeconds),
            VoiceSignalEnvelopeBinding(binding.senderIdentityId, binding.recipientIdentityId, binding.messageId, binding.expiresAtEpochSeconds + 1),
        )
        for (wrong in changes) {
            assertThrows(VoiceSignalingProtocolException::class.java) {
                VoiceSignalingWire.decode(encoded, wrong, NOW)
            }
        }
        assertThrows(VoiceSignalingProtocolException::class.java) {
            VoiceSignalingWire.encode(signal(VoiceSignalKind.OFFER, callId = ByteArray(16)))
        }
        assertThrows(VoiceSignalingProtocolException::class.java) {
            VoiceSignalingWire.encode(signal(VoiceSignalKind.OFFER, recipient = ByteArray(32) { 1 }))
        }
    }

    @Test
    fun expiryAndSenderClockSkewAreBounded() {
        val source = signal(VoiceSignalKind.OFFER)
        val wire = VoiceSignalingWire.encode(source)
        for (time in listOf(source.expiresAtEpochSeconds, source.expiresAtEpochSeconds + 1)) {
            assertThrows(VoiceSignalingProtocolException::class.java) {
                VoiceSignalingWire.decode(wire, binding(source), time)
            }
        }
        assertThrows(VoiceSignalingProtocolException::class.java) {
            VoiceSignalingWire.decode(wire, binding(source), source.sentAtEpochSeconds - 31)
        }
        assertThrows(VoiceSignalingProtocolException::class.java) {
            VoiceSignalingWire.encode(signal(VoiceSignalKind.OFFER, expiry = NOW + 91))
        }
        assertThrows(VoiceSignalingProtocolException::class.java) {
            VoiceSignalingWire.encode(signal(VoiceSignalKind.OFFER, expiry = NOW))
        }
    }

    @Test
    fun kindSpecificBodyLimitsAndCanonicalUtf8AreEnforced() {
        val maxSdp = signal(VoiceSignalKind.OFFER, payload = ByteArray(16 * 1024) { 65 })
        val decoded = VoiceSignalingWire.decode(VoiceSignalingWire.encode(maxSdp), binding(maxSdp), NOW)
        assertEquals(16 * 1024, decoded.payload.size)

        for (invalid in listOf(
            signal(VoiceSignalKind.HANGUP, payload = byteArrayOf(1)),
            signal(VoiceSignalKind.OFFER, payload = byteArrayOf()),
            signal(VoiceSignalKind.ICE_CANDIDATE, payload = ByteArray(4097) { 65 }),
            signal(VoiceSignalKind.ANSWER, payload = byteArrayOf(0xc3.toByte(), 0x28)),
            signal(VoiceSignalKind.OFFER, payload = byteArrayOf(0)),
        )) {
            assertThrows(VoiceSignalingProtocolException::class.java) { VoiceSignalingWire.encode(invalid) }
        }
    }

    private fun assertRejected(wire: ByteArray) {
        assertThrows(VoiceSignalingProtocolException::class.java) {
            VoiceSignalingWire.decode(wire, binding(signal(VoiceSignalKind.OFFER)), NOW)
        }
    }

    private fun binding(value: VoiceSignalPlaintext) = VoiceSignalEnvelopeBinding(
        value.senderIdentityId.copyOf(),
        value.recipientIdentityId.copyOf(),
        value.messageId.copyOf(),
        value.expiresAtEpochSeconds,
    )

    private fun signal(
        kind: VoiceSignalKind,
        payload: ByteArray = when (kind) {
            VoiceSignalKind.OFFER, VoiceSignalKind.ANSWER -> "v=0\r\n".toByteArray()
            VoiceSignalKind.ICE_CANDIDATE -> "candidate:1 1 udp 123 192.0.2.1 456 typ host".toByteArray()
            else -> byteArrayOf()
        },
        recipient: ByteArray = ByteArray(32) { 2 },
        callId: ByteArray = ByteArray(16) { 4 },
        expiry: Long = NOW + 60,
    ) = VoiceSignalPlaintext(
        senderIdentityId = ByteArray(32) { 1 },
        recipientIdentityId = recipient,
        messageId = ByteArray(16) { 3 },
        callId = callId,
        sentAtEpochSeconds = NOW,
        expiresAtEpochSeconds = expiry,
        kind = kind,
        payload = payload,
    )

    companion object {
        private const val NOW = 1_780_000_000L
    }
}
