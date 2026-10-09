package com.sl.kenato.call

import java.io.ByteArrayOutputStream

/** Strict M5 encrypted plaintext codec. It is NOT an authentication or delivery boundary. */
internal class VoiceSignalingProtocolException(message: String) : IllegalArgumentException(message)

internal enum class VoiceSignalKind(val number: Int) {
    OFFER(1),
    ANSWER(2),
    REJECT(3),
    BUSY(4),
    HANGUP(5),
    ICE_CANDIDATE(6),
    END_OF_CANDIDATES(7);

    companion object {
        fun fromNumber(value: Long): VoiceSignalKind =
            entries.singleOrNull { it.number.toLong() == value }
                ?: failVoiceSignal("Unsupported voice signal kind")
    }
}

internal class VoiceSignalPlaintext(
    val senderIdentityId: ByteArray,
    val recipientIdentityId: ByteArray,
    val messageId: ByteArray,
    val callId: ByteArray,
    val sentAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val kind: VoiceSignalKind,
    val payload: ByteArray,
    val applicationProtocolVersion: Int = VOICE_SIGNAL_APPLICATION_VERSION,
)

/** Values supplied from a separately authenticated, validated M4 envelope after M3 decrypt. */
internal class VoiceSignalEnvelopeBinding(
    val senderIdentityId: ByteArray,
    val recipientIdentityId: ByteArray,
    val messageId: ByteArray,
    val expiresAtEpochSeconds: Long,
)

internal object VoiceSignalingWire {
    fun encode(value: VoiceSignalPlaintext): ByteArray {
        validateShape(value)
        val out = ByteArrayOutputStream()
        out.uint(1, value.applicationProtocolVersion.toLong())
        out.bytes(2, value.senderIdentityId)
        out.bytes(3, value.recipientIdentityId)
        out.bytes(4, value.messageId)
        out.uint(5, value.sentAtEpochSeconds)
        out.uint(6, value.expiresAtEpochSeconds)
        out.bytes(7, value.callId)
        out.uint(8, value.kind.number.toLong())
        out.bytes(9, value.payload)
        return out.toByteArray().also {
            if (it.size > MAX_VOICE_SIGNAL_WIRE_BYTES) failVoiceSignal("Voice signaling record is oversized")
        }
    }

    fun decode(
        encoded: ByteArray,
        envelope: VoiceSignalEnvelopeBinding,
        nowEpochSeconds: Long,
    ): VoiceSignalPlaintext {
        if (encoded.isEmpty() || encoded.size > MAX_VOICE_SIGNAL_WIRE_BYTES) {
            failVoiceSignal("Voice signaling record size is invalid")
        }
        val reader = VoiceSignalReader(encoded)
        var version = 0L
        var sender = byteArrayOf()
        var recipient = byteArrayOf()
        var messageId = byteArrayOf()
        var sentAt = 0L
        var expiresAt = 0L
        var callId = byteArrayOf()
        var kind = 0L
        var body = byteArrayOf()
        for (field in 1..9) {
            if (reader.done()) failVoiceSignal("Voice signaling field is missing")
            val tag = reader.readUInt()
            if ((tag ushr 3) != field.toLong() || (tag and 7L).toInt() !=
                (if (field in setOf(1, 5, 6, 8)) 0 else 2)
            ) {
                failVoiceSignal("Unexpected voice signaling field, order or wire type")
            }
            when (field) {
                1 -> version = reader.readUInt()
                2 -> sender = reader.readBytes(VOICE_IDENTITY_BYTES)
                3 -> recipient = reader.readBytes(VOICE_IDENTITY_BYTES)
                4 -> messageId = reader.readBytes(VOICE_MESSAGE_ID_BYTES)
                5 -> sentAt = reader.readUInt()
                6 -> expiresAt = reader.readUInt()
                7 -> callId = reader.readBytes(VOICE_CALL_ID_BYTES)
                8 -> kind = reader.readUInt()
                9 -> body = reader.readBytes(MAX_VOICE_SDP_BYTES)
            }
        }
        if (!reader.done()) failVoiceSignal("Unexpected trailing voice signaling field")
        if (version != VOICE_SIGNAL_APPLICATION_VERSION.toLong()) {
            failVoiceSignal("Unsupported encrypted application record version")
        }
        val value = VoiceSignalPlaintext(
            senderIdentityId = sender,
            recipientIdentityId = recipient,
            messageId = messageId,
            callId = callId,
            sentAtEpochSeconds = sentAt,
            expiresAtEpochSeconds = expiresAt,
            kind = VoiceSignalKind.fromNumber(kind),
            payload = body,
        )
        validateShape(value)
        if (!encode(value).contentEquals(encoded)) {
            failVoiceSignal("Voice signaling record is not canonical")
        }
        if (
            !value.senderIdentityId.contentEquals(envelope.senderIdentityId) ||
            !value.recipientIdentityId.contentEquals(envelope.recipientIdentityId) ||
            !value.messageId.contentEquals(envelope.messageId) ||
            value.expiresAtEpochSeconds != envelope.expiresAtEpochSeconds
        ) {
            failVoiceSignal("Encrypted voice signaling does not match authenticated envelope")
        }
        if (
            nowEpochSeconds < 0L ||
            value.expiresAtEpochSeconds <= nowEpochSeconds ||
            (value.sentAtEpochSeconds > nowEpochSeconds &&
                value.sentAtEpochSeconds - nowEpochSeconds > MAX_VOICE_FUTURE_SKEW_SECONDS)
        ) {
            failVoiceSignal("Voice signaling is expired or has invalid receive time")
        }
        return value
    }

    private fun validateShape(value: VoiceSignalPlaintext) {
        if (value.applicationProtocolVersion != VOICE_SIGNAL_APPLICATION_VERSION) {
            failVoiceSignal("Unsupported encrypted application record version")
        }
        if (
            value.senderIdentityId.size != VOICE_IDENTITY_BYTES ||
            value.recipientIdentityId.size != VOICE_IDENTITY_BYTES ||
            value.senderIdentityId.all { it == 0.toByte() } ||
            value.recipientIdentityId.all { it == 0.toByte() } ||
            value.senderIdentityId.contentEquals(value.recipientIdentityId)
        ) {
            failVoiceSignal("Voice signaling peer identities are invalid")
        }
        if (
            value.messageId.size != VOICE_MESSAGE_ID_BYTES ||
            value.messageId.all { it == 0.toByte() } ||
            value.callId.size != VOICE_CALL_ID_BYTES ||
            value.callId.all { it == 0.toByte() }
        ) {
            failVoiceSignal("Voice signaling ids are invalid")
        }
        if (
            value.sentAtEpochSeconds <= 0L ||
            value.expiresAtEpochSeconds <= value.sentAtEpochSeconds ||
            value.expiresAtEpochSeconds - value.sentAtEpochSeconds > MAX_VOICE_SIGNAL_LIFETIME_SECONDS
        ) {
            failVoiceSignal("Voice signaling lifetime is invalid")
        }
        val maximum = when (value.kind) {
            VoiceSignalKind.OFFER, VoiceSignalKind.ANSWER -> MAX_VOICE_SDP_BYTES
            VoiceSignalKind.ICE_CANDIDATE -> MAX_VOICE_ICE_BYTES
            else -> 0
        }
        if (maximum == 0) {
            if (value.payload.isNotEmpty()) failVoiceSignal("Control signal must not contain a body")
        } else {
            if (value.payload.isEmpty() || value.payload.size > maximum) {
                failVoiceSignal("Voice signaling body size is invalid")
            }
            val decoded = value.payload.toString(Charsets.UTF_8)
            if (
                !decoded.toByteArray(Charsets.UTF_8).contentEquals(value.payload) ||
                '\u0000' in decoded
            ) {
                failVoiceSignal("Voice signaling body is not canonical UTF-8")
            }
        }
    }
}

private const val VOICE_SIGNAL_APPLICATION_VERSION = 2
private const val VOICE_IDENTITY_BYTES = 32
private const val VOICE_MESSAGE_ID_BYTES = 16
private const val VOICE_CALL_ID_BYTES = 16
private const val MAX_VOICE_SDP_BYTES = 16 * 1024
private const val MAX_VOICE_ICE_BYTES = 4 * 1024
private const val MAX_VOICE_SIGNAL_WIRE_BYTES = 24 * 1024
private const val MAX_VOICE_SIGNAL_LIFETIME_SECONDS = 90L
private const val MAX_VOICE_FUTURE_SKEW_SECONDS = 30L

private fun ByteArrayOutputStream.uint(field: Int, value: Long) {
    writeVarint((field shl 3).toLong())
    writeVarint(value)
}

private fun ByteArrayOutputStream.bytes(field: Int, value: ByteArray) {
    writeVarint(((field shl 3) or 2).toLong())
    writeVarint(value.size.toLong())
    write(value)
}

private fun ByteArrayOutputStream.writeVarint(value: Long) {
    if (value < 0L) failVoiceSignal("Negative voice signaling protobuf integer")
    var rest = value
    while (rest >= 128L) {
        write(((rest and 127L) or 128L).toInt())
        rest = rest ushr 7
    }
    write(rest.toInt())
}

private class VoiceSignalReader(private val data: ByteArray) {
    private var position = 0

    fun done(): Boolean = position == data.size

    fun readUInt(): Long {
        var result = 0L
        repeat(10) { index ->
            if (done()) failVoiceSignal("Truncated voice signaling varint")
            val byte = data[position++].toInt() and 255
            if (index == 9 && byte > 1) failVoiceSignal("Voice signaling varint overflow")
            result = result or ((byte and 127).toLong() shl (index * 7))
            if (byte and 128 == 0) {
                if (result < 0L) failVoiceSignal("Voice signaling unsigned integer is invalid")
                return result
            }
        }
        failVoiceSignal("Voice signaling varint too long")
    }

    fun readBytes(maximum: Int): ByteArray {
        val length = readUInt()
        if (length > maximum || length > data.size - position) {
            failVoiceSignal("Voice signaling protobuf bytes length is invalid")
        }
        val start = position
        position += length.toInt()
        return data.copyOfRange(start, position)
    }
}

private fun failVoiceSignal(message: String): Nothing = throw VoiceSignalingProtocolException(message)
