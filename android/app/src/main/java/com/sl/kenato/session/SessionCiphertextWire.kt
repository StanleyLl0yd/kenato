package com.sl.kenato.session

import java.io.ByteArrayOutputStream

/**
 * Encoded M3 application ciphertext carried opaquely by M4 Envelope.ciphertext.
 * The server never parses this value; endpoints use it to preserve the Olm
 * message type and exact M3 account-generation provenance required for decrypt.
 */
internal data class SessionCiphertext(
    val senderIdentityId: ByteArray,
    val recipientIdentityId: ByteArray,
    val senderAccountGeneration: Long,
    val recipientAccountGeneration: Long,
    val olmMessageType: Int,
    val olmMessage: ByteArray,
    val protocolVersion: Int = SESSION_PROTOCOL_VERSION,
)

internal object SessionCiphertextWire {
    const val MAX_ENCODED_BYTES = SESSION_MAX_WIRE_BYTES

    fun encode(value: SessionCiphertext): ByteArray {
        validate(value)
        return Writer(MAX_ENCODED_BYTES).apply {
            uint(1, value.protocolVersion.toLong())
            bytes(2, value.senderIdentityId)
            bytes(3, value.recipientIdentityId)
            uint(4, value.senderAccountGeneration)
            uint(5, value.recipientAccountGeneration)
            uint(6, value.olmMessageType.toLong())
            bytes(7, value.olmMessage)
        }.toByteArray()
    }

    fun decode(data: ByteArray): SessionCiphertext {
        val reader = Reader(data, MAX_ENCODED_BYTES)
        var version: Long? = null
        var sender: ByteArray? = null
        var recipient: ByteArray? = null
        var senderGeneration: Long? = null
        var recipientGeneration: Long? = null
        var messageType: Long? = null
        var olmMessage: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "protocol version")
                2 -> sender = unique(
                    sender,
                    reader.readBytes(wireType, SESSION_IDENTITY_BYTES),
                    "sender identity id",
                )
                3 -> recipient = unique(
                    recipient,
                    reader.readBytes(wireType, SESSION_IDENTITY_BYTES),
                    "recipient identity id",
                )
                4 -> senderGeneration = unique(
                    senderGeneration,
                    reader.readUInt(wireType),
                    "sender account generation",
                )
                5 -> recipientGeneration = unique(
                    recipientGeneration,
                    reader.readUInt(wireType),
                    "recipient account generation",
                )
                6 -> messageType = unique(messageType, reader.readUInt(wireType), "Olm message type")
                7 -> olmMessage = unique(
                    olmMessage,
                    reader.readBytes(wireType, SESSION_MAX_OLM_MESSAGE_BYTES),
                    "Olm message",
                )
                else -> reader.skip(wireType)
            }
        }
        val type = messageType ?: malformed("Olm message type is missing")
        if (type > Int.MAX_VALUE.toLong()) malformed("Olm message type is invalid")
        return SessionCiphertext(
            senderIdentityId = sender ?: malformed("sender identity id is missing"),
            recipientIdentityId = recipient ?: malformed("recipient identity id is missing"),
            senderAccountGeneration = senderGeneration ?: malformed("sender account generation is missing"),
            recipientAccountGeneration = recipientGeneration ?: malformed("recipient account generation is missing"),
            olmMessageType = type.toInt(),
            olmMessage = olmMessage ?: malformed("Olm message is missing"),
            protocolVersion = (version ?: malformed("protocol version is missing")).toIntChecked("protocol version"),
        ).also(::validate)
    }

    fun validate(value: SessionCiphertext) {
        if (value.protocolVersion != SESSION_PROTOCOL_VERSION) malformed("unsupported M3 protocol version")
        requireIdentity(value.senderIdentityId, "sender identity id")
        requireIdentity(value.recipientIdentityId, "recipient identity id")
        if (value.senderIdentityId.contentEquals(value.recipientIdentityId)) {
            malformed("M3 ciphertext identities must be distinct")
        }
        if (value.senderAccountGeneration <= 0 || value.recipientAccountGeneration <= 0) {
            malformed("M3 ciphertext account generation is invalid")
        }
        if (value.olmMessageType !in SESSION_OLM_MESSAGE_PRE_KEY..SESSION_OLM_MESSAGE_NORMAL) {
            malformed("M3 ciphertext Olm message type is invalid")
        }
        if (value.olmMessage.isEmpty() || value.olmMessage.size > SESSION_MAX_OLM_MESSAGE_BYTES) {
            malformed("M3 ciphertext Olm message size is invalid")
        }
    }

    private fun requireIdentity(value: ByteArray, name: String) {
        if (value.size != SESSION_IDENTITY_BYTES) malformed("$name size is invalid")
    }

    private fun <T> unique(current: T?, value: T, name: String): T {
        if (current != null) malformed("duplicate $name field")
        return value
    }

    private fun Long.toIntChecked(name: String): Int {
        if (this < 0 || this > Int.MAX_VALUE.toLong()) malformed("$name is invalid")
        return toInt()
    }

    private fun malformed(message: String): Nothing = throw SessionStateException(message)
}

private class Writer(private val maximum: Int) {
    private val output = ByteArrayOutputStream()

    fun uint(field: Int, value: Long) {
        if (field !in 1..MAX_PROTO_FIELD || value < 0) malformed("invalid protobuf integer field")
        writeVarint((field.toLong() shl 3) or VARINT_WIRE_TYPE.toLong())
        writeVarint(value)
        enforceBound()
    }

    fun bytes(field: Int, value: ByteArray) {
        if (field !in 1..MAX_PROTO_FIELD || value.size > maximum) malformed("invalid protobuf bytes field")
        writeVarint((field.toLong() shl 3) or BYTES_WIRE_TYPE.toLong())
        writeVarint(value.size.toLong())
        output.write(value)
        enforceBound()
    }

    fun toByteArray(): ByteArray = output.toByteArray().also {
        if (it.isEmpty() || it.size > maximum) malformed("M3 ciphertext protobuf size is invalid")
    }

    private fun writeVarint(value: Long) {
        var remaining = value
        while (remaining and -128L != 0L) {
            output.write(((remaining and 0x7f) or 0x80).toInt())
            remaining = remaining ushr 7
        }
        output.write(remaining.toInt())
    }

    private fun enforceBound() {
        if (output.size() > maximum) malformed("M3 ciphertext protobuf exceeds its bound")
    }

    private fun malformed(message: String): Nothing = throw SessionStateException(message)

    private companion object {
        const val MAX_PROTO_FIELD = 536_870_911
        const val VARINT_WIRE_TYPE = 0
        const val BYTES_WIRE_TYPE = 2
    }
}

private class Reader(data: ByteArray, private val maximum: Int) {
    private val data = data.copyOf()
    private var position = 0

    init {
        if (data.isEmpty() || data.size > maximum) malformed("M3 ciphertext protobuf size is invalid")
    }

    fun fields(block: (Int, Int) -> Unit) {
        while (position < data.size) {
            val tag = readVarint()
            val field = tag ushr 3
            val wireType = (tag and 7).toInt()
            if (tag < 0 || field !in 1L..MAX_PROTO_FIELD.toLong()) malformed("invalid protobuf field number")
            block(field.toInt(), wireType)
        }
    }

    fun readUInt(wireType: Int): Long {
        requireWireType(wireType, VARINT_WIRE_TYPE)
        val value = readVarint()
        if (value < 0) malformed("unsigned protobuf integer exceeds signed Android range")
        return value
    }

    fun readBytes(wireType: Int, fieldMaximum: Int): ByteArray {
        requireWireType(wireType, BYTES_WIRE_TYPE)
        val length = readVarint()
        if (length < 0 || length > fieldMaximum.toLong() || length > data.size - position) {
            malformed("protobuf bytes field size is invalid")
        }
        val start = position
        position += length.toInt()
        return data.copyOfRange(start, position)
    }

    fun skip(wireType: Int) {
        when (wireType) {
            VARINT_WIRE_TYPE -> readVarint()
            FIXED64_WIRE_TYPE -> skipFixed(8)
            BYTES_WIRE_TYPE -> {
                val length = readVarint()
                if (length < 0 || length > data.size - position) malformed("unknown protobuf field is invalid")
                position += length.toInt()
            }
            FIXED32_WIRE_TYPE -> skipFixed(4)
            else -> malformed("unsupported protobuf wire type")
        }
    }

    private fun readVarint(): Long {
        var result = 0L
        var shift = 0
        repeat(10) { index ->
            if (position >= data.size) malformed("truncated protobuf varint")
            val byte = data[position++].toInt() and 0xff
            if (index == 9 && byte > 1) malformed("protobuf varint overflows uint64")
            result = result or ((byte and 0x7f).toLong() shl shift)
            if (byte and 0x80 == 0) return result
            shift += 7
        }
        malformed("protobuf varint is too long")
    }

    private fun requireWireType(actual: Int, expected: Int) {
        if (actual != expected) malformed("protobuf wire type is invalid")
    }

    private fun skipFixed(size: Int) {
        if (size > data.size - position) malformed("truncated fixed protobuf field")
        position += size
    }

    private fun malformed(message: String): Nothing = throw SessionStateException(message)

    private companion object {
        const val MAX_PROTO_FIELD = 536_870_911
        const val VARINT_WIRE_TYPE = 0
        const val FIXED64_WIRE_TYPE = 1
        const val BYTES_WIRE_TYPE = 2
        const val FIXED32_WIRE_TYPE = 5
    }
}
