package com.sl.kenato.messaging

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

internal const val MESSAGING_ERROR_MALFORMED = 1
internal const val MESSAGING_ERROR_AUTHENTICATION_FAILED = 2
internal const val MESSAGING_ERROR_SEND_REJECTED = 3
internal const val MESSAGING_ERROR_RETRY_LATER = 4

internal data class MessagingDeliveryAck(
    val senderIdentityId: ByteArray,
    val messageId: ByteArray,
    val protocolVersion: Int = MESSAGING_PROTOCOL_VERSION,
)

internal data class MessagingSendAccepted(
    val recipientIdentityId: ByteArray,
    val messageId: ByteArray,
    val protocolVersion: Int = MESSAGING_PROTOCOL_VERSION,
)

internal data class MessagingWireError(
    val code: Int,
    val messageId: ByteArray? = null,
    val protocolVersion: Int = MESSAGING_PROTOCOL_VERSION,
)

internal data class MessagingClientFrame(
    val authResponse: MessagingAuthResponse? = null,
    val send: MessagingEnvelope? = null,
    val ack: MessagingDeliveryAck? = null,
    val protocolVersion: Int = MESSAGING_PROTOCOL_VERSION,
)

internal data class MessagingServerFrame(
    val authChallenge: MessagingAuthChallenge? = null,
    val authenticated: Boolean = false,
    val delivery: MessagingEnvelope? = null,
    val sendAccepted: MessagingSendAccepted? = null,
    val error: MessagingWireError? = null,
    val protocolVersion: Int = MESSAGING_PROTOCOL_VERSION,
)

internal object MessagingWire {
    fun encodePlaintext(value: MessagingPlaintext): ByteArray {
        MessagingProtocol.validatePlaintext(value)
        return message(MESSAGING_MAX_CIPHERTEXT_BYTES) {
            uint(1, value.protocolVersion.toLong())
            bytes(2, value.senderIdentityId)
            bytes(3, value.recipientIdentityId)
            bytes(4, value.messageId)
            uint(5, value.sentAtEpochSeconds)
            uint(6, value.expiresAtEpochSeconds)
            bytes(7, value.text.toByteArray(StandardCharsets.UTF_8))
        }
    }

    fun decodePlaintext(data: ByteArray): MessagingPlaintext {
        val reader = MessagingProtoReader(data, MESSAGING_MAX_CIPHERTEXT_BYTES)
        var version: Long? = null
        var sender: ByteArray? = null
        var recipient: ByteArray? = null
        var messageId: ByteArray? = null
        var sentAt: Long? = null
        var expiresAt: Long? = null
        var textBytes: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "plaintext protocol version")
                2 -> sender = unique(sender, reader.readBytes(wireType, MESSAGING_IDENTITY_BYTES), "plaintext sender")
                3 -> recipient = unique(
                    recipient,
                    reader.readBytes(wireType, MESSAGING_IDENTITY_BYTES),
                    "plaintext recipient",
                )
                4 -> messageId = unique(
                    messageId,
                    reader.readBytes(wireType, MESSAGING_MESSAGE_ID_BYTES),
                    "plaintext message id",
                )
                5 -> sentAt = unique(sentAt, reader.readUInt(wireType), "plaintext sent timestamp")
                6 -> expiresAt = unique(expiresAt, reader.readUInt(wireType), "plaintext expiry")
                7 -> textBytes = unique(
                    textBytes,
                    reader.readBytes(wireType, MESSAGING_MAX_TEXT_BYTES),
                    "plaintext text",
                )
                else -> reader.skip(wireType)
            }
        }
        val encodedText = textBytes ?: malformed("M4 plaintext text is missing")
        val text = String(encodedText, StandardCharsets.UTF_8)
        if (!text.toByteArray(StandardCharsets.UTF_8).contentEquals(encodedText)) {
            malformed("M4 plaintext text is not canonical UTF-8")
        }
        return MessagingPlaintext(
            senderIdentityId = sender ?: malformed("M4 plaintext sender is missing"),
            recipientIdentityId = recipient ?: malformed("M4 plaintext recipient is missing"),
            messageId = messageId ?: malformed("M4 plaintext message id is missing"),
            sentAtEpochSeconds = sentAt ?: malformed("M4 plaintext sent timestamp is missing"),
            expiresAtEpochSeconds = expiresAt ?: malformed("M4 plaintext expiry is missing"),
            text = text,
            protocolVersion = (version ?: malformed("M4 plaintext protocol version is missing")).toIntChecked(),
        ).also(MessagingProtocol::validatePlaintext)
    }

    fun encodeEnvelope(value: MessagingEnvelope): ByteArray {
        validateEnvelopeShape(value)
        return message(MESSAGING_MAX_ENVELOPE_BYTES) {
            uint(1, value.protocolVersion.toLong())
            bytes(2, value.recipientIdentityId)
            bytes(3, value.messageId)
            bytes(4, value.ciphertext)
            uint(5, value.expiresAtEpochSeconds)
            bytes(6, value.senderIdentityId)
        }
    }

    fun decodeEnvelope(data: ByteArray): MessagingEnvelope {
        val reader = MessagingProtoReader(data, MESSAGING_MAX_ENVELOPE_BYTES)
        var version: Long? = null
        var recipient: ByteArray? = null
        var messageId: ByteArray? = null
        var ciphertext: ByteArray? = null
        var expiresAt: Long? = null
        var sender: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "envelope protocol version")
                2 -> recipient = unique(
                    recipient,
                    reader.readBytes(wireType, MESSAGING_IDENTITY_BYTES),
                    "envelope recipient",
                )
                3 -> messageId = unique(
                    messageId,
                    reader.readBytes(wireType, MESSAGING_MESSAGE_ID_BYTES),
                    "envelope message id",
                )
                4 -> ciphertext = unique(
                    ciphertext,
                    reader.readBytes(wireType, MESSAGING_MAX_CIPHERTEXT_BYTES),
                    "envelope ciphertext",
                )
                5 -> expiresAt = unique(expiresAt, reader.readUInt(wireType), "envelope expiry")
                6 -> sender = unique(
                    sender,
                    reader.readBytes(wireType, MESSAGING_IDENTITY_BYTES),
                    "envelope sender",
                )
                else -> reader.skip(wireType)
            }
        }
        return MessagingEnvelope(
            senderIdentityId = sender ?: malformed("M4 envelope sender is missing"),
            recipientIdentityId = recipient ?: malformed("M4 envelope recipient is missing"),
            messageId = messageId ?: malformed("M4 envelope message id is missing"),
            ciphertext = ciphertext ?: malformed("M4 envelope ciphertext is missing"),
            expiresAtEpochSeconds = expiresAt ?: malformed("M4 envelope expiry is missing"),
            protocolVersion = (version ?: malformed("M4 envelope protocol version is missing")).toIntChecked(),
        ).also(::validateEnvelopeShape)
    }

    fun encodeClientFrame(value: MessagingClientFrame): ByteArray {
        requireVersion(value.protocolVersion)
        if (clientPayloadCount(value) != 1) malformed("M4 client frame must contain exactly one payload")
        val nested: ByteArray
        val field: Int
        when {
            value.authResponse != null -> {
                field = 2
                nested = encodeAuthResponse(value.authResponse)
            }
            value.send != null -> {
                field = 3
                nested = encodeEnvelope(value.send)
            }
            else -> {
                field = 4
                nested = encodeAck(requireNotNull(value.ack))
            }
        }
        return message(MESSAGING_MAX_WIRE_FRAME_BYTES) {
            uint(1, value.protocolVersion.toLong())
            bytes(field, nested)
        }
    }

    fun decodeClientFrame(data: ByteArray): MessagingClientFrame {
        val reader = MessagingProtoReader(data, MESSAGING_MAX_WIRE_FRAME_BYTES)
        var version: Long? = null
        var auth: MessagingAuthResponse? = null
        var send: MessagingEnvelope? = null
        var ack: MessagingDeliveryAck? = null
        var payloadSeen = false
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "client protocol version")
                2, 3, 4 -> {
                    if (payloadSeen) malformed("duplicate M4 client payload")
                    payloadSeen = true
                    val nested = reader.readBytes(wireType, MESSAGING_MAX_WIRE_FRAME_BYTES)
                    when (field) {
                        2 -> auth = decodeAuthResponse(nested)
                        3 -> send = decodeEnvelope(nested)
                        4 -> ack = decodeAck(nested)
                    }
                }
                else -> reader.skip(wireType)
            }
        }
        return MessagingClientFrame(
            authResponse = auth,
            send = send,
            ack = ack,
            protocolVersion = (version ?: malformed("M4 client protocol version is missing")).toIntChecked(),
        ).also {
            requireVersion(it.protocolVersion)
            if (!payloadSeen || clientPayloadCount(it) != 1) malformed("M4 client frame payload is missing")
        }
    }

    fun encodeServerFrame(value: MessagingServerFrame): ByteArray {
        requireVersion(value.protocolVersion)
        if (serverPayloadCount(value) != 1) malformed("M4 server frame must contain exactly one payload")
        val nested: ByteArray
        val field: Int
        when {
            value.authChallenge != null -> {
                field = 2
                nested = encodeAuthChallenge(value.authChallenge)
            }
            value.authenticated -> {
                field = 3
                nested = ByteArray(0)
            }
            value.delivery != null -> {
                field = 4
                nested = encodeEnvelope(value.delivery)
            }
            value.sendAccepted != null -> {
                field = 5
                nested = encodeSendAccepted(value.sendAccepted)
            }
            else -> {
                field = 6
                nested = encodeError(requireNotNull(value.error))
            }
        }
        return message(MESSAGING_MAX_WIRE_FRAME_BYTES) {
            uint(1, value.protocolVersion.toLong())
            bytes(field, nested)
        }
    }

    fun decodeServerFrame(data: ByteArray): MessagingServerFrame {
        val reader = MessagingProtoReader(data, MESSAGING_MAX_WIRE_FRAME_BYTES)
        var version: Long? = null
        var challenge: MessagingAuthChallenge? = null
        var authenticated = false
        var delivery: MessagingEnvelope? = null
        var accepted: MessagingSendAccepted? = null
        var error: MessagingWireError? = null
        var payloadSeen = false
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "server protocol version")
                2, 3, 4, 5, 6 -> {
                    if (payloadSeen) malformed("duplicate M4 server payload")
                    payloadSeen = true
                    val nested = reader.readBytes(wireType, MESSAGING_MAX_WIRE_FRAME_BYTES)
                    when (field) {
                        2 -> challenge = decodeAuthChallenge(nested)
                        3 -> {
                            if (nested.isNotEmpty()) malformed("M4 authenticated payload must be empty")
                            authenticated = true
                        }
                        4 -> delivery = decodeEnvelope(nested)
                        5 -> accepted = decodeSendAccepted(nested)
                        6 -> error = decodeError(nested)
                    }
                }
                else -> reader.skip(wireType)
            }
        }
        return MessagingServerFrame(
            authChallenge = challenge,
            authenticated = authenticated,
            delivery = delivery,
            sendAccepted = accepted,
            error = error,
            protocolVersion = (version ?: malformed("M4 server protocol version is missing")).toIntChecked(),
        ).also {
            requireVersion(it.protocolVersion)
            if (!payloadSeen || serverPayloadCount(it) != 1) malformed("M4 server frame payload is missing")
        }
    }

    private fun encodeAuthChallenge(value: MessagingAuthChallenge): ByteArray {
        requireVersion(value.protocolVersion)
        if (
            value.challenge.size != MESSAGING_AUTH_CHALLENGE_BYTES ||
            value.challenge.all { it == 0.toByte() } ||
            value.expiresAtEpochSeconds <= 0
        ) {
            malformed("M4 auth challenge shape is invalid")
        }
        return message(MESSAGING_MAX_WIRE_FRAME_BYTES) {
            uint(1, value.protocolVersion.toLong())
            bytes(2, value.challenge)
            uint(3, value.expiresAtEpochSeconds)
        }
    }

    private fun decodeAuthChallenge(data: ByteArray): MessagingAuthChallenge {
        val reader = MessagingFixedReader(data)
        var version: Long? = null
        var challenge: ByteArray? = null
        var expiry: Long? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "auth challenge protocol version")
                2 -> challenge = unique(
                    challenge,
                    reader.readBytes(wireType, MESSAGING_AUTH_CHALLENGE_BYTES),
                    "auth challenge",
                )
                3 -> expiry = unique(expiry, reader.readUInt(wireType), "auth challenge expiry")
                else -> reader.skip(wireType)
            }
        }
        val value = MessagingAuthChallenge(
            challenge = challenge ?: malformed("M4 auth challenge is missing"),
            expiresAtEpochSeconds = expiry ?: malformed("M4 auth challenge expiry is missing"),
            protocolVersion = (version ?: malformed("M4 auth challenge protocol version is missing")).toIntChecked(),
        )
        requireVersion(value.protocolVersion)
        if (
            value.challenge.size != MESSAGING_AUTH_CHALLENGE_BYTES ||
            value.challenge.all { it == 0.toByte() } ||
            value.expiresAtEpochSeconds <= 0
        ) {
            malformed("M4 auth challenge shape is invalid")
        }
        return value
    }

    private fun encodeAuthResponse(value: MessagingAuthResponse): ByteArray {
        MessagingProtocol.validateAuthResponseShape(value)
        return message(MESSAGING_MAX_WIRE_FRAME_BYTES) {
            uint(1, value.protocolVersion.toLong())
            bytes(2, value.identityId)
            bytes(3, value.challenge)
            uint(4, value.expiresAtEpochSeconds)
            bytes(5, value.signature)
        }
    }

    private fun decodeAuthResponse(data: ByteArray): MessagingAuthResponse {
        val reader = MessagingFixedReader(data)
        var version: Long? = null
        var identity: ByteArray? = null
        var challenge: ByteArray? = null
        var expiry: Long? = null
        var signature: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "auth response protocol version")
                2 -> identity = unique(
                    identity,
                    reader.readBytes(wireType, MESSAGING_IDENTITY_BYTES),
                    "auth response identity",
                )
                3 -> challenge = unique(
                    challenge,
                    reader.readBytes(wireType, MESSAGING_AUTH_CHALLENGE_BYTES),
                    "auth response challenge",
                )
                4 -> expiry = unique(expiry, reader.readUInt(wireType), "auth response expiry")
                5 -> signature = unique(
                    signature,
                    reader.readBytes(wireType, MESSAGING_MAX_AUTH_SIGNATURE_BYTES),
                    "auth response signature",
                )
                else -> reader.skip(wireType)
            }
        }
        return MessagingAuthResponse(
            identityId = identity ?: malformed("M4 auth response identity is missing"),
            challenge = challenge ?: malformed("M4 auth response challenge is missing"),
            expiresAtEpochSeconds = expiry ?: malformed("M4 auth response expiry is missing"),
            signature = signature ?: malformed("M4 auth response signature is missing"),
            protocolVersion = (version ?: malformed("M4 auth response protocol version is missing")).toIntChecked(),
        ).also(MessagingProtocol::validateAuthResponseShape)
    }

    private fun encodeAck(value: MessagingDeliveryAck): ByteArray {
        validateAck(value)
        return message(MESSAGING_MAX_WIRE_FRAME_BYTES) {
            uint(1, value.protocolVersion.toLong())
            bytes(2, value.senderIdentityId)
            bytes(3, value.messageId)
        }
    }

    private fun decodeAck(data: ByteArray): MessagingDeliveryAck {
        val reader = MessagingFixedReader(data)
        var version: Long? = null
        var sender: ByteArray? = null
        var messageId: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "ACK protocol version")
                2 -> sender = unique(sender, reader.readBytes(wireType, MESSAGING_IDENTITY_BYTES), "ACK sender")
                3 -> messageId = unique(
                    messageId,
                    reader.readBytes(wireType, MESSAGING_MESSAGE_ID_BYTES),
                    "ACK message id",
                )
                else -> reader.skip(wireType)
            }
        }
        return MessagingDeliveryAck(
            senderIdentityId = sender ?: malformed("M4 ACK sender is missing"),
            messageId = messageId ?: malformed("M4 ACK message id is missing"),
            protocolVersion = (version ?: malformed("M4 ACK protocol version is missing")).toIntChecked(),
        ).also(::validateAck)
    }

    private fun encodeSendAccepted(value: MessagingSendAccepted): ByteArray {
        validateSendAccepted(value)
        return message(MESSAGING_MAX_WIRE_FRAME_BYTES) {
            uint(1, value.protocolVersion.toLong())
            bytes(2, value.recipientIdentityId)
            bytes(3, value.messageId)
        }
    }

    private fun decodeSendAccepted(data: ByteArray): MessagingSendAccepted {
        val reader = MessagingFixedReader(data)
        var version: Long? = null
        var recipient: ByteArray? = null
        var messageId: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "send-accepted protocol version")
                2 -> recipient = unique(
                    recipient,
                    reader.readBytes(wireType, MESSAGING_IDENTITY_BYTES),
                    "send-accepted recipient",
                )
                3 -> messageId = unique(
                    messageId,
                    reader.readBytes(wireType, MESSAGING_MESSAGE_ID_BYTES),
                    "send-accepted message id",
                )
                else -> reader.skip(wireType)
            }
        }
        return MessagingSendAccepted(
            recipientIdentityId = recipient ?: malformed("M4 send-accepted recipient is missing"),
            messageId = messageId ?: malformed("M4 send-accepted message id is missing"),
            protocolVersion = (version ?: malformed("M4 send-accepted protocol version is missing")).toIntChecked(),
        ).also(::validateSendAccepted)
    }

    private fun encodeError(value: MessagingWireError): ByteArray {
        validateError(value)
        return message(MESSAGING_MAX_WIRE_FRAME_BYTES) {
            uint(1, value.protocolVersion.toLong())
            uint(2, value.code.toLong())
            value.messageId?.let { bytes(3, it) }
        }
    }

    private fun decodeError(data: ByteArray): MessagingWireError {
        val reader = MessagingFixedReader(data)
        var version: Long? = null
        var code: Long? = null
        var messageId: ByteArray? = null
        reader.fields { field, wireType ->
            when (field) {
                1 -> version = unique(version, reader.readUInt(wireType), "error protocol version")
                2 -> code = unique(code, reader.readUInt(wireType), "error code")
                3 -> messageId = unique(
                    messageId,
                    reader.readBytes(wireType, MESSAGING_MESSAGE_ID_BYTES),
                    "error message id",
                )
                else -> reader.skip(wireType)
            }
        }
        return MessagingWireError(
            code = (code ?: malformed("M4 error code is missing")).toIntChecked(),
            messageId = messageId,
            protocolVersion = (version ?: malformed("M4 error protocol version is missing")).toIntChecked(),
        ).also(::validateError)
    }

    private fun validateEnvelopeShape(value: MessagingEnvelope) {
        requireVersion(value.protocolVersion)
        requireIdentity(value.senderIdentityId, "M4 envelope sender")
        requireIdentity(value.recipientIdentityId, "M4 envelope recipient")
        if (value.senderIdentityId.contentEquals(value.recipientIdentityId)) malformed("M4 envelope identities must be distinct")
        requireMessageId(value.messageId, "M4 envelope message id")
        if (value.ciphertext.isEmpty() || value.ciphertext.size > MESSAGING_MAX_CIPHERTEXT_BYTES) {
            malformed("M4 envelope ciphertext size is invalid")
        }
        if (value.expiresAtEpochSeconds <= 0) malformed("M4 envelope expiry is invalid")
    }

    private fun validateAck(value: MessagingDeliveryAck) {
        requireVersion(value.protocolVersion)
        requireIdentity(value.senderIdentityId, "M4 ACK sender")
        requireMessageId(value.messageId, "M4 ACK message id")
    }

    private fun validateSendAccepted(value: MessagingSendAccepted) {
        requireVersion(value.protocolVersion)
        requireIdentity(value.recipientIdentityId, "M4 send-accepted recipient")
        requireMessageId(value.messageId, "M4 send-accepted message id")
    }

    private fun validateError(value: MessagingWireError) {
        requireVersion(value.protocolVersion)
        if (value.code !in MESSAGING_ERROR_MALFORMED..MESSAGING_ERROR_RETRY_LATER) malformed("M4 error code is invalid")
        value.messageId?.let { requireMessageId(it, "M4 error message id") }
    }

    private fun requireVersion(value: Int) {
        if (value != MESSAGING_PROTOCOL_VERSION) malformed("unsupported M4 protocol version")
    }

    private fun requireIdentity(value: ByteArray, name: String) {
        if (value.size != MESSAGING_IDENTITY_BYTES) malformed("$name size is invalid")
    }

    private fun requireMessageId(value: ByteArray, name: String) {
        if (value.size != MESSAGING_MESSAGE_ID_BYTES || value.all { it == 0.toByte() }) malformed("$name is invalid")
    }

    private fun clientPayloadCount(value: MessagingClientFrame): Int =
        listOf(value.authResponse, value.send, value.ack).count { it != null }

    private fun serverPayloadCount(value: MessagingServerFrame): Int =
        listOf(
            value.authChallenge != null,
            value.authenticated,
            value.delivery != null,
            value.sendAccepted != null,
            value.error != null,
        ).count { it }

    private fun <T> unique(current: T?, value: T, name: String): T {
        if (current != null) malformed("duplicate $name field")
        return value
    }

    private fun Long.toIntChecked(): Int {
        if (this < 0 || this > Int.MAX_VALUE.toLong()) malformed("protobuf integer exceeds Android range")
        return toInt()
    }

    private fun message(maximum: Int, block: MessagingProtoWriter.() -> Unit): ByteArray =
        MessagingProtoWriter(maximum).apply(block).toByteArray()

    private fun malformed(message: String): Nothing = throw MessagingProtocolException(message)
}

private class MessagingProtoWriter(private val maximum: Int) {
    private val output = ByteArrayOutputStream()

    fun uint(field: Int, value: Long) {
        if (field !in 1..MAX_PROTO_FIELD || value < 0) malformed("invalid protobuf integer field")
        writeVarint((field.toLong() shl 3) or VARINT.toLong())
        writeVarint(value)
        enforceBound()
    }

    fun bytes(field: Int, value: ByteArray) {
        if (field !in 1..MAX_PROTO_FIELD || value.size > maximum) malformed("invalid protobuf bytes field")
        writeVarint((field.toLong() shl 3) or BYTES.toLong())
        writeVarint(value.size.toLong())
        output.write(value)
        enforceBound()
    }

    fun toByteArray(): ByteArray = output.toByteArray().also {
        if (it.isEmpty() || it.size > maximum) malformed("M4 protobuf message size is invalid")
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
        if (output.size() > maximum) malformed("M4 protobuf message exceeds its bound")
    }

    private fun malformed(message: String): Nothing = throw MessagingProtocolException(message)

    private companion object {
        const val MAX_PROTO_FIELD = 536_870_911
        const val VARINT = 0
        const val BYTES = 2
    }
}

private open class MessagingProtoReader(data: ByteArray, private val maximum: Int) {
    private val data = data.copyOf()
    private var position = 0

    init {
        if (data.isEmpty() || data.size > maximum) malformed("M4 protobuf message size is invalid")
    }

    open fun fields(block: (Int, Int) -> Unit) {
        while (position < data.size) {
            val tag = readVarint()
            val field = tag ushr 3
            val wireType = (tag and 7).toInt()
            if (tag < 0 || field !in 1L..MAX_PROTO_FIELD.toLong()) malformed("invalid protobuf field number")
            block(field.toInt(), wireType)
        }
    }

    fun readUInt(wireType: Int): Long {
        requireWireType(wireType, VARINT)
        val value = readVarint()
        if (value < 0) malformed("unsigned protobuf integer exceeds signed Android range")
        return value
    }

    fun readBytes(wireType: Int, fieldMaximum: Int): ByteArray {
        requireWireType(wireType, BYTES)
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
            VARINT -> readVarint()
            FIXED64 -> skipFixed(8)
            BYTES -> {
                val length = readVarint()
                if (length < 0 || length > data.size - position) malformed("unknown protobuf field is invalid")
                position += length.toInt()
            }
            FIXED32 -> skipFixed(4)
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

    protected fun malformed(message: String): Nothing = throw MessagingProtocolException(message)

    private companion object {
        const val MAX_PROTO_FIELD = 536_870_911
        const val VARINT = 0
        const val FIXED64 = 1
        const val BYTES = 2
        const val FIXED32 = 5
    }
}

private class MessagingFixedReader(data: ByteArray) :
    MessagingProtoReader(data, MESSAGING_MAX_WIRE_FRAME_BYTES) {
    private val seen = HashSet<Int>()

    override fun fields(block: (Int, Int) -> Unit) {
        super.fields { field, wireType ->
            if (field > 63 || !seen.add(field)) malformed("duplicate or unsupported fixed-message field")
            block(field, wireType)
        }
    }
}
