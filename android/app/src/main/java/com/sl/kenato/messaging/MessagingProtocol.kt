package com.sl.kenato.messaging

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets

internal const val MESSAGING_PROTOCOL_VERSION = 1
internal const val MESSAGING_IDENTITY_BYTES = 32
internal const val MESSAGING_MESSAGE_ID_BYTES = 16
internal const val MESSAGING_AUTH_CHALLENGE_BYTES = 32
internal const val MESSAGING_MAX_AUTH_SIGNATURE_BYTES = 256
internal const val MESSAGING_MAX_TEXT_BYTES = 16 * 1024
internal const val MESSAGING_MAX_CIPHERTEXT_BYTES = 64 * 1024
internal const val MESSAGING_MAX_ENVELOPE_BYTES = 96 * 1024
internal const val MESSAGING_MAX_WIRE_FRAME_BYTES = 100 * 1024
internal const val MESSAGING_MAX_MAILBOX_MESSAGES_PER_RECIPIENT = 500
internal const val MESSAGING_MAX_TTL_SECONDS = 72L * 60L * 60L
internal const val MESSAGING_MAX_AUTH_CHALLENGE_LIFETIME_SECONDS = 30L

internal class MessagingProtocolException(message: String) : IllegalStateException(message)

internal data class MessagingEnvelope(
    val senderIdentityId: ByteArray,
    val recipientIdentityId: ByteArray,
    val messageId: ByteArray,
    val ciphertext: ByteArray,
    val expiresAtEpochSeconds: Long,
    val protocolVersion: Int = MESSAGING_PROTOCOL_VERSION,
)

internal data class MessagingPlaintext(
    val senderIdentityId: ByteArray,
    val recipientIdentityId: ByteArray,
    val messageId: ByteArray,
    val sentAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val text: String,
    val protocolVersion: Int = MESSAGING_PROTOCOL_VERSION,
)

internal data class MessagingAuthChallenge(
    val challenge: ByteArray,
    val expiresAtEpochSeconds: Long,
    val protocolVersion: Int = MESSAGING_PROTOCOL_VERSION,
)

internal data class MessagingAuthResponse(
    val identityId: ByteArray,
    val challenge: ByteArray,
    val expiresAtEpochSeconds: Long,
    val signature: ByteArray,
    val protocolVersion: Int = MESSAGING_PROTOCOL_VERSION,
)

internal object MessagingProtocol {
    private val authDomain = domain("KENATO-MESSAGING-AUTH-V1")

    fun authPayload(identityId: ByteArray, challenge: ByteArray, expiresAtEpochSeconds: Long): ByteArray {
        requireIdentity(identityId, "identity id")
        requireChallenge(challenge)
        if (expiresAtEpochSeconds <= 0) throw MessagingProtocolException("M4 auth expiry is invalid")
        return bytes {
            write(authDomain)
            write(identityId)
            write(challenge)
            writeLong(expiresAtEpochSeconds)
        }
    }

    fun validateAuthChallenge(value: MessagingAuthChallenge, nowEpochSeconds: Long) {
        requireVersion(value.protocolVersion)
        requireChallenge(value.challenge)
        if (nowEpochSeconds < 0 || value.expiresAtEpochSeconds <= nowEpochSeconds) {
            throw MessagingProtocolException("M4 auth challenge is expired")
        }
        if (value.expiresAtEpochSeconds - nowEpochSeconds > MESSAGING_MAX_AUTH_CHALLENGE_LIFETIME_SECONDS) {
            throw MessagingProtocolException("M4 auth challenge lifetime is invalid")
        }
    }

    fun validateAuthResponseShape(value: MessagingAuthResponse) {
        requireVersion(value.protocolVersion)
        requireIdentity(value.identityId, "identity id")
        requireChallenge(value.challenge)
        if (value.expiresAtEpochSeconds <= 0) throw MessagingProtocolException("M4 auth expiry is invalid")
        if (value.signature.isEmpty() || value.signature.size > MESSAGING_MAX_AUTH_SIGNATURE_BYTES) {
            throw MessagingProtocolException("M4 auth signature size is invalid")
        }
    }

    fun validateAuthResponseForChallenge(
        response: MessagingAuthResponse,
        challenge: MessagingAuthChallenge,
        nowEpochSeconds: Long,
    ) {
        validateAuthChallenge(challenge, nowEpochSeconds)
        validateAuthResponseShape(response)
        if (
            !response.challenge.contentEquals(challenge.challenge) ||
            response.expiresAtEpochSeconds != challenge.expiresAtEpochSeconds
        ) {
            throw MessagingProtocolException("M4 auth response does not match the connection challenge")
        }
    }

    fun validateEnvelope(value: MessagingEnvelope, nowEpochSeconds: Long) {
        requireVersion(value.protocolVersion)
        requireIdentity(value.senderIdentityId, "sender identity id")
        requireIdentity(value.recipientIdentityId, "recipient identity id")
        if (value.senderIdentityId.contentEquals(value.recipientIdentityId)) {
            throw MessagingProtocolException("M4 sender and recipient must be distinct")
        }
        requireMessageId(value.messageId)
        if (value.ciphertext.isEmpty() || value.ciphertext.size > MESSAGING_MAX_CIPHERTEXT_BYTES) {
            throw MessagingProtocolException("M4 ciphertext size is invalid")
        }
        if (nowEpochSeconds < 0 || value.expiresAtEpochSeconds <= nowEpochSeconds) {
            throw MessagingProtocolException("M4 envelope is expired")
        }
        if (value.expiresAtEpochSeconds - nowEpochSeconds > MESSAGING_MAX_TTL_SECONDS) {
            throw MessagingProtocolException("M4 envelope TTL is invalid")
        }
    }

    fun validatePlaintext(value: MessagingPlaintext) {
        requireVersion(value.protocolVersion)
        requireIdentity(value.senderIdentityId, "sender identity id")
        requireIdentity(value.recipientIdentityId, "recipient identity id")
        if (value.senderIdentityId.contentEquals(value.recipientIdentityId)) {
            throw MessagingProtocolException("M4 sender and recipient must be distinct")
        }
        requireMessageId(value.messageId)
        if (value.sentAtEpochSeconds <= 0 || value.expiresAtEpochSeconds <= value.sentAtEpochSeconds) {
            throw MessagingProtocolException("M4 plaintext timestamps are invalid")
        }
        if (value.expiresAtEpochSeconds - value.sentAtEpochSeconds > MESSAGING_MAX_TTL_SECONDS) {
            throw MessagingProtocolException("M4 plaintext TTL is invalid")
        }
        val encodedText = value.text.toByteArray(StandardCharsets.UTF_8)
        if (encodedText.isEmpty() || encodedText.size > MESSAGING_MAX_TEXT_BYTES) {
            throw MessagingProtocolException("M4 text size is invalid")
        }
    }

    fun validateDeliveryContext(
        envelope: MessagingEnvelope,
        plaintext: MessagingPlaintext,
        nowEpochSeconds: Long,
    ) {
        validateEnvelope(envelope, nowEpochSeconds)
        validatePlaintext(plaintext)
        if (
            !envelope.senderIdentityId.contentEquals(plaintext.senderIdentityId) ||
            !envelope.recipientIdentityId.contentEquals(plaintext.recipientIdentityId) ||
            !envelope.messageId.contentEquals(plaintext.messageId) ||
            envelope.expiresAtEpochSeconds != plaintext.expiresAtEpochSeconds
        ) {
            throw MessagingProtocolException("M4 decrypted context does not match routing metadata")
        }
    }

    private fun requireVersion(value: Int) {
        if (value != MESSAGING_PROTOCOL_VERSION) throw MessagingProtocolException("Unsupported M4 protocol version")
    }

    private fun requireIdentity(value: ByteArray, name: String) {
        if (value.size != MESSAGING_IDENTITY_BYTES) throw MessagingProtocolException("$name size is invalid")
    }

    private fun requireChallenge(value: ByteArray) {
        if (value.size != MESSAGING_AUTH_CHALLENGE_BYTES || value.all { it == 0.toByte() }) {
            throw MessagingProtocolException("M4 auth challenge is invalid")
        }
    }

    private fun requireMessageId(value: ByteArray) {
        if (value.size != MESSAGING_MESSAGE_ID_BYTES || value.all { it == 0.toByte() }) {
            throw MessagingProtocolException("M4 message id is invalid")
        }
    }

    private fun bytes(block: DataOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { output -> output.block() }
            buffer.toByteArray()
        }

    private fun domain(value: String): ByteArray = (value + "\u0000").toByteArray(StandardCharsets.UTF_8)
}
