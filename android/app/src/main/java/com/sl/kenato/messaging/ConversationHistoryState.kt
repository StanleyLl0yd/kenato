package com.sl.kenato.messaging

import com.sl.kenato.session.SessionStateCodec
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest

internal data class ConversationHistoryRecord(
    val localContactId: ByteArray,
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
    val direction: Int,
    val deliveryState: Int,
    val encodedPlaintext: ByteArray,
    val envelopeDigest: ByteArray,
)

internal data class ConversationHistoryState(
    val ownerIdentityId: ByteArray,
    val messages: List<ConversationHistoryRecord>,
)

internal class ConversationHistoryException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal object ConversationHistoryStateCodec {
    const val MAX_STATE_BYTES = 16 * 1024 * 1024
    const val MAX_MESSAGES = 4096
    const val MAX_MESSAGES_PER_CONVERSATION = 1000
    const val MAX_CONVERSATION_BYTES = 4 * 1024 * 1024
    const val DELIVERY_STATE_PENDING_ACK = 1
    const val ENVELOPE_DIGEST_BYTES = 32

    private const val FORMAT_VERSION = 1
    private const val DIGEST_BYTES = 32
    private const val RECORD_FIXED_BYTES =
        SessionStateCodec.LOCAL_CONTACT_ID_BYTES +
            MESSAGING_IDENTITY_BYTES +
            MESSAGING_MESSAGE_ID_BYTES +
            4 +
            4 +
            4 +
            ENVELOPE_DIGEST_BYTES
    private val magic = byteArrayOf('K'.code.toByte(), 'N'.code.toByte(), 'H'.code.toByte(), '4'.code.toByte())

    fun encode(state: ConversationHistoryState): ByteArray {
        validate(state)
        val payload = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(magic)
                output.writeInt(FORMAT_VERSION)
                output.write(state.ownerIdentityId)
                output.writeInt(state.messages.size)
                state.messages.forEach { output.writeRecord(it) }
            }
            bytes.toByteArray()
        }
        if (payload.size > MAX_STATE_BYTES - DIGEST_BYTES) {
            throw ConversationHistoryException("Conversation history exceeds the global byte bound")
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(payload)
        return payload + digest
    }

    fun decode(encoded: ByteArray): ConversationHistoryState {
        if (encoded.size <= DIGEST_BYTES || encoded.size > MAX_STATE_BYTES) {
            throw ConversationHistoryException("Conversation history size is invalid")
        }
        val payloadSize = encoded.size - DIGEST_BYTES
        val actualDigest = MessageDigest.getInstance("SHA-256").run {
            update(encoded, 0, payloadSize)
            digest()
        }
        val expectedDigest = encoded.copyOfRange(payloadSize, encoded.size)
        if (!MessageDigest.isEqual(actualDigest, expectedDigest)) {
            throw ConversationHistoryException("Conversation history checksum is invalid")
        }

        try {
            DataInputStream(ByteArrayInputStream(encoded, 0, payloadSize)).use { input ->
                val actualMagic = ByteArray(magic.size).also(input::readFully)
                if (!actualMagic.contentEquals(magic) || input.readInt() != FORMAT_VERSION) {
                    throw ConversationHistoryException("Conversation history format is unsupported")
                }
                val ownerIdentityId = ByteArray(MESSAGING_IDENTITY_BYTES).also(input::readFully)
                val count = input.readInt()
                if (count !in 0..MAX_MESSAGES) {
                    throw ConversationHistoryException("Conversation history message count is invalid")
                }
                val messages = List(count) { input.readRecord() }
                if (input.available() != 0) {
                    throw ConversationHistoryException("Conversation history contains trailing data")
                }
                return ConversationHistoryState(ownerIdentityId, messages).also(::validate)
            }
        } catch (error: ConversationHistoryException) {
            throw error
        } catch (error: Exception) {
            throw ConversationHistoryException("Conversation history is corrupt", error)
        }
    }

    private fun validate(state: ConversationHistoryState) {
        if (state.ownerIdentityId.size != MESSAGING_IDENTITY_BYTES) {
            throw ConversationHistoryException("Conversation history owner identity id is invalid")
        }
        if (state.messages.size > MAX_MESSAGES) {
            throw ConversationHistoryException("Too many conversation history messages")
        }

        val seen = HashSet<HistoryKey>()
        val conversationCounts = HashMap<ByteArrayKey, Int>()
        val conversationBytes = HashMap<ByteArrayKey, Long>()
        state.messages.forEach { record ->
            validateRecord(state.ownerIdentityId, record)
            val peerKey = ByteArrayKey(record.peerIdentityId)
            val historyKey = HistoryKey(peerKey, ByteArrayKey(record.messageId), record.direction)
            if (!seen.add(historyKey)) {
                throw ConversationHistoryException("Conversation history contains a duplicate idempotency key")
            }
            val count = (conversationCounts[peerKey] ?: 0) + 1
            if (count > MAX_MESSAGES_PER_CONVERSATION) {
                throw ConversationHistoryException("Conversation history exceeds the per-conversation message bound")
            }
            conversationCounts[peerKey] = count
            val retainedBytes = (conversationBytes[peerKey] ?: 0L) + retainedBytes(record)
            if (retainedBytes > MAX_CONVERSATION_BYTES) {
                throw ConversationHistoryException("Conversation history exceeds the per-conversation byte bound")
            }
            conversationBytes[peerKey] = retainedBytes
        }
    }

    private fun validateRecord(ownerIdentityId: ByteArray, record: ConversationHistoryRecord) {
        if (record.localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw ConversationHistoryException("Conversation history contact id is invalid")
        }
        if (
            record.peerIdentityId.size != MESSAGING_IDENTITY_BYTES ||
            record.peerIdentityId.contentEquals(ownerIdentityId)
        ) {
            throw ConversationHistoryException("Conversation history peer identity id is invalid")
        }
        if (
            record.messageId.size != MESSAGING_MESSAGE_ID_BYTES ||
            record.messageId.all { it == 0.toByte() }
        ) {
            throw ConversationHistoryException("Conversation history message id is invalid")
        }
        if (record.direction != SessionStateCodec.HANDOFF_DIRECTION_INBOUND) {
            throw ConversationHistoryException("Conversation history direction is unsupported")
        }
        if (record.deliveryState != DELIVERY_STATE_PENDING_ACK) {
            throw ConversationHistoryException("Conversation history delivery state is unsupported")
        }
        if (
            record.encodedPlaintext.isEmpty() ||
            record.encodedPlaintext.size > SessionStateCodec.MAX_HANDOFF_PLAINTEXT_BYTES
        ) {
            throw ConversationHistoryException("Conversation history plaintext size is invalid")
        }
        if (record.envelopeDigest.size != ENVELOPE_DIGEST_BYTES) {
            throw ConversationHistoryException("Conversation history envelope digest is invalid")
        }

        val plaintext = decodeCanonicalPlaintext(record.encodedPlaintext)
        if (
            !plaintext.senderIdentityId.contentEquals(record.peerIdentityId) ||
            !plaintext.recipientIdentityId.contentEquals(ownerIdentityId) ||
            !plaintext.messageId.contentEquals(record.messageId)
        ) {
            throw ConversationHistoryException("Conversation history plaintext provenance is invalid")
        }
    }

    private fun decodeCanonicalPlaintext(encoded: ByteArray): MessagingPlaintext {
        val value = try {
            MessagingWire.decodePlaintext(encoded)
        } catch (error: Exception) {
            throw ConversationHistoryException("Conversation history plaintext is invalid", error)
        }
        val canonical = try {
            MessagingWire.encodePlaintext(value)
        } catch (error: Exception) {
            throw ConversationHistoryException("Conversation history plaintext is invalid", error)
        }
        if (!canonical.contentEquals(encoded)) {
            throw ConversationHistoryException("Conversation history plaintext is not canonical")
        }
        return value
    }

    private fun retainedBytes(record: ConversationHistoryRecord): Long =
        RECORD_FIXED_BYTES.toLong() + record.encodedPlaintext.size.toLong()

    private fun DataOutputStream.writeRecord(record: ConversationHistoryRecord) {
        write(record.localContactId)
        write(record.peerIdentityId)
        write(record.messageId)
        writeInt(record.direction)
        writeInt(record.deliveryState)
        writeSized(record.encodedPlaintext)
        write(record.envelopeDigest)
    }

    private fun DataInputStream.readRecord(): ConversationHistoryRecord = ConversationHistoryRecord(
        localContactId = ByteArray(SessionStateCodec.LOCAL_CONTACT_ID_BYTES).also(::readFully),
        peerIdentityId = ByteArray(MESSAGING_IDENTITY_BYTES).also(::readFully),
        messageId = ByteArray(MESSAGING_MESSAGE_ID_BYTES).also(::readFully),
        direction = readInt(),
        deliveryState = readInt(),
        encodedPlaintext = readSized(SessionStateCodec.MAX_HANDOFF_PLAINTEXT_BYTES),
        envelopeDigest = ByteArray(ENVELOPE_DIGEST_BYTES).also(::readFully),
    )

    private fun DataOutputStream.writeSized(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }

    private fun DataInputStream.readSized(maximum: Int): ByteArray {
        val size = readInt()
        if (size !in 1..maximum || size > available()) {
            throw ConversationHistoryException("Conversation history field size is invalid")
        }
        return ByteArray(size).also(::readFully)
    }

    private class ByteArrayKey(private val value: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is ByteArrayKey && value.contentEquals(other.value)

        override fun hashCode(): Int = value.contentHashCode()
    }

    private data class HistoryKey(
        val peerIdentityId: ByteArrayKey,
        val messageId: ByteArrayKey,
        val direction: Int,
    )
}

internal fun ConversationHistoryRecord.copyForCaller(): ConversationHistoryRecord = copy(
    localContactId = localContactId.copyOf(),
    peerIdentityId = peerIdentityId.copyOf(),
    messageId = messageId.copyOf(),
    encodedPlaintext = encodedPlaintext.copyOf(),
    envelopeDigest = envelopeDigest.copyOf(),
)

internal fun ConversationHistoryState.copyForCaller(): ConversationHistoryState = copy(
    ownerIdentityId = ownerIdentityId.copyOf(),
    messages = messages.map(ConversationHistoryRecord::copyForCaller),
)
