package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingDurableVoiceEventSink
import com.sl.kenato.messaging.MessagingProtocol
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.time.Instant

internal class VoiceSemanticEventException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal interface VoiceSemanticEncryptedStore {
    fun read(): ByteArray?
    fun write(value: ByteArray): Boolean
    fun clear(): Boolean
}

/** The Android implementation must authenticate every encryption and decryption using AAD. */
internal interface VoiceSemanticPayloadCipher {
    fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray
    fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray
}

internal fun interface VoiceSemanticClock {
    fun nowEpochSeconds(): Long
}

private object SystemVoiceSemanticClock : VoiceSemanticClock {
    override fun nowEpochSeconds(): Long = Instant.now().epochSecond
}

/** This payload is private to the device and encrypted on disk; never sent to the relay. */
internal class VoiceSemanticEventRecord(
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
    val expiresAtEpochSeconds: Long,
    val envelopeDigest: ByteArray,
    val encodedPlaintext: ByteArray,
)

internal class VoiceSemanticEventState(
    val ownerIdentityId: ByteArray,
    val records: List<VoiceSemanticEventRecord>,
)

/**
 * Canonical, bounded, checksum-protected plaintext *inside* AES-GCM. The SHA-256
 * checksum only detects accidental corruption; Android Keystore AES-GCM authenticates
 * the persisted bytes. Never write this encoding to disk without encryption.
 */
internal object VoiceSemanticEventStateCodec {
    const val MAX_RECORDS = 128
    const val MAX_STATE_BYTES = 2 * 1024 * 1024
    const val MAX_EVENT_BYTES = 20 * 1024
    const val MAX_ENCRYPTED_BYTES = MAX_STATE_BYTES + 64
    private const val VERSION = 1
    private const val DIGEST_BYTES = 32
    private const val HEADER_BYTES = 4 + 4 + 32 + 4
    private const val RECORD_FIXED_BYTES = 32 + 16 + 8 + 32 + 4
    private val magic = byteArrayOf('K'.code.toByte(), 'N'.code.toByte(), 'V'.code.toByte(), '6'.code.toByte())

    fun encode(state: VoiceSemanticEventState): ByteArray {
        validate(state)
        val payload = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.write(magic)
                out.writeInt(VERSION)
                out.write(state.ownerIdentityId)
                out.writeInt(state.records.size)
                for (record in state.records) {
                    out.write(record.peerIdentityId)
                    out.write(record.messageId)
                    out.writeLong(record.expiresAtEpochSeconds)
                    out.write(record.envelopeDigest)
                    out.writeInt(record.encodedPlaintext.size)
                    out.write(record.encodedPlaintext)
                }
            }
            bytes.toByteArray()
        }
        if (payload.size > MAX_STATE_BYTES - DIGEST_BYTES) {
            throw VoiceSemanticEventException("Voice semantic state exceeds global byte limit")
        }
        return payload + MessageDigest.getInstance("SHA-256").digest(payload)
    }

    fun decode(encoded: ByteArray): VoiceSemanticEventState {
        if (encoded.size < HEADER_BYTES + DIGEST_BYTES || encoded.size > MAX_STATE_BYTES) {
            throw VoiceSemanticEventException("Voice semantic state length is invalid")
        }
        val size = encoded.size - DIGEST_BYTES
        val digest = MessageDigest.getInstance("SHA-256").run {
            update(encoded, 0, size)
            digest()
        }
        if (!MessageDigest.isEqual(digest, encoded.copyOfRange(size, encoded.size))) {
            throw VoiceSemanticEventException("Voice semantic state checksum mismatch")
        }
        return try {
            DataInputStream(ByteArrayInputStream(encoded, 0, size)).use { input ->
                val actualMagic = ByteArray(4).also(input::readFully)
                if (!actualMagic.contentEquals(magic) || input.readInt() != VERSION) {
                    throw VoiceSemanticEventException("Unsupported voice semantic state format")
                }
                val owner = ByteArray(32).also(input::readFully)
                val count = input.readInt()
                if (count !in 0..MAX_RECORDS ||
                    input.available() < count * RECORD_FIXED_BYTES
                ) {
                    throw VoiceSemanticEventException("Voice semantic event count is invalid")
                }
                val events = List(count) {
                    val peer = ByteArray(32).also(input::readFully)
                    val messageId = ByteArray(16).also(input::readFully)
                    val expiry = input.readLong()
                    val envelopeDigest = ByteArray(DIGEST_BYTES).also(input::readFully)
                    val length = input.readInt()
                    if (length !in 1..MAX_EVENT_BYTES || length > input.available()) {
                        throw VoiceSemanticEventException("Voice semantic payload length is invalid")
                    }
                    VoiceSemanticEventRecord(
                        peer, messageId, expiry, envelopeDigest,
                        ByteArray(length).also(input::readFully),
                    )
                }
                if (input.available() != 0) {
                    throw VoiceSemanticEventException("Voice semantic state has trailing bytes")
                }
                VoiceSemanticEventState(owner, events).also(::validate)
            }
        } catch (error: VoiceSemanticEventException) {
            throw error
        } catch (error: Exception) {
            throw VoiceSemanticEventException("Unable to decode voice semantic state", error)
        }
    }

    private fun validate(state: VoiceSemanticEventState) {
        if (state.ownerIdentityId.size != 32 ||
            state.ownerIdentityId.all { it == 0.toByte() } ||
            state.records.size > MAX_RECORDS
        ) {
            throw VoiceSemanticEventException("Voice semantic owner/count is invalid")
        }
        val keys = HashSet<List<Byte>>()
        var bytes = (HEADER_BYTES + DIGEST_BYTES).toLong()
        for (record in state.records) {
            if (record.peerIdentityId.size != 32 ||
                record.peerIdentityId.all { it == 0.toByte() } ||
                record.peerIdentityId.contentEquals(state.ownerIdentityId) ||
                record.messageId.size != 16 ||
                record.messageId.all { it == 0.toByte() } ||
                record.envelopeDigest.size != DIGEST_BYTES ||
                record.expiresAtEpochSeconds <= 1 ||
                record.encodedPlaintext.size !in 1..MAX_EVENT_BYTES
            ) {
                throw VoiceSemanticEventException("Voice semantic record metadata is invalid")
            }
            if (!keys.add(record.peerIdentityId.toList() + record.messageId.toList())) {
                throw VoiceSemanticEventException("Voice semantic event id collision")
            }
            bytes += RECORD_FIXED_BYTES.toLong() + record.encodedPlaintext.size.toLong()
            if (bytes > MAX_STATE_BYTES) {
                throw VoiceSemanticEventException("Voice semantic state byte limit exceeded")
            }
            try {
                VoiceSignalingWire.decode(
                    record.encodedPlaintext,
                    VoiceSignalEnvelopeBinding(
                        record.peerIdentityId,
                        state.ownerIdentityId,
                        record.messageId,
                        record.expiresAtEpochSeconds,
                    ),
                    record.expiresAtEpochSeconds - 1,
                )
            } catch (error: Exception) {
                throw VoiceSemanticEventException("Voice semantic record is not canonical/bound", error)
            }
        }
    }
}

/**
 * Durable semantic acceptance before M5 replay-journal ACK eligibility.
 * This is an isolated implementation, not yet configured in the live M4 transport.
 * The *entire* stored state is encrypted with owner-bound AAD using Android Keystore
 * AES-GCM, with a fresh nonce per atomic write and no Android auto-backup.
 */
internal class DurableVoiceSemanticEventRepository(
    private val encryptedStore: VoiceSemanticEncryptedStore,
    private val cipher: VoiceSemanticPayloadCipher,
    private val clock: VoiceSemanticClock = SystemVoiceSemanticClock,
) : MessagingDurableVoiceEventSink {
    @Synchronized
    override fun persistAuthenticatedVoiceEvent(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
    ) {
        requireOwner(ownerIdentityId)
        val now = requireNow()
        if (handoff.direction != SessionStateCodec.HANDOFF_DIRECTION_INBOUND ||
            handoff.localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES
        ) {
            throw VoiceSemanticEventException("Voice semantic M3 handoff is not inbound")
        }
        val envelope = try {
            MessagingWire.decodeEnvelope(handoff.encodedEnvelope)
        } catch (error: Exception) {
            throw VoiceSemanticEventException("Voice semantic envelope is invalid", error)
        }
        if (!MessagingWire.encodeEnvelope(envelope).contentEquals(handoff.encodedEnvelope) ||
            !envelope.recipientIdentityId.contentEquals(ownerIdentityId) ||
            !envelope.senderIdentityId.contentEquals(handoff.peerIdentityId) ||
            !envelope.messageId.contentEquals(handoff.messageId)
        ) {
            throw VoiceSemanticEventException("Voice semantic envelope provenance is invalid")
        }
        val signal = try {
            MessagingProtocol.validateEnvelope(envelope, now)
            VoiceSignalingWire.decode(
                handoff.encodedPlaintext,
                VoiceSignalEnvelopeBinding(
                    envelope.senderIdentityId,
                    envelope.recipientIdentityId,
                    envelope.messageId,
                    envelope.expiresAtEpochSeconds,
                ),
                now,
            )
        } catch (error: Exception) {
            throw VoiceSemanticEventException("Voice semantic handoff is not validated", error)
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(handoff.encodedEnvelope)
        val state = load(ownerIdentityId) ?: VoiceSemanticEventState(ownerIdentityId.copyOf(), emptyList())
        val retained = state.records.filter { it.expiresAtEpochSeconds > now }
        val sameKey = retained.singleOrNull {
            it.peerIdentityId.contentEquals(signal.senderIdentityId) &&
                it.messageId.contentEquals(signal.messageId)
        }
        if (sameKey != null) {
            if (!MessageDigest.isEqual(sameKey.envelopeDigest, digest) ||
                !sameKey.encodedPlaintext.contentEquals(handoff.encodedPlaintext) ||
                sameKey.expiresAtEpochSeconds != signal.expiresAtEpochSeconds
            ) {
                throw VoiceSemanticEventException("Conflicting semantic voice message id")
            }
            return
        }
        if (retained.size >= VoiceSemanticEventStateCodec.MAX_RECORDS) {
            throw VoiceSemanticEventException("Live semantic event store is at capacity")
        }
        val appended = VoiceSemanticEventState(
            ownerIdentityId.copyOf(),
            retained + VoiceSemanticEventRecord(
                signal.senderIdentityId.copyOf(),
                signal.messageId.copyOf(),
                signal.expiresAtEpochSeconds,
                digest,
                handoff.encodedPlaintext.copyOf(),
            ),
        )
        val bytes = VoiceSemanticEventStateCodec.encode(appended)
        val encrypted = try {
            cipher.encrypt(bytes, aad(ownerIdentityId))
        } finally {
            bytes.fill(0)
        }
        if (encrypted.isEmpty() || encrypted.size > VoiceSemanticEventStateCodec.MAX_ENCRYPTED_BYTES ||
            !encryptedStore.write(encrypted)
        ) {
            throw VoiceSemanticEventException("Voice semantic event was not durably written")
        }
    }

    /** Read only live, authenticated, canonical decrypted events for a future foreground consumer. */
    @Synchronized
    fun pendingLiveEvents(ownerIdentityId: ByteArray): List<VoiceSignalPlaintext> {
        requireOwner(ownerIdentityId)
        val now = requireNow()
        return load(ownerIdentityId)
            ?.records
            ?.filter { it.expiresAtEpochSeconds > now }
            ?.map {
                VoiceSignalingWire.decode(
                    it.encodedPlaintext,
                    VoiceSignalEnvelopeBinding(
                        it.peerIdentityId, ownerIdentityId, it.messageId, it.expiresAtEpochSeconds,
                    ),
                    now,
                )
            }
            .orEmpty()
    }

    private fun load(ownerIdentityId: ByteArray): VoiceSemanticEventState? {
        val encrypted = encryptedStore.read() ?: return null
        if (encrypted.isEmpty() || encrypted.size > VoiceSemanticEventStateCodec.MAX_ENCRYPTED_BYTES) {
            throw VoiceSemanticEventException("Encrypted semantic voice state is oversized")
        }
        val plaintext = try {
            cipher.decrypt(encrypted, aad(ownerIdentityId))
        } catch (error: Exception) {
            throw VoiceSemanticEventException("Cannot authenticate stored voice semantic events", error)
        }
        return try {
            VoiceSemanticEventStateCodec.decode(plaintext).also {
                if (!it.ownerIdentityId.contentEquals(ownerIdentityId)) {
                    throw VoiceSemanticEventException("Voice semantic state owner identity mismatch")
                }
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun aad(ownerIdentityId: ByteArray): ByteArray =
        "KENATO-M5-VOICE-SEMANTIC-V1\u0000".toByteArray(Charsets.UTF_8) + ownerIdentityId

    private fun requireNow(): Long = clock.nowEpochSeconds().also {
        if (it < 0) throw VoiceSemanticEventException("Invalid voice semantic clock")
    }

    private fun requireOwner(owner: ByteArray) {
        if (owner.size != 32 || owner.all { it == 0.toByte() }) {
            throw VoiceSemanticEventException("Voice semantic owner identity is invalid")
        }
    }
}
