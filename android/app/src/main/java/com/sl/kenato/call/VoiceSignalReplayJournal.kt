package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingProtocol
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest

internal class VoiceSignalReplayException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal interface VoiceSignalReplayStore {
    fun read(): ByteArray?
    fun write(bytes: ByteArray): Boolean
    fun clear(): Boolean
}

internal enum class VoiceSignalReplayDecision {
    NEW_EVENT,
    DUPLICATE_EVENT,
    SUPPRESSED_REUSED_CALL_ID,
}

internal class VoiceSignalReplayRecord(
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
    val callId: ByteArray,
    val kind: VoiceSignalKind,
    val expiresAtEpochSeconds: Long,
    val envelopeDigest: ByteArray,
    /** Permanent admission result for an OFFER until this exact event expires. */
    val suppressedOffer: Boolean = false,
)

internal class VoiceSignalReplayState(
    val ownerIdentityId: ByteArray,
    val records: List<VoiceSignalReplayRecord>,
)

/**
 * The journal stores only bounded correlation metadata and SHA-256 envelope digests,
 * never SDP, ICE, ciphertext, voice content, or user-visible chat history.
 *
 * This is NOT an authentication boundary. The caller must pass a durable inbound
 * SessionMessageHandoff created atomically with M3 ratchet advancement. Import must
 * finish BEFORE completing the handoff, ACKing the relay or dispatching call effects.
 * M4 delivery/recovery are intentionally not wired to this module yet.
 */
internal class VoiceSignalReplayJournal(private val store: VoiceSignalReplayStore) {
    @Synchronized
    fun importAuthenticatedInboundHandoff(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
        nowEpochSeconds: Long,
    ): VoiceSignalReplayDecision {
        if (handoff.direction != SessionStateCodec.HANDOFF_DIRECTION_INBOUND ||
            ownerIdentityId.size != VOICE_REPLAY_IDENTITY_BYTES ||
            ownerIdentityId.all { it == 0.toByte() } ||
            handoff.encodedEnvelope.size > VOICE_REPLAY_MAX_ENVELOPE_BYTES
        ) {
            throw VoiceSignalReplayException("Voice replay inbound handoff context is invalid")
        }
        val envelope = try {
            MessagingWire.decodeEnvelope(handoff.encodedEnvelope).also {
                if (!MessagingWire.encodeEnvelope(it).contentEquals(handoff.encodedEnvelope)) {
                    throw VoiceSignalReplayException("Voice replay outer envelope is not canonical")
                }
                MessagingProtocol.validateEnvelope(it, nowEpochSeconds)
            }
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Voice replay outer envelope is invalid", error)
        }
        if (!envelope.recipientIdentityId.contentEquals(ownerIdentityId) ||
            !envelope.senderIdentityId.contentEquals(handoff.peerIdentityId) ||
            !envelope.messageId.contentEquals(handoff.messageId)
        ) {
            throw VoiceSignalReplayException("Voice replay handoff is not bound to its outer envelope")
        }
        val event = try {
            VoiceSignalingWire.decode(
                encoded = handoff.encodedPlaintext,
                envelope = VoiceSignalEnvelopeBinding(
                    envelope.senderIdentityId,
                    envelope.recipientIdentityId,
                    envelope.messageId,
                    envelope.expiresAtEpochSeconds,
                ),
                nowEpochSeconds = nowEpochSeconds,
            )
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Voice replay decrypted signaling is invalid", error)
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(handoff.encodedEnvelope)
        val existing = store.read()?.let(VoiceSignalReplayStateCodec::decode)
        if (existing != null && !existing.ownerIdentityId.contentEquals(ownerIdentityId)) {
            throw VoiceSignalReplayException("Voice replay journal belongs to another identity")
        }
        val retained = existing?.records.orEmpty().filter { it.expiresAtEpochSeconds > nowEpochSeconds }
        val previous = retained.singleOrNull {
            it.peerIdentityId.contentEquals(event.senderIdentityId) &&
                it.messageId.contentEquals(event.messageId)
        }
        if (previous != null) {
            if (!MessageDigest.isEqual(previous.envelopeDigest, digest) ||
                !previous.callId.contentEquals(event.callId) ||
                previous.kind != event.kind ||
                previous.expiresAtEpochSeconds != event.expiresAtEpochSeconds
            ) {
                throw VoiceSignalReplayException("Conflicting authenticated voice signaling message id")
            }
            return VoiceSignalReplayDecision.DUPLICATE_EVENT
        }
        if (retained.size >= VoiceSignalReplayStateCodec.MAX_RECORDS) {
            throw VoiceSignalReplayException("Voice replay journal capacity is exhausted")
        }
        val oldOffer = event.kind == VoiceSignalKind.OFFER && retained.any {
            it.kind == VoiceSignalKind.OFFER &&
                it.peerIdentityId.contentEquals(event.senderIdentityId) &&
                it.callId.contentEquals(event.callId)
        }
        val record = VoiceSignalReplayRecord(
            event.senderIdentityId.copyOf(),
            event.messageId.copyOf(),
            event.callId.copyOf(),
            event.kind,
            event.expiresAtEpochSeconds,
            digest,
            suppressedOffer = oldOffer,
        )
        val encoded = VoiceSignalReplayStateCodec.encode(
            VoiceSignalReplayState(ownerIdentityId.copyOf(), retained + record),
        )
        if (!store.write(encoded)) {
            throw VoiceSignalReplayException("Voice replay journal did not persist")
        }
        return if (oldOffer) VoiceSignalReplayDecision.SUPPRESSED_REUSED_CALL_ID
        else VoiceSignalReplayDecision.NEW_EVENT
    }

    /**
     * Validate an already persisted live M5 receipt using the exact encrypted
     * envelope hash, not untrusted claimed message ids alone. Suppressed offers
     * are still ACK-eligible when their encrypted semantic payload also exists.
     */
    @Synchronized
    fun exactLiveInboundReceipt(
        ownerIdentityId: ByteArray,
        envelope: com.sl.kenato.messaging.MessagingEnvelope,
        nowEpochSeconds: Long,
    ): VoiceSignalReplayReceipt? {
        if (ownerIdentityId.size != VOICE_REPLAY_IDENTITY_BYTES ||
            ownerIdentityId.all { it == 0.toByte() } ||
            !ownerIdentityId.contentEquals(envelope.recipientIdentityId)
        ) {
            throw VoiceSignalReplayException("Voice receipt owner mismatch")
        }
        MessagingProtocol.validateEnvelope(envelope, nowEpochSeconds)
        val state = store.read()?.let(VoiceSignalReplayStateCodec::decode) ?: return null
        if (!state.ownerIdentityId.contentEquals(ownerIdentityId)) {
            throw VoiceSignalReplayException("Voice receipt belongs to another owner")
        }
        val record = state.records.singleOrNull {
            it.peerIdentityId.contentEquals(envelope.senderIdentityId) &&
                it.messageId.contentEquals(envelope.messageId)
        } ?: return null
        val exactDigest = MessageDigest.getInstance("SHA-256").digest(
            MessagingWire.encodeEnvelope(envelope),
        )
        if (!MessageDigest.isEqual(exactDigest, record.envelopeDigest) ||
            record.expiresAtEpochSeconds != envelope.expiresAtEpochSeconds
        ) {
            throw VoiceSignalReplayException("Conflicting encrypted M5 receipt at a persisted message id")
        }
        return VoiceSignalReplayReceipt(
            record.peerIdentityId.copyOf(),
            record.messageId.copyOf(),
            record.callId.copyOf(),
            record.kind,
            record.expiresAtEpochSeconds,
            record.envelopeDigest.copyOf(),
        )
    }

    /**
     * A voice receipt must never share an authenticated sender/message id with M4 text.
     * Include expired retained records: expiry revokes ACK, not message-id provenance.
     */
    @Synchronized
    fun hasPersistedInboundMessageKey(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
    ): Boolean {
        if (ownerIdentityId.size != VOICE_REPLAY_IDENTITY_BYTES ||
            ownerIdentityId.all { it == 0.toByte() } ||
            peerIdentityId.size != VOICE_REPLAY_IDENTITY_BYTES ||
            messageId.size != VOICE_REPLAY_MESSAGE_ID_BYTES
        ) {
            throw VoiceSignalReplayException("Voice replay lookup key is invalid")
        }
        val state = store.read()?.let(VoiceSignalReplayStateCodec::decode) ?: return false
        if (!state.ownerIdentityId.contentEquals(ownerIdentityId)) {
            throw VoiceSignalReplayException("Voice replay lookup belongs to another identity")
        }
        return state.records.any {
            it.peerIdentityId.contentEquals(peerIdentityId) &&
                it.messageId.contentEquals(messageId)
        }
    }

    /**
     * An ACK only confirms durable receipt, not permission to execute a call effect.
     * A suppressed OFFER remains ACK-eligible but is NEVER dispatchable, including
     * after the original winning offer expires or the process restarts.
     */
    @Synchronized
    fun pendingLiveDispatchPermits(
        ownerIdentityId: ByteArray,
        nowEpochSeconds: Long,
    ): List<VoiceSignalReplayDispatchPermit> {
        if (ownerIdentityId.size != VOICE_REPLAY_IDENTITY_BYTES ||
            ownerIdentityId.all { it == 0.toByte() } ||
            nowEpochSeconds < 0
        ) {
            throw VoiceSignalReplayException("Voice dispatch recovery context is invalid")
        }
        val state = store.read()?.let(VoiceSignalReplayStateCodec::decode) ?: return emptyList()
        if (!state.ownerIdentityId.contentEquals(ownerIdentityId)) {
            throw VoiceSignalReplayException("Voice dispatch state belongs to another identity")
        }
        return state.records
            .filter { it.expiresAtEpochSeconds > nowEpochSeconds && !it.suppressedOffer }
            .map {
                VoiceSignalReplayDispatchPermit(
                    it.peerIdentityId.copyOf(),
                    it.messageId.copyOf(),
                    it.callId.copyOf(),
                    it.kind,
                    it.envelopeDigest.copyOf(),
                )
            }
    }

    /** Replays still-live ACK permissions even for successfully suppressed offers. */
    @Synchronized
    fun pendingLiveAcknowledgements(
        ownerIdentityId: ByteArray,
        nowEpochSeconds: Long,
    ): List<VoiceSignalReplayAck> {
        if (ownerIdentityId.size != VOICE_REPLAY_IDENTITY_BYTES ||
            ownerIdentityId.all { it == 0.toByte() } ||
            nowEpochSeconds < 0
        ) {
            throw VoiceSignalReplayException("Voice replay ACK recovery context is invalid")
        }
        val state = store.read()?.let(VoiceSignalReplayStateCodec::decode) ?: return emptyList()
        if (!state.ownerIdentityId.contentEquals(ownerIdentityId)) {
            throw VoiceSignalReplayException("Voice replay ACK state belongs to another identity")
        }
        return state.records
            .filter { it.expiresAtEpochSeconds > nowEpochSeconds }
            .map { VoiceSignalReplayAck(it.peerIdentityId.copyOf(), it.messageId.copyOf()) }
    }
}

/** Immutable-by-convention ACK correlation; copy arrays before handing them to a socket. */
internal class VoiceSignalReplayAck(
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
)

/** A prior authenticated/durable message receipt, not a relay-side voice flag. */
internal class VoiceSignalReplayReceipt(
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
    val callId: ByteArray,
    val kind: VoiceSignalKind,
    val expiresAtEpochSeconds: Long,
    val envelopeDigest: ByteArray,
)

/** Permitted semantic dispatch key, not the authenticated SDP/ICE event payload. */
internal class VoiceSignalReplayDispatchPermit(
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
    val callId: ByteArray,
    val kind: VoiceSignalKind,
    val envelopeDigest: ByteArray,
)

internal object VoiceSignalReplayStateCodec {
    const val MAX_RECORDS = 512
    const val MAX_STATE_BYTES = 64 * 1024
    private const val FORMAT_VERSION = 2
    private const val LEGACY_FORMAT_VERSION = 1
    private const val DIGEST_BYTES = 32
    private const val LEGACY_RECORD_BYTES = 32 + 16 + 16 + 4 + 8 + 32
    private const val RECORD_BYTES = LEGACY_RECORD_BYTES + 1
    private const val HEADER_BYTES = 4 + 4 + 32 + 4
    private val magic = byteArrayOf('K'.code.toByte(), 'N'.code.toByte(), 'V'.code.toByte(), '5'.code.toByte())

    fun encode(state: VoiceSignalReplayState): ByteArray {
        validate(state)
        val content = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(magic)
                output.writeInt(FORMAT_VERSION)
                output.write(state.ownerIdentityId)
                output.writeInt(state.records.size)
                for (r in state.records) {
                    output.write(r.peerIdentityId)
                    output.write(r.messageId)
                    output.write(r.callId)
                    output.writeInt(r.kind.number)
                    output.writeLong(r.expiresAtEpochSeconds)
                    output.write(r.envelopeDigest)
                    output.writeByte(if (r.suppressedOffer) 1 else 0)
                }
            }
            bytes.toByteArray()
        }
        if (content.size + DIGEST_BYTES > MAX_STATE_BYTES) {
            throw VoiceSignalReplayException("Voice replay state exceeds byte bound")
        }
        return content + MessageDigest.getInstance("SHA-256").digest(content)
    }

    fun decode(bytes: ByteArray): VoiceSignalReplayState {
        if (bytes.size < HEADER_BYTES + DIGEST_BYTES || bytes.size > MAX_STATE_BYTES) {
            throw VoiceSignalReplayException("Voice replay persisted state has invalid size")
        }
        val payloadLength = bytes.size - DIGEST_BYTES
        val checksum = MessageDigest.getInstance("SHA-256").run {
            update(bytes, 0, payloadLength)
            digest()
        }
        if (!MessageDigest.isEqual(checksum, bytes.copyOfRange(payloadLength, bytes.size))) {
            throw VoiceSignalReplayException("Voice replay persisted state checksum mismatch")
        }
        return try {
            DataInputStream(ByteArrayInputStream(bytes, 0, payloadLength)).use { input ->
                val header = ByteArray(4).also(input::readFully)
                val version = input.readInt()
                if (!header.contentEquals(magic) ||
                    version !in LEGACY_FORMAT_VERSION..FORMAT_VERSION
                ) {
                    throw VoiceSignalReplayException("Unsupported voice replay state format")
                }
                val owner = ByteArray(VOICE_REPLAY_IDENTITY_BYTES).also(input::readFully)
                val count = input.readInt()
                val recordBytes = if (version == FORMAT_VERSION) RECORD_BYTES else LEGACY_RECORD_BYTES
                if (count !in 0..MAX_RECORDS ||
                    input.available() != count * recordBytes
                ) {
                    throw VoiceSignalReplayException("Voice replay state record count is invalid")
                }
                val records = List(count) {
                    val peer = ByteArray(VOICE_REPLAY_IDENTITY_BYTES).also(input::readFully)
                    val messageId = ByteArray(VOICE_REPLAY_MESSAGE_ID_BYTES).also(input::readFully)
                    val callId = ByteArray(VOICE_REPLAY_MESSAGE_ID_BYTES).also(input::readFully)
                    val kind = VoiceSignalKind.fromNumber(input.readInt().toLong())
                    val expiry = input.readLong()
                    val digest = ByteArray(DIGEST_BYTES).also(input::readFully)
                    val suppressed = if (version == FORMAT_VERSION) {
                        when (input.readUnsignedByte()) {
                            0 -> false
                            1 -> true
                            else -> throw VoiceSignalReplayException("Invalid persisted voice suppression flag")
                        }
                    } else {
                        // V1 could not tell a winning OFFER from an already-suppressed replay.
                        // Conservatively disable all old OFFER effects while retaining live
                        // receipt/ACK rights. Never infer the lost decision from list order.
                        kind == VoiceSignalKind.OFFER
                    }
                    VoiceSignalReplayRecord(peer, messageId, callId, kind, expiry, digest, suppressed)
                }
                if (input.available() != 0) {
                    throw VoiceSignalReplayException("Voice replay state contains trailing bytes")
                }
                VoiceSignalReplayState(owner, records).also(::validate)
            }
        } catch (error: VoiceSignalReplayException) {
            throw error
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Voice replay state is corrupt", error)
        }
    }

    private fun validate(state: VoiceSignalReplayState) {
        if (state.ownerIdentityId.size != VOICE_REPLAY_IDENTITY_BYTES ||
            state.ownerIdentityId.all { it == 0.toByte() } ||
            state.records.size > MAX_RECORDS
        ) {
            throw VoiceSignalReplayException("Voice replay owner or count is invalid")
        }
        val seen = HashSet<List<Byte>>()
        for (record in state.records) {
            if (record.peerIdentityId.size != VOICE_REPLAY_IDENTITY_BYTES ||
                record.peerIdentityId.all { it == 0.toByte() } ||
                record.peerIdentityId.contentEquals(state.ownerIdentityId) ||
                record.messageId.size != VOICE_REPLAY_MESSAGE_ID_BYTES ||
                record.messageId.all { it == 0.toByte() } ||
                record.callId.size != VOICE_REPLAY_MESSAGE_ID_BYTES ||
                record.callId.all { it == 0.toByte() } ||
                record.envelopeDigest.size != DIGEST_BYTES ||
                (record.suppressedOffer && record.kind != VoiceSignalKind.OFFER) ||
                record.expiresAtEpochSeconds <= 0L
            ) {
                throw VoiceSignalReplayException("Voice replay record shape is invalid")
            }
            if (!seen.add(record.peerIdentityId.toList() + record.messageId.toList())) {
                throw VoiceSignalReplayException("Voice replay record ids collide")
            }
        }
    }
}

private const val VOICE_REPLAY_IDENTITY_BYTES = 32
private const val VOICE_REPLAY_MESSAGE_ID_BYTES = 16
private const val VOICE_REPLAY_MAX_ENVELOPE_BYTES = 96 * 1024
