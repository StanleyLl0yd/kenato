package com.sl.kenato.call

import com.sl.kenato.messaging.ConversationHistoryRepository
import com.sl.kenato.messaging.MESSAGING_MESSAGE_ID_BYTES
import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingMessageIdGenerator
import com.sl.kenato.messaging.MessagingOutboundClock
import com.sl.kenato.messaging.MessagingOutboundSessionDriver
import com.sl.kenato.messaging.MessagingProtocol
import com.sl.kenato.messaging.MessagingSessionHandoffRepository
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.messaging.MessagingWssCoordinator
import com.sl.kenato.messaging.SecureMessagingMessageIdGenerator
import com.sl.kenato.session.SessionCiphertext
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.security.MessageDigest
import java.time.Instant

internal class VoiceOutboundStagingException(message: String) : IllegalStateException(message)

/**
 * Isolated M5 crypto-coupled outbound staging. The exact v2 plaintext, ciphertext and
 * routing envelope survive a crash in the same atomic M3 ratchet handoff.
 *
 * NOT a send/ACK/recovery implementation. Until typed outbound recovery and expiry
 * terminalization are wired, no app entry point may invoke this stage: M4 text recovery
 * intentionally rejects v2 outbound records rather than misclassifying them as chat.
 */
internal class VoiceOutboundHandoffStager(
    private val guard: VoiceOutboundCapabilityGuard,
    private val sessions: MessagingOutboundSessionDriver,
    private val handoffs: MessagingSessionHandoffRepository,
    private val history: ConversationHistoryRepository,
    private val messageIds: MessagingMessageIdGenerator = SecureMessagingMessageIdGenerator(),
    private val clock: MessagingOutboundClock = MessagingOutboundClock { Instant.now().epochSecond },
) {
    @Synchronized
    fun stage(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        callId: ByteArray,
        kind: VoiceSignalKind,
        payload: ByteArray,
        ttlSeconds: Long,
    ): SessionMessageHandoff {
        if (ttlSeconds !in 1L..90L) throw VoiceOutboundStagingException("Invalid M5 outbound TTL")
        // Reject oversized caller input before making an avoidable plaintext copy.
        if (payload.size > 16 * 1024) {
            throw VoiceOutboundStagingException("M5 outbound signal payload is oversized")
        }
        if (callId.size != 16 || callId.all { it == 0.toByte() }) {
            throw VoiceOutboundStagingException("Invalid M5 outbound call id")
        }
        val now = clock.nowEpochSeconds()
        if (now <= 0 || now > Long.MAX_VALUE - ttlSeconds) {
            throw VoiceOutboundStagingException("Invalid M5 outbound clock")
        }
        val existing = handoffs.pendingMessageHandoffs(ownerIdentityId)
        val outbound = existing.filter { it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND }
        if (outbound.size >= MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS) {
            throw VoiceOutboundStagingException("M4/M5 staged transport send capacity reached")
        }
        // This isolated slice permits one uncompleted voice event, until the typed
        // send-accepted/expiry lifecycle can safely free and retry voice work.
        if (outbound.any { it.encodedPlaintext.size >= 2 &&
                it.encodedPlaintext[0] == 0x08.toByte() &&
                it.encodedPlaintext[1] == 0x02.toByte() }) {
            throw VoiceOutboundStagingException("Previous M5 outbound handoff is not terminal")
        }
        val knownIds = existing.map { it.messageId } +
            history.currentState(ownerIdentityId)?.messages.orEmpty().map { it.messageId }
        val messageId = (1..8).asSequence().map { messageIds.nextMessageId() }
            .firstOrNull { id ->
                id.size == MESSAGING_MESSAGE_ID_BYTES &&
                    id.any { it != 0.toByte() } &&
                    knownIds.none { MessageDigest.isEqual(it, id) }
            }?.copyOf() ?: throw VoiceOutboundStagingException("No unique M5 outbound message id")

        val signal = VoiceSignalPlaintext(
            senderIdentityId = ownerIdentityId.copyOf(),
            recipientIdentityId = peerIdentityId.copyOf(),
            messageId = messageId,
            callId = callId.copyOf(),
            sentAtEpochSeconds = now,
            expiresAtEpochSeconds = now + ttlSeconds,
            kind = kind,
            payload = payload.copyOf(),
        )
        // Fail before ratchet mutation for unsupported kind/payload, size or timestamps.
        val plaintext = VoiceSignalingWire.encode(signal)
        if (plaintext.size > SessionStateCodec.MAX_HANDOFF_PLAINTEXT_BYTES) {
            throw VoiceOutboundStagingException("M5 outbound handoff plaintext is oversized")
        }
        val permitted = guard.requireEligiblePeer(ownerIdentityId, peerIdentityId)
        return sessions.encryptAndStageMessageHandoff(
            ownerIdentityId = ownerIdentityId.copyOf(),
            localContactId = permitted.localContactId.copyOf(),
            encodedPlaintext = plaintext,
        ) { context, native ->
            // Recheck within the M3 synchronized encrypt-and-commit builder, immediately
            // before persisting the advanced ratchet. A revoked capability must fail
            // without creating a deliverable v2 record.
            val latest = guard.requireEligiblePeer(ownerIdentityId, peerIdentityId)
            // Close the gap between initial ID/queue preflight and serialized M3 commit.
            // Production adapters must share the same LocalSessionRepository lock.
            val livePending = handoffs.pendingMessageHandoffs(ownerIdentityId)
            if (livePending.size >= SessionStateCodec.MAX_MESSAGE_HANDOFFS ||
                livePending.any { MessageDigest.isEqual(it.messageId, messageId) } ||
                livePending.any {
                    it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                        it.encodedPlaintext.size >= 2 &&
                        it.encodedPlaintext[0] == 0x08.toByte() &&
                        it.encodedPlaintext[1] == 0x02.toByte()
                }
            ) {
                throw VoiceOutboundStagingException("M5 outbound handoff admission changed")
            }
            if (!MessageDigest.isEqual(latest.localContactId, permitted.localContactId) ||
                !MessageDigest.isEqual(context.ownerIdentityId, ownerIdentityId) ||
                !MessageDigest.isEqual(context.peerIdentityId, peerIdentityId) ||
                !MessageDigest.isEqual(context.localContactId, latest.localContactId) ||
                context.localAccountGeneration <= 0 ||
                context.peerAccountGeneration <= 0
            ) {
                throw VoiceOutboundStagingException("M5 outbound M2/M3 crypto binding changed")
            }
            val wrapped = SessionCiphertextWire.encode(
                SessionCiphertext(
                    senderIdentityId = context.ownerIdentityId.copyOf(),
                    recipientIdentityId = context.peerIdentityId.copyOf(),
                    senderAccountGeneration = context.localAccountGeneration,
                    recipientAccountGeneration = context.peerAccountGeneration,
                    olmMessageType = native.messageType,
                    olmMessage = native.ciphertext.copyOf(),
                ),
            )
            val envelope = MessagingEnvelope(
                senderIdentityId = ownerIdentityId.copyOf(),
                recipientIdentityId = peerIdentityId.copyOf(),
                messageId = messageId.copyOf(),
                ciphertext = wrapped,
                expiresAtEpochSeconds = signal.expiresAtEpochSeconds,
            )
            MessagingProtocol.validateEnvelope(envelope, now)
            SessionMessageHandoff(
                localContactId = latest.localContactId.copyOf(),
                peerIdentityId = peerIdentityId.copyOf(),
                messageId = messageId.copyOf(),
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                encodedPlaintext = plaintext.copyOf(),
                encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
            )
        }
    }
}
