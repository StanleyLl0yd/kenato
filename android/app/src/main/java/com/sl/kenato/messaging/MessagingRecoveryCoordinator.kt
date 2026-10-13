package com.sl.kenato.messaging

import com.sl.kenato.call.EncryptedApplicationPayload
import com.sl.kenato.call.EncryptedApplicationPayloadClassifier
import com.sl.kenato.call.VoiceInboundHandoffRecovery
import com.sl.kenato.call.VoiceInboundPersistenceFacade
import com.sl.kenato.call.VoiceOutboundHandoffRecovery
import com.sl.kenato.session.LocalSessionRepository
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.security.MessageDigest
import java.time.Instant

internal data class MessagingRecoveredSend(
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
    val encodedEnvelope: ByteArray,
)

internal data class MessagingRecoveredAck(
    val peerIdentityId: ByteArray,
    val messageId: ByteArray,
)

internal data class MessagingRecoveryPlan(
    val outboundSends: List<MessagingRecoveredSend>,
    val inboundAcks: List<MessagingRecoveredAck>,
)

internal class MessagingRecoveryException(message: String) : IllegalStateException(message)

/**
 * A M5 live event MUST be durably retained for semantic call handling before its metadata
 * becomes ACK-eligible. Implementations persist the authenticated M3 handoff's exact voice
 * plaintext, are idempotent by owner/peer/message id, and throw on failure/conflict.
 *
 * A volatile UI callback cannot satisfy this interface. No implementation is wired by
 * default: M4 remains text-only until an audited encrypted voice-event store exists.
 */
internal fun interface MessagingDurableVoiceEventSink {
    fun persistAuthenticatedVoiceEvent(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
    )
}

internal fun interface MessagingRecoveryClock {
    fun nowEpochSeconds(): Long
}

private object SystemMessagingRecoveryClock : MessagingRecoveryClock {
    override fun nowEpochSeconds(): Long = Instant.now().epochSecond
}

internal interface MessagingSessionHandoffRepository {
    fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff>

    fun completeMessageHandoff(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        direction: Int,
    ): Boolean
}

internal class LocalMessagingSessionHandoffRepository(
    private val repository: LocalSessionRepository,
) : MessagingSessionHandoffRepository {
    override fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff> =
        repository.pendingMessageHandoffs(ownerIdentityId)

    override fun completeMessageHandoff(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        direction: Int,
    ): Boolean = repository.completeMessageHandoff(
        ownerIdentityId,
        peerIdentityId,
        messageId,
        direction,
    )
}

/**
 * Reconciles the M4 crypto-coupled handoff journal with durable conversation history after
 * process restart or reconnect. It does not own sockets, timers, retry policy, or encryption.
 * Returned outbound envelopes are the exact bytes staged with the ratchet advance.
 */
internal class MessagingRecoveryCoordinator(
    private val sessions: MessagingSessionHandoffRepository,
    private val history: ConversationHistoryRepository,
    private val voice: VoiceInboundHandoffRecovery? = null,
    private val voiceSink: MessagingDurableVoiceEventSink? = null,
    private val clock: MessagingRecoveryClock = SystemMessagingRecoveryClock,
    /**
     * Mandatory for any recovered live M5 ACK. A metadata-only replay journal
     * may not authorize ACK without its matching Keystore-authenticated SDP/ICE.
     */
    private val verifiedVoiceAcks: VoiceInboundPersistenceFacade? = null,
    /** Opt-in: no change to M4 outbound recovery until this adapter is supplied. */
    private val outboundVoice: VoiceOutboundHandoffRecovery? = null,
) {
    @Synchronized
    fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan {
        requireIdentity(ownerIdentityId)
        val handoffs = sessions.pendingMessageHandoffs(ownerIdentityId)
        val recoveredSends = reconcileHandoffs(
            ownerIdentityId = ownerIdentityId,
            handoffs = handoffs,
            includeInbound = true,
        )
        val recoveredAcks = history.pendingInboundAcks(ownerIdentityId).map { record ->
            MessagingRecoveredAck(
                peerIdentityId = record.peerIdentityId.copyOf(),
                messageId = record.messageId.copyOf(),
            )
        }.toMutableList()
        if (voice != null) {
            val now = clock.nowEpochSeconds()
            if (now < 0L) throw MessagingRecoveryException("Voice ACK recovery clock is invalid")
            val replayCandidates = voice.pendingLiveReceipts(ownerIdentityId, now)
            if (replayCandidates.isNotEmpty()) {
                val verifier = verifiedVoiceAcks ?: throw MessagingRecoveryException(
                    "Voice replay receipts have no independently encrypted semantic ACK verifier",
                )
                val verified = verifier.verifiedPendingLiveReceipts(ownerIdentityId, now)
                // Fail closed even when a miswired adapter has the same peer/message IDs
                // but a different authenticated encrypted envelope or call metadata.
                val raw = replayCandidates.associateBy {
                    MessageKey(it.peerIdentityId, it.messageId)
                }
                val confirmed = verified.associateBy {
                    MessageKey(it.peerIdentityId, it.messageId)
                }
                if (raw.size != replayCandidates.size ||
                    confirmed.size != verified.size ||
                    raw.keys != confirmed.keys
                ) {
                    throw MessagingRecoveryException("Verified voice ACK keys differ from replay journal")
                }
                for ((key, receipt) in confirmed) {
                    val original = raw[key] ?: throw MessagingRecoveryException(
                        "Verified voice ACK missing authenticated replay receipt",
                    )
                    if (!MessageDigest.isEqual(receipt.envelopeDigest, original.envelopeDigest) ||
                        !MessageDigest.isEqual(receipt.callId, original.callId) ||
                        receipt.kind != original.kind ||
                        receipt.expiresAtEpochSeconds != original.expiresAtEpochSeconds
                    ) {
                        throw MessagingRecoveryException(
                            "Verified voice ACK disagrees with original authenticated replay metadata",
                        )
                    }
                }
                recoveredAcks += verified.map {
                    MessagingRecoveredAck(it.peerIdentityId.copyOf(), it.messageId.copyOf())
                }
            }
        }
        val uniqueAcks = HashSet<MessageKey>()
        if (recoveredAcks.any { !uniqueAcks.add(MessageKey(it.peerIdentityId, it.messageId)) }) {
            throw MessagingRecoveryException("Text and voice ACK key collision during recovery")
        }
        return MessagingRecoveryPlan(recoveredSends, recoveredAcks)
    }

    /**
     * Reconciles only durable outbound work for sender admission. Inbound handoffs are deliberately
     * left untouched so a foreground send cannot race the WSS-owned inbound delivery/ACK path or
     * make inbound plaintext durable without the transport being responsible for the resulting ACK.
     */
    @Synchronized
    fun recoverOutbound(ownerIdentityId: ByteArray): List<MessagingRecoveredSend> {
        requireIdentity(ownerIdentityId)
        return reconcileHandoffs(
            ownerIdentityId = ownerIdentityId,
            handoffs = sessions.pendingMessageHandoffs(ownerIdentityId),
            includeInbound = false,
        )
    }

    /**
     * Reconciles one recovered outbound key that is not known to be in flight on the caller's
     * current socket. If TTL is due, history becomes EXPIRED before the staged ciphertext is
     * removed. ACCEPTED/EXPIRED are idempotent terminal outcomes so a stale recovery plan cannot
     * resurrect or fail on work completed by another path through this coordinator.
     * Returns true when the key is terminal and must not be sent or counted as active staged work.
     */
    @Synchronized
    fun expireOutboundIfDue(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        nowEpochSeconds: Long,
    ): Boolean {
        requireIdentity(ownerIdentityId)
        val staged = pendingOutboundHandoff(ownerIdentityId, peerIdentityId, messageId)
        if (staged != null && applicationVersion(staged) == 2) {
            requireNoTextOutboundCollision(ownerIdentityId, peerIdentityId, messageId)
            val typed = outboundVoice ?: throw MessagingRecoveryException(
                "M5 outbound expiry requires typed voice recovery",
            )
            return typed.expireIfDue(ownerIdentityId, peerIdentityId, messageId, nowEpochSeconds)
        }
        val before = history.currentState(ownerIdentityId)
            ?.messages
            ?.singleOrNull {
                it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                    it.peerIdentityId.contentEquals(peerIdentityId) &&
                    it.messageId.contentEquals(messageId)
            }
            ?: throw MessagingRecoveryException("Expiring outbound message is absent from history")
        val wasExpired = before.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED

        val record = history.expireOutboundIfDue(
            ownerIdentityId = ownerIdentityId,
            peerIdentityId = peerIdentityId,
            messageId = messageId,
            nowEpochSeconds = nowEpochSeconds,
        )
        return when (record.deliveryState) {
            ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE -> false
            ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED -> {
                // A stale plan can observe ACCEPTED after SendAccepted already removed the handoff.
                // Removing again is intentionally best-effort and still terminal.
                sessions.completeMessageHandoff(
                    ownerIdentityId = ownerIdentityId,
                    peerIdentityId = peerIdentityId,
                    messageId = messageId,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                )
                true
            }
            ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED -> {
                val removed = sessions.completeMessageHandoff(
                    ownerIdentityId = ownerIdentityId,
                    peerIdentityId = peerIdentityId,
                    messageId = messageId,
                    direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                )
                if (!removed && !wasExpired) {
                    throw MessagingRecoveryException("Expired outbound message lost its staged handoff")
                }
                true
            }
            else -> throw MessagingRecoveryException("Outbound expiry history state is invalid")
        }
    }

    /**
     * Applies an authenticated server SendAccepted in crash-safe order: history first, staged
     * ciphertext second. If a crash happens between those writes, [recover] observes ACCEPTED and
     * removes the leftover handoff without scheduling another send.
     */
    @Synchronized
    fun recordSendAccepted(
        ownerIdentityId: ByteArray,
        accepted: MessagingSendAccepted,
    ) {
        requireIdentity(ownerIdentityId)
        val staged = pendingOutboundHandoff(
            ownerIdentityId, accepted.recipientIdentityId, accepted.messageId,
        )
        if (staged != null && applicationVersion(staged) == 2) {
            requireNoTextOutboundCollision(ownerIdentityId, accepted.recipientIdentityId, accepted.messageId)
            val typed = outboundVoice ?: throw MessagingRecoveryException(
                "M5 outbound acceptance requires typed voice recovery",
            )
            typed.recordAccepted(ownerIdentityId, accepted, clock.nowEpochSeconds())
            return
        }
        val before = history.currentState(ownerIdentityId)
            ?.messages
            ?.singleOrNull {
                it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                    it.peerIdentityId.contentEquals(accepted.recipientIdentityId) &&
                    it.messageId.contentEquals(accepted.messageId)
            }
            ?: throw MessagingRecoveryException("Accepted outbound message is absent from history")
        val wasAccepted = before.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED
        history.markOutboundAccepted(ownerIdentityId, accepted)
        val removed = sessions.completeMessageHandoff(
            ownerIdentityId = ownerIdentityId,
            peerIdentityId = accepted.recipientIdentityId,
            messageId = accepted.messageId,
            direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
        )
        if (!removed && !wasAccepted) {
            throw MessagingRecoveryException("Accepted outbound message lost its staged handoff")
        }
    }

    private fun reconcileHandoffs(
        ownerIdentityId: ByteArray,
        handoffs: List<SessionMessageHandoff>,
        includeInbound: Boolean,
    ): List<MessagingRecoveredSend> {
        val recoveredSends = ArrayList<MessagingRecoveredSend>()
        val pendingSendKeys = HashSet<MessageKey>()

        // Reject mixed text/voice duplicate transport keys BEFORE an earlier text
        // handoff can be imported into visible conversation history.
        handoffs.filter { it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND }
            .forEach { handoff ->
                if (!pendingSendKeys.add(MessageKey(handoff.peerIdentityId, handoff.messageId))) {
                    throw MessagingRecoveryException("Duplicate cross-type outbound recovery key")
                }
            }
        pendingSendKeys.clear()

        handoffs.forEach { handoff ->
            when (handoff.direction) {
                SessionStateCodec.HANDOFF_DIRECTION_INBOUND -> {
                    if (includeInbound) recoverInbound(ownerIdentityId, handoff)
                }
                SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND -> {
                    when (applicationVersion(handoff)) {
                        2 -> {
                            val adapter = outboundVoice ?: throw MessagingRecoveryException(
                                "M5 outbound handoff requires typed recovery",
                            )
                            requireNoTextOutboundCollision(
                                ownerIdentityId, handoff.peerIdentityId, handoff.messageId,
                            )
                            val now = clock.nowEpochSeconds()
                            val recovered = adapter.recover(ownerIdentityId, handoff, now)
                            if (!pendingSendKeys.add(MessageKey(recovered.peerIdentityId, recovered.messageId))) {
                                throw MessagingRecoveryException("Duplicate typed outbound recovery handoff")
                            }
                            recoveredSends += recovered
                        }
                        1 -> {
                            val record = history.importOutboundPendingAcceptance(ownerIdentityId, handoff)
                            when (record.deliveryState) {
                                ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE -> {
                                    val key = MessageKey(record.peerIdentityId, record.messageId)
                                    if (!pendingSendKeys.add(key)) {
                                        throw MessagingRecoveryException("Duplicate outbound recovery handoff")
                                    }
                                    recoveredSends += MessagingRecoveredSend(
                                        peerIdentityId = handoff.peerIdentityId.copyOf(),
                                        messageId = handoff.messageId.copyOf(),
                                        encodedEnvelope = handoff.encodedEnvelope.copyOf(),
                                    )
                                }
                                ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
                                ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED,
                                -> completeRequired(ownerIdentityId, handoff)
                                else -> throw MessagingRecoveryException(
                                    "Outbound recovery history state is invalid",
                                )
                            }
                        }
                        else -> throw MessagingRecoveryException("Unsupported outbound application version")
                    }
                }
                else -> throw MessagingRecoveryException("Recovery handoff direction is invalid")
            }
        }

        history.pendingOutboundAcceptances(ownerIdentityId).forEach { record ->
            if (!pendingSendKeys.contains(MessageKey(record.peerIdentityId, record.messageId))) {
                throw MessagingRecoveryException(
                    "Pending outbound history is missing its recoverable staged envelope",
                )
            }
        }
        return recoveredSends
    }

    private fun pendingOutboundHandoff(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
    ): SessionMessageHandoff? = sessions.pendingMessageHandoffs(ownerIdentityId)
        .singleOrNull {
            it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                it.peerIdentityId.contentEquals(peerIdentityId) &&
                it.messageId.contentEquals(messageId)
        }

    private fun requireNoTextOutboundCollision(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
    ) {
        if (history.currentState(ownerIdentityId)?.messages?.any {
                it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                    it.peerIdentityId.contentEquals(peerIdentityId) &&
                    it.messageId.contentEquals(messageId)
            } == true
        ) {
            throw MessagingRecoveryException("M5 outbound voice id collides with M4 text history")
        }
    }

    private fun recoverInbound(ownerIdentityId: ByteArray, handoff: SessionMessageHandoff) {
        when (applicationVersion(handoff)) {
            1 -> {
                if (voice?.hasPersistedInboundMessageKey(
                        ownerIdentityId, handoff.peerIdentityId, handoff.messageId,
                    ) == true
                ) {
                    throw MessagingRecoveryException("M4 text collides with a durable M5 voice id")
                }
                history.importInboundPendingAck(ownerIdentityId, handoff)
            }
            2 -> {
                val voiceRecovery = voice ?: throw MessagingRecoveryException(
                    "M5 inbound handoff has no typed voice recovery adapter",
                )
                val sameTextKey = history.currentState(ownerIdentityId)?.messages?.any {
                    it.direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND &&
                        it.peerIdentityId.contentEquals(handoff.peerIdentityId) &&
                        it.messageId.contentEquals(handoff.messageId)
                } == true
                if (sameTextKey) {
                    throw MessagingRecoveryException("M5 voice collides with a durable M4 text id")
                }
                val now = clock.nowEpochSeconds()
                if (now < 0L) throw MessagingRecoveryException("Voice recovery clock is invalid")
                val envelope = try {
                    MessagingWire.decodeEnvelope(handoff.encodedEnvelope)
                } catch (error: Exception) {
                    throw MessagingRecoveryException("Recovered M5 envelope is invalid")
                }
                if (!MessagingWire.encodeEnvelope(envelope).contentEquals(handoff.encodedEnvelope) ||
                    !envelope.senderIdentityId.contentEquals(handoff.peerIdentityId) ||
                    !envelope.recipientIdentityId.contentEquals(ownerIdentityId) ||
                    !envelope.messageId.contentEquals(handoff.messageId)
                ) {
                    throw MessagingRecoveryException("Recovered M5 handoff is not canonically bound to envelope")
                }
                if (envelope.expiresAtEpochSeconds > now) {
                    // The M3 handoff is already committed and authenticated. Validate the
                    // full canonical inner/outer context BEFORE trusting the application sink.
                    // Requiring a durable semantic sink before the replay journal prevents an
                    // ACK from silently discarding the only restorable SDP/ICE offer on crash.
                    val parsed = EncryptedApplicationPayloadClassifier.classify(
                        handoff.encodedPlaintext, envelope, now,
                    )
                    if (parsed !is EncryptedApplicationPayload.Voice) {
                        throw MessagingRecoveryException("Recovered M5 handoff is not a voice record")
                    }
                    val sink = voiceSink ?: throw MessagingRecoveryException(
                        "M5 live handoff has no durable semantic event sink",
                    )
                    sink.persistAuthenticatedVoiceEvent(ownerIdentityId, handoff)
                }
                voiceRecovery.reconcileCommittedHandoff(ownerIdentityId, handoff, now)
            }
            else -> throw MessagingRecoveryException("Unsupported recovered M3 application record version")
        }
        // Both branches durably import or explicitly validate and retire an expired M5 event.
        // A write failure leaves the M3 ratchet-coupled handoff intact. ACKs are read only
        // after reconciliation and therefore cannot precede durable import.
        completeRequired(ownerIdentityId, handoff)
    }

    /**
     * M3 handoffs were already authenticated before the atomic ratchet persist. Read only
     * the canonical version-prefix discriminator here; each destination validates the full
     * plaintext again. Unknown/malformed types must never enter user-visible M4 history.
     */
    private fun applicationVersion(handoff: SessionMessageHandoff): Int {
        val bytes = handoff.encodedPlaintext
        if (bytes.size < 2 || bytes[0] != 0x08.toByte()) {
            throw MessagingRecoveryException("Recovered M3 application prefix is invalid")
        }
        return when (bytes[1].toInt() and 0xff) {
            1 -> 1
            2 -> 2
            else -> throw MessagingRecoveryException("Unknown recovered M3 application version")
        }
    }

    private fun completeRequired(ownerIdentityId: ByteArray, handoff: SessionMessageHandoff) {
        if (
            !sessions.completeMessageHandoff(
                ownerIdentityId = ownerIdentityId,
                peerIdentityId = handoff.peerIdentityId,
                messageId = handoff.messageId,
                direction = handoff.direction,
            )
        ) {
            throw MessagingRecoveryException("Recovery handoff disappeared before durable completion")
        }
    }

    private fun requireIdentity(ownerIdentityId: ByteArray) {
        if (ownerIdentityId.size != MESSAGING_IDENTITY_BYTES) {
            throw MessagingRecoveryException("Recovery owner identity id size is invalid")
        }
    }

    private class MessageKey(
        peerIdentityId: ByteArray,
        messageId: ByteArray,
    ) {
        private val peer = peerIdentityId.copyOf()
        private val message = messageId.copyOf()

        override fun equals(other: Any?): Boolean =
            other is MessageKey && peer.contentEquals(other.peer) && message.contentEquals(other.message)

        override fun hashCode(): Int = 31 * peer.contentHashCode() + message.contentHashCode()
    }
}
