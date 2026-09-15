package com.sl.kenato.messaging

import com.sl.kenato.session.LocalSessionRepository
import com.sl.kenato.session.NativeSessionMessage
import com.sl.kenato.session.SessionCiphertext
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageCryptoContext
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.security.SecureRandom
import java.time.Instant

internal class MessagingOutboundSendException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal interface MessagingOutboundSessionDriver {
    fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray

    fun encryptAndStageMessageHandoff(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        encodedPlaintext: ByteArray,
        buildHandoff: (SessionMessageCryptoContext, NativeSessionMessage) -> SessionMessageHandoff,
    ): SessionMessageHandoff
}

internal class LocalMessagingOutboundSessionDriver(
    private val repository: LocalSessionRepository,
) : MessagingOutboundSessionDriver {
    override fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray {
        val state = repository.currentState(ownerIdentityId)
            ?: throw MessagingOutboundSendException("M4 outbound send has no local M3 state")
        val session = state.sessions.singleOrNull { it.peerIdentityId.contentEquals(peerIdentityId) }
            ?: throw MessagingOutboundSendException("M4 outbound send has no active pinned M3 session")
        return session.localContactId.copyOf()
    }

    override fun encryptAndStageMessageHandoff(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        encodedPlaintext: ByteArray,
        buildHandoff: (SessionMessageCryptoContext, NativeSessionMessage) -> SessionMessageHandoff,
    ): SessionMessageHandoff = repository.encryptAndStageMessageHandoff(
        ownerIdentityId = ownerIdentityId,
        localContactId = localContactId,
        encodedPlaintext = encodedPlaintext,
        buildHandoff = buildHandoff,
    )
}

internal fun interface MessagingOutboundRecovery {
    fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan
}

internal class CoordinatorMessagingOutboundRecovery(
    private val coordinator: MessagingRecoveryCoordinator,
) : MessagingOutboundRecovery {
    override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan = coordinator.recover(ownerIdentityId)
}

internal fun interface MessagingMessageIdGenerator {
    fun nextMessageId(): ByteArray
}

internal class SecureMessagingMessageIdGenerator(
    private val random: SecureRandom = SecureRandom(),
) : MessagingMessageIdGenerator {
    override fun nextMessageId(): ByteArray = ByteArray(MESSAGING_MESSAGE_ID_BYTES).also(random::nextBytes)
}

internal fun interface MessagingOutboundClock {
    fun nowEpochSeconds(): Long
}

private object SystemMessagingOutboundClock : MessagingOutboundClock {
    override fun nowEpochSeconds(): Long = Instant.now().epochSecond
}

/**
 * Creates one durable outbound logical message. It never owns a socket and never sends bytes.
 * Network delivery consumes only the exact envelope staged by the atomic M3 handoff boundary.
 */
internal class DurableMessagingOutboundSender(
    private val sessions: MessagingOutboundSessionDriver,
    private val history: ConversationHistoryRepository,
    private val recovery: MessagingOutboundRecovery,
    private val messageIds: MessagingMessageIdGenerator = SecureMessagingMessageIdGenerator(),
    private val clock: MessagingOutboundClock = SystemMessagingOutboundClock,
) {
    @Synchronized
    fun stageText(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        text: String,
        ttlSeconds: Long = MESSAGING_MAX_TTL_SECONDS,
    ): ConversationHistoryRecord {
        requireIdentity(ownerIdentityId, "M4 outbound owner identity id")
        requireIdentity(peerIdentityId, "M4 outbound peer identity id")
        if (ownerIdentityId.contentEquals(peerIdentityId)) {
            throw MessagingOutboundSendException("M4 outbound peer cannot be the local identity")
        }
        val textBytes = text.toByteArray(Charsets.UTF_8)
        if (textBytes.isEmpty() || textBytes.size > MESSAGING_MAX_TEXT_BYTES) {
            throw MessagingOutboundSendException("M4 outbound text size is invalid")
        }
        if (ttlSeconds !in 1..MESSAGING_MAX_TTL_SECONDS) {
            throw MessagingOutboundSendException("M4 outbound message TTL is invalid")
        }

        // Reconcile every older crypto handoff first. This keeps the lower 32-send transport bound
        // authoritative even though the crypto journal itself permits up to 64 crash handoffs.
        val plan = recovery.recover(ownerIdentityId.copyOf())
        if (plan.outboundSends.size >= MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS) {
            throw MessagingOutboundSendException("M4 outbound staged send queue is full")
        }

        val localContactId = sessions.localContactIdForPeer(ownerIdentityId, peerIdentityId)
        if (localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw MessagingOutboundSendException("M4 outbound local contact id is invalid")
        }

        val now = nowEpochSeconds()
        if (now > Long.MAX_VALUE - ttlSeconds) {
            throw MessagingOutboundSendException("M4 outbound message expiry overflows")
        }
        val expiresAt = now + ttlSeconds
        val messageId = nextUniqueMessageId(ownerIdentityId)
        val plaintext = MessagingPlaintext(
            senderIdentityId = ownerIdentityId.copyOf(),
            recipientIdentityId = peerIdentityId.copyOf(),
            messageId = messageId.copyOf(),
            sentAtEpochSeconds = now,
            expiresAtEpochSeconds = expiresAt,
            text = text,
        )
        try {
            MessagingProtocol.validatePlaintext(plaintext)
        } catch (error: Exception) {
            throw MessagingOutboundSendException("M4 outbound plaintext is invalid", error)
        }
        val encodedPlaintext = try {
            MessagingWire.encodePlaintext(plaintext)
        } catch (error: Exception) {
            throw MessagingOutboundSendException("Unable to encode M4 outbound plaintext", error)
        }

        // History bounds are known before encryption because retained history stores plaintext plus
        // an envelope digest, not the full staged envelope. Fail here rather than advance a ratchet
        // that is already known to have no admissible history slot.
        history.requireCanAppendOutbound(
            ownerIdentityId = ownerIdentityId,
            localContactId = localContactId,
            peerIdentityId = peerIdentityId,
            messageId = messageId,
            encodedPlaintext = encodedPlaintext,
        )

        val handoff = sessions.encryptAndStageMessageHandoff(
            ownerIdentityId = ownerIdentityId,
            localContactId = localContactId,
            encodedPlaintext = encodedPlaintext,
        ) { context, nativeMessage ->
            requireCryptoContext(context, ownerIdentityId, localContactId, peerIdentityId)
            val encodedCiphertext = try {
                SessionCiphertextWire.encode(
                    SessionCiphertext(
                        senderIdentityId = context.ownerIdentityId.copyOf(),
                        recipientIdentityId = context.peerIdentityId.copyOf(),
                        senderAccountGeneration = context.localAccountGeneration,
                        recipientAccountGeneration = context.peerAccountGeneration,
                        olmMessageType = nativeMessage.messageType,
                        olmMessage = nativeMessage.ciphertext.copyOf(),
                    ),
                )
            } catch (error: Exception) {
                throw MessagingOutboundSendException("Unable to encode M4 outbound session ciphertext", error)
            }
            val envelope = MessagingEnvelope(
                senderIdentityId = context.ownerIdentityId.copyOf(),
                recipientIdentityId = context.peerIdentityId.copyOf(),
                messageId = messageId.copyOf(),
                ciphertext = encodedCiphertext,
                expiresAtEpochSeconds = expiresAt,
            )
            try {
                MessagingProtocol.validateEnvelope(envelope, nowEpochSeconds())
            } catch (error: Exception) {
                throw MessagingOutboundSendException("M4 outbound envelope is invalid", error)
            }
            val encodedEnvelope = try {
                MessagingWire.encodeEnvelope(envelope)
            } catch (error: Exception) {
                throw MessagingOutboundSendException("Unable to encode M4 outbound envelope", error)
            }
            SessionMessageHandoff(
                localContactId = context.localContactId.copyOf(),
                peerIdentityId = context.peerIdentityId.copyOf(),
                messageId = messageId.copyOf(),
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                encodedPlaintext = encodedPlaintext.copyOf(),
                encodedEnvelope = encodedEnvelope,
            )
        }

        // The ratchet and exact envelope are already durable at this point. If this separate history
        // write fails, the session handoff remains authoritative and restart recovery re-imports it.
        return history.importOutboundPendingAcceptance(ownerIdentityId, handoff)
    }

    private fun nextUniqueMessageId(ownerIdentityId: ByteArray): ByteArray {
        val existingOutboundIds = history.currentState(ownerIdentityId)
            ?.messages
            ?.asSequence()
            ?.filter { it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND }
            ?.map { it.messageId }
            ?.toList()
            .orEmpty()
        repeat(MAX_MESSAGE_ID_ATTEMPTS) {
            val candidate = messageIds.nextMessageId()
            if (
                candidate.size == MESSAGING_MESSAGE_ID_BYTES &&
                candidate.any { it != 0.toByte() } &&
                existingOutboundIds.none { it.contentEquals(candidate) }
            ) {
                return candidate.copyOf()
            }
        }
        throw MessagingOutboundSendException("Unable to generate a unique M4 message id")
    }

    private fun requireCryptoContext(
        context: SessionMessageCryptoContext,
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
    ) {
        if (
            !context.ownerIdentityId.contentEquals(ownerIdentityId) ||
            !context.localContactId.contentEquals(localContactId) ||
            !context.peerIdentityId.contentEquals(peerIdentityId) ||
            context.localAccountGeneration <= 0 ||
            context.peerAccountGeneration <= 0
        ) {
            throw MessagingOutboundSendException("M4 outbound crypto context does not match the pinned session")
        }
    }

    private fun requireIdentity(value: ByteArray, name: String) {
        if (value.size != MESSAGING_IDENTITY_BYTES) {
            throw MessagingOutboundSendException("$name size is invalid")
        }
    }

    private fun nowEpochSeconds(): Long = clock.nowEpochSeconds().also {
        if (it <= 0) throw MessagingOutboundSendException("M4 outbound clock returned an invalid timestamp")
    }

    private companion object {
        const val MAX_MESSAGE_ID_ATTEMPTS = 8
    }
}
