package com.sl.kenato.messaging

import com.sl.kenato.session.LocalSessionRepository
import com.sl.kenato.session.SessionCiphertext
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageCryptoContext
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.time.Instant

internal class MessagingInboundDeliveryException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal interface MessagingInboundSessionDriver {
    fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray

    fun decryptAndStageMessageHandoff(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        ciphertext: SessionCiphertext,
        buildHandoff: (SessionMessageCryptoContext, ByteArray) -> SessionMessageHandoff,
    ): SessionMessageHandoff

    fun completeInboundMessageHandoff(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
    ): Boolean
}

internal class LocalMessagingInboundSessionDriver(
    private val repository: LocalSessionRepository,
) : MessagingInboundSessionDriver {
    override fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray {
        val state = repository.currentState(ownerIdentityId)
            ?: throw MessagingInboundDeliveryException("M4 inbound delivery has no local M3 state")
        val session = state.sessions.singleOrNull { it.peerIdentityId.contentEquals(peerIdentityId) }
            ?: throw MessagingInboundDeliveryException("M4 inbound delivery has no active pinned M3 session")
        return session.localContactId.copyOf()
    }

    override fun decryptAndStageMessageHandoff(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        ciphertext: SessionCiphertext,
        buildHandoff: (SessionMessageCryptoContext, ByteArray) -> SessionMessageHandoff,
    ): SessionMessageHandoff = repository.decryptAndStageMessageHandoff(
        ownerIdentityId = ownerIdentityId,
        localContactId = localContactId,
        ciphertext = ciphertext,
        buildHandoff = buildHandoff,
    )

    override fun completeInboundMessageHandoff(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
    ): Boolean = repository.completeMessageHandoff(
        ownerIdentityId = ownerIdentityId,
        peerIdentityId = peerIdentityId,
        messageId = messageId,
        direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
    )
}

internal fun interface MessagingInboundClock {
    fun nowEpochSeconds(): Long
}

private object SystemMessagingInboundClock : MessagingInboundClock {
    override fun nowEpochSeconds(): Long = Instant.now().epochSecond
}

/**
 * Bridges an authenticated WSS delivery into the M3 ratchet and durable M4 history boundary.
 * The WSS coordinator verifies that [MessagingEnvelope.recipientIdentityId] is the authenticated
 * socket identity before invoking this handler. This class independently revalidates the durable
 * owner/session state and never ACKs a message before authenticated history contains it.
 */
internal class DurableMessagingInboundDeliveryHandler(
    private val sessions: MessagingInboundSessionDriver,
    private val history: ConversationHistoryRepository,
    private val clock: MessagingInboundClock = SystemMessagingInboundClock,
) : MessagingInboundDeliveryHandler {
    @Synchronized
    override fun handle(envelope: MessagingEnvelope): MessagingDeliveryAck {
        val ownerIdentityId = envelope.recipientIdentityId.copyOf()
        requireIdentity(ownerIdentityId, "M4 inbound owner identity id")
        MessagingProtocol.validateEnvelope(envelope, nowEpochSeconds())

        val encodedEnvelope = MessagingWire.encodeEnvelope(envelope)

        // At-least-once redelivery must not touch the ratchet after this exact envelope is durable.
        if (history.matchesAuthenticatedInboundEnvelope(ownerIdentityId, encodedEnvelope)) {
            return acknowledgement(envelope)
        }

        // A reused authenticated message id with different ciphertext/context is a conflict, not a
        // new message. Reject it before native decrypt so it cannot advance the M3 ratchet.
        if (hasConflictingInboundHistoryKey(ownerIdentityId, envelope)) {
            throw MessagingInboundDeliveryException(
                "M4 inbound message id conflicts with an already authenticated history record",
            )
        }

        // Parse and bind the opaque M3 wrapper before consulting local session state. Malformed or
        // relay-rewritten ciphertext therefore cannot trigger a session lookup or native decrypt.
        val ciphertext = try {
            SessionCiphertextWire.decode(envelope.ciphertext)
        } catch (error: Exception) {
            throw MessagingInboundDeliveryException("M4 inbound SessionCiphertext is invalid", error)
        }
        if (
            !ciphertext.senderIdentityId.contentEquals(envelope.senderIdentityId) ||
            !ciphertext.recipientIdentityId.contentEquals(ownerIdentityId)
        ) {
            throw MessagingInboundDeliveryException(
                "M4 inbound SessionCiphertext identities do not match the routing envelope",
            )
        }

        val localContactId = sessions.localContactIdForPeer(
            ownerIdentityId = ownerIdentityId,
            peerIdentityId = envelope.senderIdentityId,
        )
        val handoff = sessions.decryptAndStageMessageHandoff(
            ownerIdentityId = ownerIdentityId,
            localContactId = localContactId,
            ciphertext = ciphertext,
        ) { context, decryptedPlaintext ->
            requireCryptoContext(context, ownerIdentityId, localContactId, envelope.senderIdentityId)
            val plaintext = try {
                MessagingWire.decodePlaintext(decryptedPlaintext)
            } catch (error: Exception) {
                throw MessagingInboundDeliveryException("M4 decrypted plaintext is invalid", error)
            }
            val encodedPlaintext = try {
                MessagingWire.encodePlaintext(plaintext)
            } catch (error: Exception) {
                throw MessagingInboundDeliveryException("M4 decrypted plaintext is invalid", error)
            }
            if (!encodedPlaintext.contentEquals(decryptedPlaintext)) {
                throw MessagingInboundDeliveryException("M4 decrypted plaintext is not canonical")
            }
            MessagingProtocol.validateDeliveryContext(envelope, plaintext, nowEpochSeconds())
            SessionMessageHandoff(
                localContactId = context.localContactId.copyOf(),
                peerIdentityId = context.peerIdentityId.copyOf(),
                messageId = envelope.messageId.copyOf(),
                direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
                encodedPlaintext = encodedPlaintext,
                encodedEnvelope = encodedEnvelope.copyOf(),
            )
        }

        // History must become durable before ACK eligibility. If this write fails, the atomic M3
        // handoff remains for restart recovery and this call emits no ACK.
        history.importInboundPendingAck(ownerIdentityId, handoff)

        // Once history is durable it is sufficient to authorize an idempotent duplicate ACK. The
        // crypto-coupled handoff can therefore be removed; a failure leaves it for recovery.
        if (
            !sessions.completeInboundMessageHandoff(
                ownerIdentityId = ownerIdentityId,
                peerIdentityId = envelope.senderIdentityId,
                messageId = envelope.messageId,
            )
        ) {
            throw MessagingInboundDeliveryException(
                "M4 inbound handoff disappeared before durable completion",
            )
        }

        return acknowledgement(envelope)
    }

    private fun hasConflictingInboundHistoryKey(
        ownerIdentityId: ByteArray,
        envelope: MessagingEnvelope,
    ): Boolean = history.currentState(ownerIdentityId)?.messages?.any {
        it.direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND &&
            it.peerIdentityId.contentEquals(envelope.senderIdentityId) &&
            it.messageId.contentEquals(envelope.messageId)
    } == true

    private fun requireCryptoContext(
        context: SessionMessageCryptoContext,
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
    ) {
        if (
            !context.ownerIdentityId.contentEquals(ownerIdentityId) ||
            !context.localContactId.contentEquals(localContactId) ||
            !context.peerIdentityId.contentEquals(peerIdentityId)
        ) {
            throw MessagingInboundDeliveryException("M4 inbound crypto context does not match the delivery")
        }
    }

    private fun acknowledgement(envelope: MessagingEnvelope): MessagingDeliveryAck = MessagingDeliveryAck(
        senderIdentityId = envelope.senderIdentityId.copyOf(),
        messageId = envelope.messageId.copyOf(),
    )

    private fun requireIdentity(value: ByteArray, name: String) {
        if (value.size != MESSAGING_IDENTITY_BYTES) {
            throw MessagingInboundDeliveryException("$name size is invalid")
        }
    }

    private fun nowEpochSeconds(): Long = clock.nowEpochSeconds().also {
        if (it < 0) throw MessagingInboundDeliveryException("M4 inbound clock returned an invalid timestamp")
    }
}
