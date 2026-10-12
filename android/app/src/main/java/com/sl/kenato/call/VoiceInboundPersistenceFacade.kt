package com.sl.kenato.call

import com.sl.kenato.messaging.MessagingEnvelope
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.SessionMessageHandoff
import java.security.MessageDigest

internal class VoiceInboundPersistenceException(message: String) : IllegalStateException(message)

/**
 * Opt-in M5 durability boundary for the EXISTING authenticated M3/M4 envelope.
 * Never infer voice from relay-visible metadata. Preflight uses only previously
 * authenticated and persisted exact ciphertext receipts, prior to a second
 * irreversible ratchet decrypt. No call reducer or effects are dispatched.
 */
internal class VoiceInboundPersistenceFacade(
    private val recovery: VoiceInboundHandoffRecovery,
    private val semantic: DurableVoiceSemanticEventRepository,
) {
    @Synchronized
    fun hasDurableDuplicate(
        envelope: MessagingEnvelope,
        receivedAtEpochSeconds: Long,
    ): Boolean {
        val owner = envelope.recipientIdentityId
        val receipt = recovery.exactLiveInboundReceipt(owner, envelope, receivedAtEpochSeconds)
        val existing = semantic.pendingLiveEventSnapshots(owner, receivedAtEpochSeconds)
            .filter {
                MessageDigest.isEqual(it.signal.senderIdentityId, envelope.senderIdentityId) &&
                    MessageDigest.isEqual(it.signal.messageId, envelope.messageId)
            }
        if (receipt == null) {
            if (existing.isNotEmpty()) {
                throw VoiceInboundPersistenceException(
                    "M5 semantic event is committed without a replay receipt; recover M3 handoff first",
                )
            }
            return false
        }
        if (existing.size != 1) {
            throw VoiceInboundPersistenceException(
                "M5 replay receipt lacks exactly one durable semantic payload",
            )
        }
        val event = existing.single()
        if (!MessageDigest.isEqual(event.envelopeDigest, receipt.envelopeDigest) ||
            !MessageDigest.isEqual(event.signal.callId, receipt.callId) ||
            event.signal.kind != receipt.kind ||
            event.signal.expiresAtEpochSeconds != receipt.expiresAtEpochSeconds
        ) {
            throw VoiceInboundPersistenceException("M5 replay receipt contradicts semantic ciphertext")
        }
        return true
    }

    @Synchronized
    fun importCommittedHandoff(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
        receivedAtEpochSeconds: Long,
    ) {
        // AES-GCM semantic payload first, metadata/replay acknowledgement second.
        // Every exception leaves the atomic M3 handoff for restart reconciliation.
        semantic.persistAuthenticatedVoiceEvent(ownerIdentityId, handoff)
        if (recovery.reconcileCommittedHandoff(
                ownerIdentityId, handoff, receivedAtEpochSeconds,
            ) != VoiceInboundHandoffRecoveryOutcome.DURABLY_IMPORTED
        ) {
            throw VoiceInboundPersistenceException("Expired M5 handoff cannot be ACKed")
        }
    }
}
