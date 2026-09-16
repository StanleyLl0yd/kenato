package com.sl.kenato.messaging

import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.security.MessageDigest
import java.time.Instant

internal fun interface ConversationHistoryClock {
    fun nowEpochSeconds(): Long
}

private object SystemConversationHistoryClock : ConversationHistoryClock {
    override fun nowEpochSeconds(): Long = Instant.now().epochSecond
}

internal class ConversationHistoryRepository(
    private val stateStore: ConversationHistoryStore,
    private val clock: ConversationHistoryClock = SystemConversationHistoryClock,
) {
    @Synchronized
    fun currentState(ownerIdentityId: ByteArray): ConversationHistoryState? {
        requireIdentity(ownerIdentityId, "owner identity id")
        return loadState(ownerIdentityId)?.copyForCaller()
    }

    /**
     * Makes room for a new outbound record before M3 advances the ratchet. Only records that are
     * already safe to forget may be pruned. Any pruning required by this preflight is itself made
     * durable before encryption starts, so the subsequent handoff import has a real history slot.
     */
    @Synchronized
    fun requireCanAppendOutbound(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        encodedPlaintext: ByteArray,
    ) {
        requireIdentity(ownerIdentityId, "owner identity id")
        if (localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw ConversationHistoryException("Outbound history preflight contact id is invalid")
        }
        requireIdentity(peerIdentityId, "outbound history preflight peer identity id")
        if (peerIdentityId.contentEquals(ownerIdentityId)) {
            throw ConversationHistoryException("Outbound history preflight peer cannot be the local identity")
        }
        requireMessageId(messageId)
        val plaintext = decodeCanonicalPlaintext(encodedPlaintext)
        if (
            !plaintext.senderIdentityId.contentEquals(ownerIdentityId) ||
            !plaintext.recipientIdentityId.contentEquals(peerIdentityId) ||
            !plaintext.messageId.contentEquals(messageId)
        ) {
            throw ConversationHistoryException("Outbound history preflight plaintext provenance is invalid")
        }

        val state = loadState(ownerIdentityId) ?: emptyState(ownerIdentityId)
        val candidate = ConversationHistoryRecord(
            localContactId = localContactId.copyOf(),
            peerIdentityId = peerIdentityId.copyOf(),
            messageId = messageId.copyOf(),
            direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
            deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE,
            encodedPlaintext = encodedPlaintext.copyOf(),
            envelopeDigest = ByteArray(ConversationHistoryStateCodec.ENVELOPE_DIGEST_BYTES),
        )
        if (state.messages.any { sameIdempotencyKey(it, candidate) }) {
            throw ConversationHistoryException("Outbound history preflight message id already exists")
        }

        val admission = admitCandidate(state, candidate)
        if (admission.prunedState.messages.size != state.messages.size) {
            persist(admission.prunedState)
        }
    }

    @Synchronized
    fun importInboundPendingAck(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
    ): ConversationHistoryRecord {
        requireIdentity(ownerIdentityId, "owner identity id")
        val candidate = inboundPendingAck(ownerIdentityId, handoff)
        val state = loadState(ownerIdentityId) ?: emptyState(ownerIdentityId)
        val existing = state.messages.singleOrNull { sameIdempotencyKey(it, candidate) }
        if (existing != null) {
            if (
                existing.deliveryState != ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK ||
                !sameRecordPayload(existing, candidate)
            ) {
                throw ConversationHistoryException("Conflicting conversation history record for authenticated message id")
            }
            return existing.copyForCaller()
        }

        persist(admitCandidate(state, candidate).withCandidate)
        return candidate.copyForCaller()
    }

    @Synchronized
    fun importOutboundPendingAcceptance(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
    ): ConversationHistoryRecord {
        requireIdentity(ownerIdentityId, "owner identity id")
        val candidate = outboundPendingAcceptance(ownerIdentityId, handoff)
        val state = loadState(ownerIdentityId) ?: emptyState(ownerIdentityId)
        val existing = state.messages.singleOrNull { sameIdempotencyKey(it, candidate) }
        if (existing != null) {
            if (
                existing.deliveryState != ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE &&
                existing.deliveryState != ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED &&
                existing.deliveryState != ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED
            ) {
                throw ConversationHistoryException("Conflicting conversation history record for authenticated message id")
            }
            if (!sameRecordPayload(existing, candidate)) {
                throw ConversationHistoryException("Conflicting conversation history record for authenticated message id")
            }
            return existing.copyForCaller()
        }

        persist(admitCandidate(state, candidate).withCandidate)
        return candidate.copyForCaller()
    }

    @Synchronized
    fun pendingInboundAcks(ownerIdentityId: ByteArray): List<ConversationHistoryRecord> {
        requireIdentity(ownerIdentityId, "owner identity id")
        return loadState(ownerIdentityId)
            ?.messages
            ?.filter {
                it.direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND &&
                    it.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK
            }
            ?.map(ConversationHistoryRecord::copyForCaller)
            .orEmpty()
    }

    @Synchronized
    fun pendingOutboundAcceptances(ownerIdentityId: ByteArray): List<ConversationHistoryRecord> {
        requireIdentity(ownerIdentityId, "owner identity id")
        return loadState(ownerIdentityId)
            ?.messages
            ?.filter {
                it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                    it.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE
            }
            ?.map(ConversationHistoryRecord::copyForCaller)
            .orEmpty()
    }

    /**
     * Transitions a still-pending outbound message to durable EXPIRED at the exact protocol expiry
     * boundary. The caller supplies the transport clock snapshot so persistence and envelope
     * validation make the same decision.
     */
    @Synchronized
    fun expireOutboundIfDue(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        nowEpochSeconds: Long,
    ): ConversationHistoryRecord {
        requireIdentity(ownerIdentityId, "owner identity id")
        requireIdentity(peerIdentityId, "outbound expiry peer identity id")
        if (peerIdentityId.contentEquals(ownerIdentityId)) {
            throw ConversationHistoryException("Outbound expiry peer cannot be the local identity")
        }
        requireMessageId(messageId)
        if (nowEpochSeconds < 0) {
            throw ConversationHistoryException("Conversation history clock returned an invalid timestamp")
        }

        val state = loadState(ownerIdentityId)
            ?: throw ConversationHistoryException("Expiring outbound message is not represented in conversation history")
        val index = state.messages.indexOfFirst {
            it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                it.peerIdentityId.contentEquals(peerIdentityId) &&
                it.messageId.contentEquals(messageId)
        }
        if (index < 0) {
            throw ConversationHistoryException("Expiring outbound message is not represented in conversation history")
        }
        val existing = state.messages[index]
        when (existing.deliveryState) {
            ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
            ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED,
            -> return existing.copyForCaller()
            ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE -> Unit
            else -> throw ConversationHistoryException("Outbound conversation history cannot transition to expired")
        }

        val plaintext = decodeCanonicalPlaintext(existing.encodedPlaintext)
        if (plaintext.expiresAtEpochSeconds > nowEpochSeconds) {
            return existing.copyForCaller()
        }
        val updatedRecord = existing.copy(deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED)
        val messages = state.messages.toMutableList().also { it[index] = updatedRecord }
        persist(state.copy(messages = messages))
        return updatedRecord.copyForCaller()
    }

    @Synchronized
    fun markOutboundAccepted(
        ownerIdentityId: ByteArray,
        accepted: MessagingSendAccepted,
    ): ConversationHistoryRecord {
        requireIdentity(ownerIdentityId, "owner identity id")
        requireSendAccepted(accepted)
        val state = loadState(ownerIdentityId)
            ?: throw ConversationHistoryException("Accepted outbound message is not represented in conversation history")
        val index = state.messages.indexOfFirst {
            it.direction == SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND &&
                it.peerIdentityId.contentEquals(accepted.recipientIdentityId) &&
                it.messageId.contentEquals(accepted.messageId)
        }
        if (index < 0) {
            throw ConversationHistoryException("Accepted outbound message is not represented in conversation history")
        }
        val existing = state.messages[index]
        if (existing.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED) {
            return existing.copyForCaller()
        }
        if (existing.deliveryState != ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE) {
            throw ConversationHistoryException("Outbound conversation history cannot transition to accepted")
        }
        val updatedRecord = existing.copy(deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED)
        val messages = state.messages.toMutableList().also { it[index] = updatedRecord }
        persist(state.copy(messages = messages))
        return updatedRecord.copyForCaller()
    }

    @Synchronized
    fun matchesAuthenticatedInboundEnvelope(
        ownerIdentityId: ByteArray,
        encodedEnvelope: ByteArray,
    ): Boolean {
        requireIdentity(ownerIdentityId, "owner identity id")
        val envelope = decodeCanonicalEnvelope(encodedEnvelope)
        if (!envelope.recipientIdentityId.contentEquals(ownerIdentityId)) {
            throw ConversationHistoryException("Inbound history envelope recipient does not match local identity")
        }
        val envelopeDigest = MessageDigest.getInstance("SHA-256").digest(encodedEnvelope)
        return loadState(ownerIdentityId)?.messages?.any {
            it.direction == SessionStateCodec.HANDOFF_DIRECTION_INBOUND &&
                it.peerIdentityId.contentEquals(envelope.senderIdentityId) &&
                it.messageId.contentEquals(envelope.messageId) &&
                MessageDigest.isEqual(it.envelopeDigest, envelopeDigest)
        } == true
    }

    private fun admitCandidate(
        state: ConversationHistoryState,
        candidate: ConversationHistoryRecord,
    ): HistoryAdmission {
        ConversationHistoryStateCodec.encode(state.copy(messages = listOf(candidate)))

        val working = state.messages.toMutableList()
        var pruningNow: Long? = null
        fun nowForPruning(): Long {
            pruningNow?.let { return it }
            val value = currentTime()
            pruningNow = value
            return value
        }

        while (!conversationFits(working, candidate)) {
            val index = oldestSafelyPrunableIndex(
                messages = working,
                peerIdentityId = candidate.peerIdentityId,
                nowEpochSeconds = nowForPruning(),
            ) ?: throw ConversationHistoryException(
                "Conversation history conversation capacity is exhausted by non-prunable messages",
            )
            working.removeAt(index)
        }

        while (!globalFits(working, candidate)) {
            val index = oldestSafelyPrunableIndex(
                messages = working,
                peerIdentityId = null,
                nowEpochSeconds = nowForPruning(),
            ) ?: throw ConversationHistoryException(
                "Conversation history global capacity is exhausted by non-prunable messages",
            )
            working.removeAt(index)
        }

        val prunedState = state.copy(messages = working.toList())
        val withCandidate = state.copy(messages = working + candidate)
        ConversationHistoryStateCodec.encode(withCandidate)
        return HistoryAdmission(prunedState, withCandidate)
    }

    private fun conversationFits(
        messages: List<ConversationHistoryRecord>,
        candidate: ConversationHistoryRecord,
    ): Boolean {
        var count = 1
        var retainedBytes = ConversationHistoryStateCodec.retainedBytesForBounds(candidate)
        messages.forEach { record ->
            if (record.peerIdentityId.contentEquals(candidate.peerIdentityId)) {
                count++
                if (count > ConversationHistoryStateCodec.MAX_MESSAGES_PER_CONVERSATION) return false
                retainedBytes += ConversationHistoryStateCodec.retainedBytesForBounds(record)
                if (retainedBytes > ConversationHistoryStateCodec.MAX_CONVERSATION_BYTES) return false
            }
        }
        return retainedBytes <= ConversationHistoryStateCodec.MAX_CONVERSATION_BYTES
    }

    private fun globalFits(
        messages: List<ConversationHistoryRecord>,
        candidate: ConversationHistoryRecord,
    ): Boolean {
        if (messages.size >= ConversationHistoryStateCodec.MAX_MESSAGES) return false
        val stateBytes = ConversationHistoryStateCodec.encodedBytesForBounds(messages)
        return stateBytes + ConversationHistoryStateCodec.retainedBytesForBounds(candidate) <=
            ConversationHistoryStateCodec.MAX_STATE_BYTES
    }

    private fun oldestSafelyPrunableIndex(
        messages: List<ConversationHistoryRecord>,
        peerIdentityId: ByteArray?,
        nowEpochSeconds: Long,
    ): Int? {
        var selectedIndex = -1
        var selectedSentAt = Long.MAX_VALUE
        messages.forEachIndexed { index, record ->
            if (peerIdentityId != null && !record.peerIdentityId.contentEquals(peerIdentityId)) return@forEachIndexed
            val plaintext = decodeCanonicalPlaintext(record.encodedPlaintext)
            if (!isSafelyPrunable(record, plaintext, nowEpochSeconds)) return@forEachIndexed
            if (selectedIndex < 0 || plaintext.sentAtEpochSeconds < selectedSentAt) {
                selectedIndex = index
                selectedSentAt = plaintext.sentAtEpochSeconds
            }
        }
        return selectedIndex.takeIf { it >= 0 }
    }

    private fun isSafelyPrunable(
        record: ConversationHistoryRecord,
        plaintext: MessagingPlaintext,
        nowEpochSeconds: Long,
    ): Boolean = when (record.direction) {
        SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND ->
            record.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED ||
                record.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED
        SessionStateCodec.HANDOFF_DIRECTION_INBOUND ->
            record.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK &&
                plaintext.expiresAtEpochSeconds <= nowEpochSeconds
        else -> false
    }

    private fun loadState(ownerIdentityId: ByteArray): ConversationHistoryState? {
        val encoded = stateStore.read() ?: return null
        val state = ConversationHistoryStateCodec.decode(encoded)
        if (!state.ownerIdentityId.contentEquals(ownerIdentityId)) {
            throw ConversationHistoryException("Persisted conversation history belongs to a different local identity")
        }
        return state
    }

    private fun emptyState(ownerIdentityId: ByteArray): ConversationHistoryState = ConversationHistoryState(
        ownerIdentityId = ownerIdentityId.copyOf(),
        messages = emptyList(),
    )

    private fun persist(state: ConversationHistoryState) {
        val encoded = ConversationHistoryStateCodec.encode(state)
        if (!stateStore.write(encoded)) {
            throw ConversationHistoryException("Unable to durably persist conversation history")
        }
    }

    private fun inboundPendingAck(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
    ): ConversationHistoryRecord {
        validateHandoffShape(handoff)
        if (handoff.direction != SessionStateCodec.HANDOFF_DIRECTION_INBOUND) {
            throw ConversationHistoryException("Only inbound handoffs may enter PENDING_ACK")
        }

        val plaintext = decodeCanonicalPlaintext(handoff.encodedPlaintext)
        val envelope = decodeCanonicalEnvelope(handoff.encodedEnvelope)
        if (
            !plaintext.senderIdentityId.contentEquals(handoff.peerIdentityId) ||
            !plaintext.recipientIdentityId.contentEquals(ownerIdentityId) ||
            !plaintext.messageId.contentEquals(handoff.messageId) ||
            !envelope.senderIdentityId.contentEquals(handoff.peerIdentityId) ||
            !envelope.recipientIdentityId.contentEquals(ownerIdentityId) ||
            !envelope.messageId.contentEquals(handoff.messageId) ||
            envelope.expiresAtEpochSeconds != plaintext.expiresAtEpochSeconds
        ) {
            throw ConversationHistoryException("Inbound history handoff does not match authenticated messaging context")
        }

        return ConversationHistoryRecord(
            localContactId = handoff.localContactId.copyOf(),
            peerIdentityId = handoff.peerIdentityId.copyOf(),
            messageId = handoff.messageId.copyOf(),
            direction = SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
            deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACK,
            encodedPlaintext = handoff.encodedPlaintext.copyOf(),
            envelopeDigest = MessageDigest.getInstance("SHA-256").digest(handoff.encodedEnvelope),
        )
    }

    private fun outboundPendingAcceptance(
        ownerIdentityId: ByteArray,
        handoff: SessionMessageHandoff,
    ): ConversationHistoryRecord {
        validateHandoffShape(handoff)
        if (handoff.direction != SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND) {
            throw ConversationHistoryException("Only outbound handoffs may enter PENDING_ACCEPTANCE")
        }

        val plaintext = decodeCanonicalPlaintext(handoff.encodedPlaintext)
        val envelope = decodeCanonicalEnvelope(handoff.encodedEnvelope)
        if (
            !plaintext.senderIdentityId.contentEquals(ownerIdentityId) ||
            !plaintext.recipientIdentityId.contentEquals(handoff.peerIdentityId) ||
            !plaintext.messageId.contentEquals(handoff.messageId) ||
            !envelope.senderIdentityId.contentEquals(ownerIdentityId) ||
            !envelope.recipientIdentityId.contentEquals(handoff.peerIdentityId) ||
            !envelope.messageId.contentEquals(handoff.messageId) ||
            envelope.expiresAtEpochSeconds != plaintext.expiresAtEpochSeconds
        ) {
            throw ConversationHistoryException("Outbound history handoff does not match authenticated messaging context")
        }

        return ConversationHistoryRecord(
            localContactId = handoff.localContactId.copyOf(),
            peerIdentityId = handoff.peerIdentityId.copyOf(),
            messageId = handoff.messageId.copyOf(),
            direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
            deliveryState = ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE,
            encodedPlaintext = handoff.encodedPlaintext.copyOf(),
            envelopeDigest = MessageDigest.getInstance("SHA-256").digest(handoff.encodedEnvelope),
        )
    }

    private fun validateHandoffShape(handoff: SessionMessageHandoff) {
        if (handoff.localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw ConversationHistoryException("History handoff contact id is invalid")
        }
        requireIdentity(handoff.peerIdentityId, "history handoff peer identity id")
        requireMessageId(handoff.messageId)
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

    private fun decodeCanonicalEnvelope(encoded: ByteArray): MessagingEnvelope {
        val value = try {
            MessagingWire.decodeEnvelope(encoded)
        } catch (error: Exception) {
            throw ConversationHistoryException("Conversation history envelope is invalid", error)
        }
        val canonical = try {
            MessagingWire.encodeEnvelope(value)
        } catch (error: Exception) {
            throw ConversationHistoryException("Conversation history envelope is invalid", error)
        }
        if (!canonical.contentEquals(encoded)) {
            throw ConversationHistoryException("Conversation history envelope is not canonical")
        }
        return value
    }

    private fun requireSendAccepted(value: MessagingSendAccepted) {
        if (value.protocolVersion != MESSAGING_PROTOCOL_VERSION) {
            throw ConversationHistoryException("Outbound acceptance protocol version is invalid")
        }
        requireIdentity(value.recipientIdentityId, "outbound acceptance recipient identity id")
        requireMessageId(value.messageId)
    }

    private fun requireIdentity(value: ByteArray, name: String) {
        if (value.size != MESSAGING_IDENTITY_BYTES) {
            throw ConversationHistoryException("$name size is invalid")
        }
    }

    private fun requireMessageId(value: ByteArray) {
        if (value.size != MESSAGING_MESSAGE_ID_BYTES || value.all { it == 0.toByte() }) {
            throw ConversationHistoryException("Conversation history message id is invalid")
        }
    }

    private fun currentTime(): Long = clock.nowEpochSeconds().also {
        if (it < 0) throw ConversationHistoryException("Conversation history clock returned an invalid timestamp")
    }

    private fun sameIdempotencyKey(
        first: ConversationHistoryRecord,
        second: ConversationHistoryRecord,
    ): Boolean =
        first.direction == second.direction &&
            first.peerIdentityId.contentEquals(second.peerIdentityId) &&
            first.messageId.contentEquals(second.messageId)

    private fun sameRecordPayload(
        first: ConversationHistoryRecord,
        second: ConversationHistoryRecord,
    ): Boolean =
        first.localContactId.contentEquals(second.localContactId) &&
            first.peerIdentityId.contentEquals(second.peerIdentityId) &&
            first.messageId.contentEquals(second.messageId) &&
            first.direction == second.direction &&
            first.encodedPlaintext.contentEquals(second.encodedPlaintext) &&
            MessageDigest.isEqual(first.envelopeDigest, second.envelopeDigest)

    private data class HistoryAdmission(
        val prunedState: ConversationHistoryState,
        val withCandidate: ConversationHistoryState,
    )
}
