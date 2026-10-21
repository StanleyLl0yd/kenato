package com.sl.kenato.call

import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64

internal class VoiceCallAdmissionException(message: String) : IllegalStateException(message)

/**
 * Production implementations MUST verify the currently pinned M2 public identity,
 * matching established M3 contact, and a durable, consumed v2 signed consent proof.
 * This read-only check is not a network or media authorization.
 */
internal fun interface VoiceCallVerifiedPeerAdmission {
    fun requireApproved(ownerIdentityId: ByteArray, peerIdentityId: ByteArray)
}

internal class PinnedVoiceCallVerifiedPeerAdmission(
    private val guard: VoiceOutboundCapabilityGuard,
) : VoiceCallVerifiedPeerAdmission {
    override fun requireApproved(ownerIdentityId: ByteArray, peerIdentityId: ByteArray) {
        guard.requireEligiblePeer(ownerIdentityId.copyOf(), peerIdentityId.copyOf())
    }
}

/** Only the already-authenticated, durable M3/M4 voice event is eligible for a one-time claim. */
internal fun interface VoiceCallClaimedControlSource {
    fun claimControl(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        nowEpochSeconds: Long,
    ): VoiceSignalPlaintext?
}

/**
 * ICE remains UNCLAIMED here; only the call-control subset is handed to the reducer.
 * A later reviewed WebRTC adapter must own candidate ordering, quotas and claims.
 */
internal class MatcherVoiceCallClaimedControlSource(
    private val matcher: RestorableVoiceSignalMatcher,
) : VoiceCallClaimedControlSource {
    override fun claimControl(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        messageId: ByteArray,
        nowEpochSeconds: Long,
    ): VoiceSignalPlaintext? {
        val pendingControl = matcher.restorableCandidates(ownerIdentityId, nowEpochSeconds)
            .singleOrNull {
                MessageDigest.isEqual(it.senderIdentityId, peerIdentityId) &&
                    MessageDigest.isEqual(it.messageId, messageId)
            } ?: return null
        if (pendingControl.kind !in CONTROL_SIGNAL_KINDS) return null
        return matcher.claimRestorableCandidate(
            ownerIdentityId, peerIdentityId, messageId, nowEpochSeconds,
        )
    }
}

internal fun interface VoiceCallCoordinatorClock {
    fun nowEpochSeconds(): Long
}

/** A fresh 128-bit cryptographically random call id for every proposed dial. */
internal fun interface VoiceCallIdGenerator {
    fun newCallId(): ByteArray
}

private object SecureVoiceCallIdGenerator : VoiceCallIdGenerator {
    private val random = SecureRandom()
    override fun newCallId(): ByteArray =
        ByteArray(16).also(random::nextBytes)
}

/**
 * In-memory, non-UI call-control reducer admission adapter, NOT a call runtime.
 *
 * This coordinator never sends a packet, rings, accesses a microphone, creates media
 * tracks or executes effects. Returned effects are only *proposals*. A future owner
 * must revalidate pinned consent and the exact call key under the same serialized
 * M3/WSS lifecycle before committing each side effect, and must stage E2EE ciphertext
 * durably before transmitting it. State is volatile; no background/M6 behavior.
 *
 * The incoming source MUST verify durable M3/M4 semantic + replay provenance and
 * atomically consume its one-time effect claim before it returns an event.
 */
internal class VoiceCallAdmissionCoordinator(
    ownerIdentityId: ByteArray,
    private val approved: VoiceCallVerifiedPeerAdmission,
    private val inbound: VoiceCallClaimedControlSource,
    private val clock: VoiceCallCoordinatorClock =
        VoiceCallCoordinatorClock { Instant.now().epochSecond },
    private val callIds: VoiceCallIdGenerator = SecureVoiceCallIdGenerator,
) {
    private val owner = ownerIdentityId.copyOf().also {
        requireValidIdentity(it, "local voice call owner")
    }
    private val ownerEncoded = encode(owner)
    private var state = VoiceCallSnapshot()
    private val timeoutFence = VoiceCallMonotonicTimeoutFence()

    @Synchronized
    fun snapshot(): VoiceCallSnapshot = state.copy(
        retiredCallIds = state.retiredCallIds.toList(),
    )

    /** Only an explicit local user gesture may propose a new outgoing offer. */
    @Synchronized
    fun userDial(
        peerIdentityId: ByteArray,
        explicitUserApproval: Boolean,
    ): VoiceCallTransition {
        if (!explicitUserApproval) throw VoiceCallAdmissionException("User approval required to dial")
        requireValidIdentity(peerIdentityId, "outbound voice peer")
        if (MessageDigest.isEqual(owner, peerIdentityId)) {
            throw VoiceCallAdmissionException("Cannot call the local identity")
        }
        approved.requireApproved(owner.copyOf(), peerIdentityId.copyOf())
        if (state.phase != VoiceCallPhase.IDLE) {
            return VoiceCallTransition(state)
        }
        // Never let UI, network input or wall-clock time supply call-id entropy.
        val key = key(peerIdentityId, callIds.newCallId())
        return commit(VoiceCallReducer.apply(state, VoiceCallEvent(VoiceCallEventKind.LOCAL_DIAL, key)))
    }

    /** Incoming control can only originate from a durable one-time semantic claim. */
    @Synchronized
    fun receiveClaimedControl(
        peerIdentityId: ByteArray,
        messageId: ByteArray,
    ): VoiceCallTransition? {
        requireValidIdentity(peerIdentityId, "voice signaling peer")
        if (MessageDigest.isEqual(owner, peerIdentityId) ||
            messageId.size != 16 || messageId.all { it == 0.toByte() }
        ) {
            throw VoiceCallAdmissionException("Voice signaling peer/message key invalid")
        }
        val now = clock.nowEpochSeconds()
        if (now <= 0L) throw VoiceCallAdmissionException("Voice event clock invalid")
        approved.requireApproved(owner.copyOf(), peerIdentityId.copyOf())
        val signal = inbound.claimControl(
            owner.copyOf(), peerIdentityId.copyOf(), messageId.copyOf(), now,
        ) ?: return null
        if (!MessageDigest.isEqual(signal.senderIdentityId, peerIdentityId) ||
            !MessageDigest.isEqual(signal.recipientIdentityId, owner) ||
            !MessageDigest.isEqual(signal.messageId, messageId) ||
            signal.expiresAtEpochSeconds <= now ||
            signal.kind !in CONTROL_SIGNAL_KINDS ||
            signal.applicationProtocolVersion != 2
        ) {
            throw VoiceCallAdmissionException("Claimed M5 voice signal has invalid authenticated context")
        }
        val callKey = key(peerIdentityId, signal.callId)
        // The local signed consent may have been revoked while the durable claim was written.
        approved.requireApproved(owner.copyOf(), peerIdentityId.copyOf())
        val transition = when (signal.kind) {
            VoiceSignalKind.OFFER -> VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(
                ownerEncoded, state, callKey,
            )
            VoiceSignalKind.ANSWER -> VoiceCallReducer.apply(
                state, VoiceCallEvent(VoiceCallEventKind.REMOTE_ACCEPT, callKey),
            )
            VoiceSignalKind.REJECT, VoiceSignalKind.BUSY -> VoiceCallReducer.apply(
                state, VoiceCallEvent(VoiceCallEventKind.REMOTE_REJECT, callKey),
            )
            VoiceSignalKind.HANGUP -> VoiceCallReducer.apply(
                state, VoiceCallEvent(VoiceCallEventKind.REMOTE_HANGUP, callKey),
            )
            else -> throw VoiceCallAdmissionException("Unreviewed media event cannot control calls")
        }
        return commit(transition)
    }

    /**
     * Local accept requires a fresh user gesture and current pinned consent.
     * Rejection/hangup remain possible *locally* after a peer's consent is
     * revoked; the future effect runner must independently enforce this boundary.
     */
    @Synchronized
    fun userAction(
        kind: VoiceCallEventKind,
        key: VoiceCallKey,
        explicitUserApproval: Boolean = false,
    ): VoiceCallTransition {
        if (kind !in setOf(
                VoiceCallEventKind.LOCAL_ACCEPT,
                VoiceCallEventKind.LOCAL_REJECT,
                VoiceCallEventKind.LOCAL_HANGUP,
            )
        ) throw VoiceCallAdmissionException("Network/media event supplied through user action")
        if (kind == VoiceCallEventKind.LOCAL_ACCEPT) {
            if (!explicitUserApproval) throw VoiceCallAdmissionException("User approval required to accept")
            approved.requireApproved(owner.copyOf(), decode(key.peerIdentityId))
        } else if (key == state.active) {
            // Hangup/reject still work locally when trust is revoked, but must not
            // propose another encrypted signal to a no-longer-approved contact.
            val revalidated = revalidateActiveCall()
            if (revalidated.next.phase == VoiceCallPhase.IDLE) return revalidated
        }
        return commit(VoiceCallReducer.apply(state, VoiceCallEvent(kind, key)))
    }

    /**
     * A changed M2 pin, revoked v2 consent or inaccessible Keystore state must
     * retire the current call before another effect is executed. Do not send
     * even a teardown signal to an identity that is no longer approved.
     * The future media owner must execute STOP_MEDIA locally and atomically
     * correlate it with the returned call key.
     */
    @Synchronized
    fun revalidateActiveCall(): VoiceCallTransition {
        val active = state.active ?: return VoiceCallTransition(state)
        return try {
            approved.requireApproved(owner.copyOf(), decode(active.peerIdentityId))
            VoiceCallTransition(state)
        } catch (_: Exception) {
            val stopped = VoiceCallReducer.apply(
                state, VoiceCallEvent(VoiceCallEventKind.LOCAL_HANGUP, active),
            )
            commit(stopped.copy(
                effects = stopped.effects.filter { it.kind == VoiceCallEffectKind.STOP_MEDIA },
            ))
        }
    }

    /**
     * Only genuine asynchronous media callbacks are accepted here.
     * Timeouts MUST enter through [timeoutCallback] with their exact issued ticket.
     */
    @Synchronized
    fun callback(kind: VoiceCallEventKind, key: VoiceCallKey): VoiceCallTransition {
        if (kind !in setOf(
                VoiceCallEventKind.MEDIA_CONNECTED,
                VoiceCallEventKind.MEDIA_FAILED,
            )
        ) throw VoiceCallAdmissionException("Unclaimed timeout/network event supplied through callback")
        return admitLocalCallback(kind, key)
    }

    /**
     * The coordinator owns exactly one timeout fence, never a caller-supplied
     * fence. The future runtime must serialize timers and effect execution with
     * this authenticated owner; no scheduling or media is performed here.
     */
    @Synchronized
    fun issueTimeout(nowElapsedMillis: Long, delayMillis: Long): VoiceCallMonotonicTimeoutFence.Ticket =
        timeoutFence.issue(state, nowElapsedMillis, delayMillis)

    /** Lifecycle close/revocation may proactively invalidate outstanding timers. */
    @Synchronized
    fun cancelTimeout() {
        timeoutFence.cancel()
    }

    /** Only the exact unexpired ticket issued by THIS coordinator may fire. */
    @Synchronized
    fun timeoutCallback(
        ticket: VoiceCallMonotonicTimeoutFence.Ticket,
        nowElapsedMillis: Long,
    ): VoiceCallTransition {
        val accepted = timeoutFence.consume(ticket, state, nowElapsedMillis)
            ?: return VoiceCallTransition(state)
        return admitLocalCallback(accepted.kind, accepted.key)
    }

    /** Invoked only under the synchronized coordinator admission monitor. */
    private fun admitLocalCallback(kind: VoiceCallEventKind, key: VoiceCallKey): VoiceCallTransition {
        if (key == state.active) {
            // Revoked trust permits local STOP_MEDIA but never outbound teardown.
            val revalidated = revalidateActiveCall()
            if (revalidated.next.phase == VoiceCallPhase.IDLE) return revalidated
        }
        return commit(VoiceCallReducer.apply(state, VoiceCallEvent(kind, key)))
    }

    private fun commit(transition: VoiceCallTransition): VoiceCallTransition {
        if (state.active != transition.next.active || state.phase != transition.next.phase) {
            // Phase or owner changes invalidate old async timeout callbacks.
            timeoutFence.cancel()
        }
        state = transition.next
        return transition
    }

    private fun key(peerIdentityId: ByteArray, callId: ByteArray): VoiceCallKey {
        requireValidIdentity(peerIdentityId, "voice call peer")
        if (MessageDigest.isEqual(owner, peerIdentityId) ||
            callId.size != 16 || callId.all { it == 0.toByte() }
        ) throw VoiceCallAdmissionException("Voice call peer or id invalid")
        return VoiceCallKey(encode(callId), encode(peerIdentityId))
    }

    private fun decode(value: String): ByteArray = try {
        Base64.getUrlDecoder().decode(value)
    } catch (_: IllegalArgumentException) {
        throw VoiceCallAdmissionException("Invalid voice call key")
    }

    private fun requireValidIdentity(value: ByteArray, name: String) {
        if (value.size != 32 || value.all { it == 0.toByte() }) {
            throw VoiceCallAdmissionException("$name invalid")
        }
    }

    private fun encode(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)
}

private val CONTROL_SIGNAL_KINDS = setOf(
    VoiceSignalKind.OFFER,
    VoiceSignalKind.ANSWER,
    VoiceSignalKind.REJECT,
    VoiceSignalKind.BUSY,
    VoiceSignalKind.HANGUP,
)
