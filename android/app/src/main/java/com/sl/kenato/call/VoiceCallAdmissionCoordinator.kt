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
     * Rejection/hangup remain possible even after a peer's consent is revoked.
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
        }
        return commit(VoiceCallReducer.apply(state, VoiceCallEvent(kind, key)))
    }

    /** All asynchronous media/timeouts must carry the originally admitted exact call key. */
    @Synchronized
    fun callback(kind: VoiceCallEventKind, key: VoiceCallKey): VoiceCallTransition {
        if (kind !in setOf(
                VoiceCallEventKind.MEDIA_CONNECTED,
                VoiceCallEventKind.MEDIA_FAILED,
                VoiceCallEventKind.RING_TIMEOUT,
                VoiceCallEventKind.CONNECT_TIMEOUT,
            )
        ) throw VoiceCallAdmissionException("Unclaimed network event supplied through callback")
        if (kind == VoiceCallEventKind.MEDIA_CONNECTED && key == state.active) {
            approved.requireApproved(owner.copyOf(), decode(key.peerIdentityId))
        }
        return commit(VoiceCallReducer.apply(state, VoiceCallEvent(kind, key)))
    }

    private fun commit(transition: VoiceCallTransition): VoiceCallTransition {
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
