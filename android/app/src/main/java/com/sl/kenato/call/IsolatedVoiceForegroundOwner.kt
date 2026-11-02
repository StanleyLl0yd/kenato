package com.sl.kenato.call

/**
 * Process-local M5 research owner. The only inbound control source is the
 * independently authenticated + KDL1-protected, consent-revalidated adapter.
 * This construction path has NO checksum-only legacy fallback.
 *
 * This class is NOT the durable M2/M3/WSS/effect owner: no Android factory
 * constructs it, it does not hold locks used by M2 consent mutations or M3
 * ratchet/WSS writes, and it never runs effects, media, microphone or network.
 */
internal class IsolatedVoiceForegroundOwner(
    ownerIdentityId: ByteArray,
    private val approved: VoiceCallVerifiedPeerAdmission,
    matcher: RestorableVoiceSignalMatcher,
    continuity: VoiceDispatchContinuityLedger,
    clock: VoiceCallCoordinatorClock,
) : AutoCloseable {
    private val identity = ownerIdentityId.copyOf()
    private val coordinator = VoiceCallAdmissionCoordinator(
        identity,
        approved,
        EpochGuardedVoiceCallClaimedControlSource(matcher, continuity, approved, clock),
        clock,
    )
    private val proposals = VoiceEffectClaimGate()
    private var closed = false

    /** Tickets are proposals, never permission to execute a native/network effect. */
    internal class Result internal constructor(
        val snapshot: VoiceCallSnapshot,
        val tickets: List<VoiceEffectClaimGate.Ticket>,
    )

    @Synchronized
    fun snapshot(): VoiceCallSnapshot {
        requireOpen()
        return coordinator.snapshot()
    }

    @Synchronized
    fun receiveControl(peerIdentityId: ByteArray, messageId: ByteArray): Result? {
        requireOpen()
        return try {
            coordinator.receiveClaimedControl(peerIdentityId.copyOf(), messageId.copyOf())
                ?.let(::register)
        } catch (error: Exception) {
            proposals.cancel()
            throw error
        }
    }

    @Synchronized
    fun userDial(peerIdentityId: ByteArray, explicitUserApproval: Boolean): Result =
        registerSafely { coordinator.userDial(peerIdentityId.copyOf(), explicitUserApproval) }

    @Synchronized
    fun userAction(
        kind: VoiceCallEventKind,
        key: VoiceCallKey,
        explicitUserApproval: Boolean = false,
    ): Result = registerSafely { coordinator.userAction(kind, key, explicitUserApproval) }

    @Synchronized
    fun mediaCallback(kind: VoiceCallEventKind, key: VoiceCallKey): Result =
        registerSafely { coordinator.callback(kind, key) }

    @Synchronized
    fun revalidateActiveCall(): Result =
        registerSafely { coordinator.revalidateActiveCall() }

    @Synchronized
    fun issueTimeout(nowElapsedMillis: Long, delayMillis: Long):
        VoiceCallMonotonicTimeoutFence.Ticket {
        requireOpen()
        return coordinator.issueTimeout(nowElapsedMillis, delayMillis)
    }

    @Synchronized
    fun timeoutCallback(
        ticket: VoiceCallMonotonicTimeoutFence.Ticket,
        nowElapsedMillis: Long,
    ): Result = registerSafely { coordinator.timeoutCallback(ticket, nowElapsedMillis) }

    /**
     * One-time in-memory *proposal* claim. The future runtime MUST execute its
     * effect under the SAME durable owner, revalidate M2/v2 consent and M3/WSS
     * staging, and use an exact peer+call-keyed native media handle. Returning
     * this result outside a real owner is NOT executable authorization.
     */
    @Synchronized
    fun claimProposal(ticket: VoiceEffectClaimGate.Ticket): VoiceCallEffect? {
        requireOpen()
        return proposals.claim(ticket, coordinator.snapshot(), approved, identity.copyOf())
    }

    /** Invalidate all pending in-memory tickets and timeout callbacks. */
    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        proposals.cancel()
        coordinator.cancelTimeout()
    }

    private fun registerSafely(change: () -> VoiceCallTransition): Result {
        requireOpen()
        return try {
            register(change())
        } catch (error: Exception) {
            proposals.cancel()
            throw error
        }
    }

    private fun register(change: VoiceCallTransition): Result {
        if (coordinator.snapshot() != change.next) {
            proposals.cancel()
            throw VoiceCallAdmissionException("Voice owner transition and committed reducer state differ")
        }
        return Result(change.next.copy(retiredCallIds = change.next.retiredCallIds.toList()),
            proposals.replace(change))
    }

    private fun requireOpen() {
        if (closed) throw VoiceCallAdmissionException("Voice foreground owner is closed")
    }
}
