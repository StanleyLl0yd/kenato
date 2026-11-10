package com.sl.kenato.call

import java.util.Base64

/**
 * Process-local, one-use **proposal claim**, not a network/media effect runner.
 *
 * The future runtime must call [replace] after committing the coordinator's
 * transition, and [claim] under the SAME serialized owner that protects M2
 * consent, the M3 durable stage, WSS send admission and the native media owner.
 * This object does not itself establish that cross-component lock or durable
 * transaction. No production call site invokes it.
 *
 * A claim does NOT authorize a plaintext send, bypass E2EE, grant microphone
 * access or start WebRTC. The consumer must use the exact correlated call key,
 * stage signed/verified signaling durably, revalidate consent at the actual
 * commit point and separately gate media permission.
 */
internal class VoiceEffectClaimGate {
    internal class Ticket internal constructor(
        val key: VoiceCallKey,
        val kind: VoiceCallEffectKind,
        internal val generation: Long,
        internal val ordinal: Int,
    )

    private var generation = 0L
    private var expected = VoiceCallSnapshot()
    private var outstanding = emptyList<Ticket>()
    private val claimed = HashSet<Int>()

    /**
     * Cancel EVERY previous ticket, including tickets for a terminalized call.
     * Only the owner that committed [transition] may register it.
     */
    @Synchronized
    fun replace(transition: VoiceCallTransition): List<Ticket> {
        if (generation == Long.MAX_VALUE) {
            throw IllegalStateException("Voice effect generation exhausted")
        }
        // Fail closed on rejected registration too: an old proposal must
        // never survive a newer committed transition with invalid effects.
        generation++
        outstanding = emptyList()
        claimed.clear()
        require(transition.effects.size <= MAX_EFFECTS_PER_TRANSITION) {
            "Too many voice effect proposals"
        }
        require(transition.effects.all { effectMatchesSnapshot(it, transition.next) }) {
            "Voice effect key or phase conflicts with committed snapshot"
        }
        expected = transition.next.copy(retiredCallIds = transition.next.retiredCallIds.toList())
        outstanding = transition.effects.mapIndexed { index, effect ->
            Ticket(effect.key, effect.kind, generation, index)
        }
        return outstanding.toList()
    }

    /**
     * Claims a proposal at most once, with identity-based ticket validation.
     * Revoked/invalid consent consumes the proposal fail-closed. STOP_MEDIA is
     * deliberately local-only and still claimable after revocation; it MUST
     * be executed on the exact keyed media owner, never an arbitrary track.
     *
     * [live] and [permission] must be supplied under the future common
     * lifecycle lock. Passing a stale snapshot or a non-atomic callback is
     * NOT production authorization.
     */
    @Synchronized
    fun claim(
        ticket: Ticket,
        live: VoiceCallSnapshot,
        permission: VoiceCallVerifiedPeerAdmission,
        ownerIdentityId: ByteArray,
    ): VoiceCallEffect? {
        val issued = outstanding.getOrNull(ticket.ordinal) ?: return null
        if (issued !== ticket || ticket.generation != generation ||
            claimed.contains(ticket.ordinal)
        ) {
            return null
        }
        // Even a single observed mismatch is fail-closed. Never make the
        // same ticket usable again if a later snapshot happens to match.
        claimed.add(ticket.ordinal)
        if (live != expected) return null

        if (ticket.kind != VoiceCallEffectKind.STOP_MEDIA) {
            // No external side effects. A rejected Keystore/pin/consent check
            // cannot be retried using the already-consumed ticket.
            val peer = Base64.getUrlDecoder().decode(ticket.key.peerIdentityId)
            try {
                permission.requireApproved(ownerIdentityId.copyOf(), peer)
            } catch (_: Exception) {
                return null
            }
        }
        return VoiceCallEffect(ticket.kind, ticket.key)
    }

    /** Shutdown/owner replacement invalidates outstanding in-memory claims. */
    @Synchronized
    fun cancel() {
        if (generation == Long.MAX_VALUE) {
            // Exhaustion is already a terminal fail-closed state.
            outstanding = emptyList()
            claimed.clear()
            return
        }
        generation++
        outstanding = emptyList()
        claimed.clear()
    }

    // Only the most recently retired call may generate terminal effects.
    // Terminal snapshots do not retain peers: STOP_MEDIA still needs exact
    // peer+call-key correlation at the future native media owner.
    private fun effectMatchesSnapshot(
        effect: VoiceCallEffect,
        next: VoiceCallSnapshot,
    ): Boolean = when (effect.kind) {
        VoiceCallEffectKind.SEND_OFFER ->
            next.phase == VoiceCallPhase.OUTGOING_RINGING &&
                next.direction == VoiceCallDirection.OUTGOING && next.active == effect.key
        VoiceCallEffectKind.SEND_ACCEPT ->
            next.phase == VoiceCallPhase.CONNECTING &&
                next.direction == VoiceCallDirection.INCOMING && next.active == effect.key
        VoiceCallEffectKind.START_MEDIA ->
            next.phase == VoiceCallPhase.CONNECTING && next.active == effect.key
        VoiceCallEffectKind.SEND_BUSY ->
            next.active != null && next.active != effect.key &&
                next.active.callId != effect.key.callId &&
                effect.key.callId !in next.retiredCallIds
        VoiceCallEffectKind.SEND_REJECT,
        VoiceCallEffectKind.STOP_MEDIA ->
            next.phase == VoiceCallPhase.IDLE &&
                effect.key.callId == next.retiredCallIds.lastOrNull()
        VoiceCallEffectKind.SEND_HANGUP ->
            (next.phase == VoiceCallPhase.IDLE &&
                effect.key.callId == next.retiredCallIds.lastOrNull()) ||
                // The losing side of simultaneous outbound glare must retire
                // its old outgoing ID while switching to the winning incoming
                // ID from the SAME peer. Never hang up the new incoming call.
                (next.phase == VoiceCallPhase.INCOMING_RINGING &&
                    next.direction == VoiceCallDirection.INCOMING &&
                    next.active != null &&
                    next.active.peerIdentityId == effect.key.peerIdentityId &&
                    next.active.callId != effect.key.callId &&
                    effect.key.callId == next.retiredCallIds.lastOrNull())
    }

    private companion object {
        const val MAX_EFFECTS_PER_TRANSITION = 2
    }
}
