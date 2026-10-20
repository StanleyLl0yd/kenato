package com.sl.kenato.call

/**
 * One-shot, in-process deadline gate for a future serialized M5 call runtime.
 *
 * No Android AlarmManager, background thread, network or reducer side effects.
 * A caller may ask whether an already-fired timer belongs to the exact
 * current call key/phase and only then pass the returned event to the
 * VoiceCallAdmissionCoordinator. A caller MUST still serialize that handoff
 * with its real admission lifecycle and revalidate current consent there.
 */
internal class VoiceCallMonotonicTimeoutFence {
    private var generation = 0L
    private var pending: Ticket? = null

    internal data class Ticket(
        val key: VoiceCallKey,
        val phase: VoiceCallPhase,
        val generation: Long,
        val deadlineElapsedMillis: Long,
    )

    /** Only live ringing/connecting states can create timer tickets. */
    @Synchronized
    fun issue(
        snapshot: VoiceCallSnapshot,
        nowElapsedMillis: Long,
        delayMillis: Long,
    ): Ticket {
        require(nowElapsedMillis >= 0L) { "Monotonic clock invalid" }
        require(delayMillis in 1L..MAX_TIMEOUT_MILLIS) { "Call timeout outside bounded range" }
        require(snapshot.phase in TIMEOUT_PHASES) { "No timeout for idle/active call" }
        val key = requireNotNull(snapshot.active)
        if (generation == Long.MAX_VALUE) {
            throw IllegalStateException("Call timeout epoch exhausted")
        }
        val deadline = try {
            Math.addExact(nowElapsedMillis, delayMillis)
        } catch (_: ArithmeticException) {
            throw IllegalArgumentException("Call timeout deadline overflow")
        }
        val ticket = Ticket(key, snapshot.phase, ++generation, deadline)
        pending = ticket
        return ticket
    }

    /**
     * Reject early, duplicate, superseded, wrong-peer/call and wrong-phase
     * callbacks. This is a proposal of an event only, never execution.
     */
    @Synchronized
    fun consume(
        ticket: Ticket,
        snapshot: VoiceCallSnapshot,
        nowElapsedMillis: Long,
    ): VoiceCallEvent? {
        if (nowElapsedMillis < 0L ||
            ticket != pending ||
            snapshot.phase != ticket.phase ||
            snapshot.active != ticket.key ||
            nowElapsedMillis < ticket.deadlineElapsedMillis
        ) {
            return null
        }
        pending = null
        return when (ticket.phase) {
            VoiceCallPhase.OUTGOING_RINGING, VoiceCallPhase.INCOMING_RINGING ->
                VoiceCallEvent(VoiceCallEventKind.RING_TIMEOUT, ticket.key)
            VoiceCallPhase.CONNECTING ->
                VoiceCallEvent(VoiceCallEventKind.CONNECT_TIMEOUT, ticket.key)
            else -> null
        }
    }

    /** Revocation, hangup, process owner replacement and close invalidate tickets. */
    @Synchronized
    fun cancel() {
        pending = null
    }

    private companion object {
        private const val MAX_TIMEOUT_MILLIS = 120_000L
        private val TIMEOUT_PHASES = setOf(
            VoiceCallPhase.OUTGOING_RINGING,
            VoiceCallPhase.INCOMING_RINGING,
            VoiceCallPhase.CONNECTING,
        )
    }
}
