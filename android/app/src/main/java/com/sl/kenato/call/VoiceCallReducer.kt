package com.sl.kenato.call

import java.util.Base64

/**
 * An authenticated, pinned peer plus a fresh 128-bit call identifier.
 * This is local call-control state, not a wire format or a source of peer trust.
 */
internal data class VoiceCallKey(
    val callId: String,
    val peerIdentityId: String,
) {
    init {
        requireCanonicalBase64Url(callId, CALL_ID_BYTES)
        requireCanonicalBase64Url(peerIdentityId, IDENTITY_ID_BYTES)
    }
}

internal enum class VoiceCallPhase {
    IDLE,
    OUTGOING_RINGING,
    INCOMING_RINGING,
    CONNECTING,
    ACTIVE,
}

internal enum class VoiceCallDirection { OUTGOING, INCOMING }

/** Caller-owned timeout events are explicitly correlated to a call key and phase. */
internal enum class VoiceCallEventKind {
    LOCAL_DIAL,
    INCOMING_OFFER,
    REMOTE_ACCEPT,
    REMOTE_REJECT,
    REMOTE_HANGUP,
    LOCAL_ACCEPT,
    LOCAL_REJECT,
    LOCAL_HANGUP,
    MEDIA_CONNECTED,
    MEDIA_FAILED,
    RING_TIMEOUT,
    CONNECT_TIMEOUT,
}

internal data class VoiceCallEvent(
    val kind: VoiceCallEventKind,
    val key: VoiceCallKey,
)

internal enum class VoiceCallEffectKind {
    SEND_OFFER,
    SEND_ACCEPT,
    SEND_REJECT,
    SEND_BUSY,
    SEND_HANGUP,
    START_MEDIA,
    STOP_MEDIA,
}

internal data class VoiceCallEffect(
    val kind: VoiceCallEffectKind,
    val key: VoiceCallKey,
)

/**
 * Exactly one active call. Completed call IDs form a bounded best-effort replay guard.
 * The eventual encrypted signaling decoder must independently verify freshness,
 * identity binding, nonce uniqueness and maximum message size.
 */
internal data class VoiceCallSnapshot(
    val phase: VoiceCallPhase = VoiceCallPhase.IDLE,
    val active: VoiceCallKey? = null,
    val direction: VoiceCallDirection? = null,
    val retiredCallIds: List<String> = emptyList(),
) {
    init {
        require(
            if (phase == VoiceCallPhase.IDLE) active == null && direction == null
            else active != null && direction != null
        )
        require(retiredCallIds.size <= RETIRED_CALL_LIMIT)
        require(retiredCallIds.size == retiredCallIds.distinct().size)
        require(active == null || active.callId !in retiredCallIds)
        when (phase) {
            VoiceCallPhase.OUTGOING_RINGING -> require(direction == VoiceCallDirection.OUTGOING)
            VoiceCallPhase.INCOMING_RINGING -> require(direction == VoiceCallDirection.INCOMING)
            else -> Unit
        }
    }
}

internal data class VoiceCallTransition(
    val next: VoiceCallSnapshot,
    val effects: List<VoiceCallEffect> = emptyList(),
)

/**
 * Pure deterministic state machine. Network, audio, timers, UI and cryptographic
 * verification are external and must not run from this reducer.
 */
internal object VoiceCallReducer {
    fun apply(state: VoiceCallSnapshot, event: VoiceCallEvent): VoiceCallTransition {
        val active = state.active
        val kind = event.kind
        val key = event.key

        if (state.phase == VoiceCallPhase.IDLE) {
            if (key.callId in state.retiredCallIds) return VoiceCallTransition(state)
            return when (kind) {
                VoiceCallEventKind.LOCAL_DIAL -> VoiceCallTransition(
                    state.copy(phase = VoiceCallPhase.OUTGOING_RINGING, active = key, direction = VoiceCallDirection.OUTGOING),
                    listOf(VoiceCallEffect(VoiceCallEffectKind.SEND_OFFER, key)),
                )
                VoiceCallEventKind.INCOMING_OFFER -> VoiceCallTransition(
                    state.copy(phase = VoiceCallPhase.INCOMING_RINGING, active = key, direction = VoiceCallDirection.INCOMING),
                )
                else -> VoiceCallTransition(state)
            }
        }

        if (kind == VoiceCallEventKind.INCOMING_OFFER && key != active) {
            // A reused call id with a different peer is not a separate busy call.
            if (key.callId == active?.callId || key.callId in state.retiredCallIds) {
                return VoiceCallTransition(state)
            }
            return VoiceCallTransition(state, listOf(VoiceCallEffect(VoiceCallEffectKind.SEND_BUSY, key)))
        }
        // Stale network frames, UI operations and timeout callbacks must not act on another call.
        if (key != active) return VoiceCallTransition(state)

        return when (kind) {
            VoiceCallEventKind.REMOTE_ACCEPT ->
                if (state.phase == VoiceCallPhase.OUTGOING_RINGING) VoiceCallTransition(
                    state.copy(phase = VoiceCallPhase.CONNECTING),
                    listOf(VoiceCallEffect(VoiceCallEffectKind.START_MEDIA, key)),
                ) else VoiceCallTransition(state)

            VoiceCallEventKind.LOCAL_ACCEPT ->
                if (state.phase == VoiceCallPhase.INCOMING_RINGING) VoiceCallTransition(
                    state.copy(phase = VoiceCallPhase.CONNECTING),
                    listOf(
                        VoiceCallEffect(VoiceCallEffectKind.SEND_ACCEPT, key),
                        VoiceCallEffect(VoiceCallEffectKind.START_MEDIA, key),
                    ),
                ) else VoiceCallTransition(state)

            VoiceCallEventKind.MEDIA_CONNECTED ->
                if (state.phase == VoiceCallPhase.CONNECTING) VoiceCallTransition(state.copy(phase = VoiceCallPhase.ACTIVE))
                else VoiceCallTransition(state)

            VoiceCallEventKind.REMOTE_REJECT ->
                if (state.phase == VoiceCallPhase.OUTGOING_RINGING) finish(state)
                else VoiceCallTransition(state)

            VoiceCallEventKind.REMOTE_HANGUP -> finish(state)

            VoiceCallEventKind.LOCAL_REJECT ->
                if (state.phase == VoiceCallPhase.INCOMING_RINGING) finish(state, VoiceCallEffectKind.SEND_REJECT)
                else VoiceCallTransition(state)

            VoiceCallEventKind.LOCAL_HANGUP -> {
                val signal = if (state.phase == VoiceCallPhase.INCOMING_RINGING) {
                    VoiceCallEffectKind.SEND_REJECT
                } else {
                    VoiceCallEffectKind.SEND_HANGUP
                }
                finish(state, signal)
            }

            VoiceCallEventKind.MEDIA_FAILED ->
                if (state.phase == VoiceCallPhase.CONNECTING || state.phase == VoiceCallPhase.ACTIVE) {
                    finish(state, VoiceCallEffectKind.SEND_HANGUP)
                } else VoiceCallTransition(state)

            VoiceCallEventKind.RING_TIMEOUT ->
                if (state.phase == VoiceCallPhase.OUTGOING_RINGING) {
                    finish(state, VoiceCallEffectKind.SEND_HANGUP)
                } else if (state.phase == VoiceCallPhase.INCOMING_RINGING) {
                    finish(state, VoiceCallEffectKind.SEND_REJECT)
                } else VoiceCallTransition(state)

            VoiceCallEventKind.CONNECT_TIMEOUT ->
                if (state.phase == VoiceCallPhase.CONNECTING) finish(state, VoiceCallEffectKind.SEND_HANGUP)
                else VoiceCallTransition(state)

            VoiceCallEventKind.LOCAL_DIAL,
            VoiceCallEventKind.INCOMING_OFFER,
            -> VoiceCallTransition(state)
        }
    }

    private fun finish(state: VoiceCallSnapshot, signal: VoiceCallEffectKind? = null): VoiceCallTransition {
        val key = requireNotNull(state.active)
        val effects = buildList {
            if (signal != null) add(VoiceCallEffect(signal, key))
            if (state.phase == VoiceCallPhase.CONNECTING || state.phase == VoiceCallPhase.ACTIVE) {
                add(VoiceCallEffect(VoiceCallEffectKind.STOP_MEDIA, key))
            }
        }
        return VoiceCallTransition(
            VoiceCallSnapshot(
                retiredCallIds = (state.retiredCallIds + key.callId).takeLast(RETIRED_CALL_LIMIT),
            ),
            effects,
        )
    }
}

private const val CALL_ID_BYTES = 16
private const val IDENTITY_ID_BYTES = 32
private const val RETIRED_CALL_LIMIT = 64
private val BASE64_URL = Regex("^[A-Za-z0-9_-]+$")

private fun requireCanonicalBase64Url(encoded: String, expectedBytes: Int) {
    // Reject unbounded caller input before regex matching or base64 decoding.
    require(encoded.length == (expectedBytes * 8 + 5) / 6 && BASE64_URL.matches(encoded))
    val bytes = try {
        Base64.getUrlDecoder().decode(encoded)
    } catch (_: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid call identifier encoding")
    }
    require(bytes.size == expectedBytes && bytes.any { it != 0.toByte() })
    require(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == encoded)
}
