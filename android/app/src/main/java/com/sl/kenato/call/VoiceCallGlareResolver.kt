package com.sl.kenato.call

import java.util.Base64

/**
 * Simultaneous outbound offers need a single winner. The lexicographically lower
 * raw pinned identity keeps its locally generated outgoing call identifier.
 * The other peer retires its outgoing call and displays the winning incoming call.
 *
 * Caller MUST authenticate the incoming offer via M3 and exact M4 envelope binding
 * before invoking this function. A local identity id is never learned from the relay.
 * This resolver does not send packets or start media on its own.
 */
internal object VoiceCallGlareResolver {
    fun resolveAuthenticatedIncomingOffer(
        localIdentityId: String,
        state: VoiceCallSnapshot,
        incoming: VoiceCallKey,
    ): VoiceCallTransition {
        val local = decodeIdentity(localIdentityId)
        val peer = decodeIdentity(incoming.peerIdentityId)
        if (local.contentEquals(peer)) {
            throw IllegalArgumentException("Glare peer must not be the local identity")
        }
        val active = state.active
        if (state.phase != VoiceCallPhase.OUTGOING_RINGING ||
            active == null ||
            active.peerIdentityId != incoming.peerIdentityId ||
            active.callId == incoming.callId ||
            incoming.callId in state.retiredCallIds
        ) {
            return VoiceCallReducer.apply(state, VoiceCallEvent(VoiceCallEventKind.INCOMING_OFFER, incoming))
        }

        // Compare unsigned raw 32-byte identities, never localized/display names.
        val lowerLocal = (0 until local.size).firstOrNull { local[it] != peer[it] }?.let {
            (local[it].toInt() and 255) < (peer[it].toInt() and 255)
        } ?: throw IllegalArgumentException("Glare identity comparison is invalid")

        if (lowerLocal) {
            // Winning caller retains its outgoing offer and declines the peer's losing offer.
            return VoiceCallReducer.apply(state, VoiceCallEvent(VoiceCallEventKind.INCOMING_OFFER, incoming))
        }

        // Losing caller retires the exact old key, preserving idempotent late-event rejection.
        // LOCAL_HANGUP produces SEND_HANGUP but no STOP_MEDIA while still ringing.
        val closed = VoiceCallReducer.apply(state, VoiceCallEvent(VoiceCallEventKind.LOCAL_HANGUP, active))
        check(closed.next.phase == VoiceCallPhase.IDLE)
        return VoiceCallTransition(
            closed.next.copy(
                phase = VoiceCallPhase.INCOMING_RINGING,
                active = incoming,
                direction = VoiceCallDirection.INCOMING,
            ),
            closed.effects,
        )
    }

    private fun decodeIdentity(encoded: String): ByteArray {
        if (encoded.length != 43 || !encoded.all {
            it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '_' || it == '-'
        }) {
            throw IllegalArgumentException("Glare identity encoding is invalid")
        }
        val value = try {
            Base64.getUrlDecoder().decode(encoded)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Glare identity encoding is invalid")
        }
        if (value.size != 32 || value.all { it == 0.toByte() } ||
            Base64.getUrlEncoder().withoutPadding().encodeToString(value) != encoded
        ) {
            throw IllegalArgumentException("Glare identity is invalid")
        }
        return value
    }
}
