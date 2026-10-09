package com.sl.kenato.call

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class VoiceCallGlareResolverTest {
    @Test
    fun lowerIdentityRetainsOutgoingCallAndRepliesBusyToLosingOffer() {
        val call = outgoing(HIGHER)
        val incoming = VoiceCallKey(id(12), HIGHER)
        val result = VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(LOWER, call, incoming)
        assertEquals(call, result.next)
        assertEquals(listOf(VoiceCallEffectKind.SEND_BUSY), result.effects.map { it.kind })
        assertEquals(incoming, result.effects.single().key)
    }

    @Test
    fun higherIdentitySwitchesToWinningIncomingCallWithoutStartingMedia() {
        val outgoing = outgoing(LOWER)
        val old = requireNotNull(outgoing.active)
        val newCall = VoiceCallKey(id(12), LOWER)
        val switched = VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(HIGHER, outgoing, newCall)
        assertEquals(VoiceCallPhase.INCOMING_RINGING, switched.next.phase)
        assertEquals(VoiceCallDirection.INCOMING, switched.next.direction)
        assertEquals(newCall, switched.next.active)
        assertEquals(listOf(old.callId), switched.next.retiredCallIds)
        assertEquals(listOf(VoiceCallEffectKind.SEND_HANGUP), switched.effects.map { it.kind })
        assertEquals(old, switched.effects.single().key)
        assertTrue(
            VoiceCallReducer.apply(
                switched.next,
                VoiceCallEvent(VoiceCallEventKind.REMOTE_ACCEPT, old),
            ).effects.isEmpty(),
        )
        val accepted = VoiceCallReducer.apply(
            switched.next,
            VoiceCallEvent(VoiceCallEventKind.LOCAL_ACCEPT, newCall),
        )
        assertEquals(VoiceCallPhase.CONNECTING, accepted.next.phase)
        assertEquals(
            listOf(VoiceCallEffectKind.SEND_ACCEPT, VoiceCallEffectKind.START_MEDIA),
            accepted.effects.map { it.kind },
        )
    }

    @Test
    fun repeatedWinningOfferNeverStartsSecondCallOrRetiresAnother() {
        val outbound = outgoing(LOWER)
        val incoming = VoiceCallKey(id(12), LOWER)
        val first = VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(HIGHER, outbound, incoming)
        val second = VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(HIGHER, first.next, incoming)
        assertEquals(first.next, second.next)
        assertTrue(second.effects.isEmpty())
    }

    @Test
    fun wrongPeerOldCallIdAndUnrelatedStatesNeverTriggerGlareSwap() {
        val outgoing = outgoing(LOWER)
        val other = VoiceCallKey(id(12), THIRD)
        val differentPeer = VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(HIGHER, outgoing, other)
        assertEquals(outgoing, differentPeer.next)
        assertEquals(listOf(VoiceCallEffectKind.SEND_BUSY), differentPeer.effects.map { it.kind })

        val sameCallId = VoiceCallKey(requireNotNull(outgoing.active).callId, LOWER)
        val old = VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(HIGHER, outgoing, sameCallId)
        assertEquals(outgoing, old.next)
        assertTrue(old.effects.isEmpty())

        val active = VoiceCallReducer.apply(
            VoiceCallReducer.apply(
                outgoing,
                VoiceCallEvent(VoiceCallEventKind.REMOTE_ACCEPT, requireNotNull(outgoing.active)),
            ).next,
            VoiceCallEvent(VoiceCallEventKind.MEDIA_CONNECTED, requireNotNull(outgoing.active)),
        ).next
        val busy = VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(
            HIGHER, active, VoiceCallKey(id(12), LOWER),
        )
        assertEquals(active, busy.next)
        assertEquals(listOf(VoiceCallEffectKind.SEND_BUSY), busy.effects.map { it.kind })
    }

    @Test
    fun invalidLocalIdentityOrSelfCallFailsClosedBeforeGlareTransition() {
        val outgoing = outgoing(LOWER)
        for (invalid in listOf("", "x", "A".repeat(100_000), identity(0), id(3))) {
            assertThrows(IllegalArgumentException::class.java) {
                VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(invalid, outgoing, VoiceCallKey(id(12), LOWER))
            }
        }
        val self = outgoing(LOWER)
        assertThrows(IllegalArgumentException::class.java) {
            VoiceCallGlareResolver.resolveAuthenticatedIncomingOffer(LOWER, self, VoiceCallKey(id(12), LOWER))
        }
    }

    private fun outgoing(peer: String): VoiceCallSnapshot {
        val key = VoiceCallKey(id(10), peer)
        return VoiceCallReducer.apply(
            VoiceCallSnapshot(),
            VoiceCallEvent(VoiceCallEventKind.LOCAL_DIAL, key),
        ).next
    }

    private fun id(value: Int) = Base64.getUrlEncoder().withoutPadding().encodeToString(
        ByteArray(16) { value.toByte() },
    )

    private fun identity(value: Int) = Base64.getUrlEncoder().withoutPadding().encodeToString(
        ByteArray(32) { value.toByte() },
    )

    companion object {
        private val LOWER = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 1 })
        private val HIGHER = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 2 })
        private val THIRD = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 3 })
    }
}
