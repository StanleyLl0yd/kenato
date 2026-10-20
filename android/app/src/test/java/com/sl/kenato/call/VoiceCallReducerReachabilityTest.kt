package com.sl.kenato.call

import java.util.ArrayDeque
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Finite reachable-state exploration of the pure M5 reducer. This does NOT
 * authorize effect execution or replace authenticated durable M3 claims.
 */
class VoiceCallReducerReachabilityTest {
    private val keys = listOf(
        key(1, 11),
        key(2, 11), // Another call id to same exact peer
        key(3, 12), // Different authenticated peer
    )

    @Test
    fun everyReachableTransitionRespectsMediaAndSignalingKeyBoundaries() {
        val initial = VoiceCallSnapshot()
        val visited = mutableSetOf(initial)
        val frontier = ArrayDeque<VoiceCallSnapshot>()
        frontier.add(initial)
        var explored = 0
        var mediaStarts = 0
        var mediaStops = 0
        var busyOffers = 0

        while (frontier.isNotEmpty()) {
            val before = frontier.removeFirst()
            for (key in keys) {
                for (kind in VoiceCallEventKind.entries) {
                    val event = VoiceCallEvent(kind, key)
                    val actual = VoiceCallReducer.apply(before, event)
                    explored++
                    // Reducers may emit a two-step signal+media proposal but
                    // cannot themselves execute one.
                    assertTrue("Too many effects: $event", actual.effects.size <= 2)
                    assertTrue("Retirement cache must remain bounded", actual.next.retiredCallIds.size <= 64)
                    for (effect in actual.effects) {
                        when (effect.kind) {
                            VoiceCallEffectKind.SEND_OFFER -> {
                                assertEquals(VoiceCallPhase.IDLE, before.phase)
                                assertEquals(VoiceCallPhase.OUTGOING_RINGING, actual.next.phase)
                                assertEquals(key, actual.next.active)
                            }
                            VoiceCallEffectKind.SEND_ACCEPT -> {
                                assertEquals(VoiceCallPhase.INCOMING_RINGING, before.phase)
                                assertEquals(VoiceCallPhase.CONNECTING, actual.next.phase)
                                assertEquals(before.active, effect.key)
                            }
                            VoiceCallEffectKind.SEND_BUSY -> {
                                busyOffers++
                                assertTrue(before.phase != VoiceCallPhase.IDLE)
                                assertEquals(before, actual.next)
                                assertTrue(before.active != effect.key)
                                assertTrue(before.active!!.callId != effect.key.callId)
                                assertTrue(effect.key.callId !in before.retiredCallIds)
                            }
                            VoiceCallEffectKind.SEND_REJECT -> {
                                assertEquals(VoiceCallPhase.INCOMING_RINGING, before.phase)
                                assertEquals(VoiceCallPhase.IDLE, actual.next.phase)
                                assertEquals(before.active, effect.key)
                            }
                            VoiceCallEffectKind.SEND_HANGUP -> {
                                assertTrue(before.phase in setOf(
                                    VoiceCallPhase.OUTGOING_RINGING,
                                    VoiceCallPhase.CONNECTING,
                                    VoiceCallPhase.ACTIVE,
                                ))
                                assertEquals(VoiceCallPhase.IDLE, actual.next.phase)
                                assertEquals(before.active, effect.key)
                            }
                            VoiceCallEffectKind.START_MEDIA -> {
                                mediaStarts++
                                assertTrue(before.phase in setOf(
                                    VoiceCallPhase.OUTGOING_RINGING,
                                    VoiceCallPhase.INCOMING_RINGING,
                                ))
                                assertEquals(VoiceCallPhase.CONNECTING, actual.next.phase)
                                assertEquals(before.active, effect.key)
                                assertEquals(actual.next.active, effect.key)
                            }
                            VoiceCallEffectKind.STOP_MEDIA -> {
                                mediaStops++
                                assertTrue(before.phase in setOf(
                                    VoiceCallPhase.CONNECTING, VoiceCallPhase.ACTIVE,
                                ))
                                assertEquals(VoiceCallPhase.IDLE, actual.next.phase)
                                assertEquals(before.active, effect.key)
                                assertTrue(effect.key.callId in actual.next.retiredCallIds)
                            }
                        }
                        assertTrue("Proposed effect must refer to event key", effect.key == event.key)
                    }
                    if (visited.add(actual.next)) {
                        frontier.addLast(actual.next)
                        assertTrue("Finite-state probe exceeded bound", visited.size < 2000)
                    }
                }
            }
        }
        assertTrue("Exploration did not exercise enough state", visited.size >= 12)
        assertTrue("Exploration did not propose enough transitions", explored >= 100)
        assertTrue(mediaStarts > 0)
        assertTrue(mediaStops > 0)
        assertTrue(busyOffers > 0)
    }

    @Test
    fun staleRetiredCallMediaCallbacksCannotActOnNextCall() {
        val old = keys[0]
        val next = keys[1]
        val first = VoiceCallReducer.apply(
            VoiceCallSnapshot(), VoiceCallEvent(VoiceCallEventKind.LOCAL_DIAL, old),
        )
        val retired = VoiceCallReducer.apply(
            first.next, VoiceCallEvent(VoiceCallEventKind.LOCAL_HANGUP, old),
        )
        val second = VoiceCallReducer.apply(
            retired.next, VoiceCallEvent(VoiceCallEventKind.LOCAL_DIAL, next),
        )
        assertEquals(next, second.next.active)
        for (kind in VoiceCallEventKind.entries.filter {
            it != VoiceCallEventKind.INCOMING_OFFER && it != VoiceCallEventKind.LOCAL_DIAL
        }) {
            val result = VoiceCallReducer.apply(second.next, VoiceCallEvent(kind, old))
            assertEquals(second.next, result.next)
            assertTrue("Stale callback proposed effect: $kind", result.effects.isEmpty())
        }
    }

    private fun key(call: Int, peer: Int): VoiceCallKey = VoiceCallKey(
        encode(ByteArray(16) { call.toByte() }),
        encode(ByteArray(32) { peer.toByte() }),
    )

    private fun encode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
