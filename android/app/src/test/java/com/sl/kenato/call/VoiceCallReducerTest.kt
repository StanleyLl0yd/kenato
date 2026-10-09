package com.sl.kenato.call

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class VoiceCallReducerTest {
    @Test
    fun outgoingCallStartsMediaOnlyAfterAuthenticatedPeerAccept() {
        val dial = send(VoiceCallSnapshot(), VoiceCallEventKind.LOCAL_DIAL)
        assertEquals(VoiceCallPhase.OUTGOING_RINGING, dial.next.phase)
        assertEquals(listOf(VoiceCallEffectKind.SEND_OFFER), kinds(dial))

        val connected = send(dial.next, VoiceCallEventKind.REMOTE_ACCEPT)
        assertEquals(VoiceCallPhase.CONNECTING, connected.next.phase)
        assertEquals(listOf(VoiceCallEffectKind.START_MEDIA), kinds(connected))

        val active = send(connected.next, VoiceCallEventKind.MEDIA_CONNECTED)
        assertEquals(VoiceCallPhase.ACTIVE, active.next.phase)
        assertTrue(active.effects.isEmpty())

        val ended = send(active.next, VoiceCallEventKind.LOCAL_HANGUP)
        assertEquals(VoiceCallPhase.IDLE, ended.next.phase)
        assertEquals(listOf(VoiceCallEffectKind.SEND_HANGUP, VoiceCallEffectKind.STOP_MEDIA), kinds(ended))
        assertEquals(listOf(PRIMARY.callId), ended.next.retiredCallIds)
    }

    @Test
    fun incomingCallRequiresExplicitLocalAcceptance() {
        val offered = send(VoiceCallSnapshot(), VoiceCallEventKind.INCOMING_OFFER)
        assertEquals(VoiceCallPhase.INCOMING_RINGING, offered.next.phase)
        assertTrue(offered.effects.isEmpty())

        val accepted = send(offered.next, VoiceCallEventKind.LOCAL_ACCEPT)
        assertEquals(VoiceCallPhase.CONNECTING, accepted.next.phase)
        assertEquals(listOf(VoiceCallEffectKind.SEND_ACCEPT, VoiceCallEffectKind.START_MEDIA), kinds(accepted))

        val closed = send(accepted.next, VoiceCallEventKind.REMOTE_HANGUP)
        assertEquals(VoiceCallPhase.IDLE, closed.next.phase)
        assertEquals(listOf(VoiceCallEffectKind.STOP_MEDIA), kinds(closed))
    }

    @Test
    fun incomingBusyDoesNotReplaceActiveCallAndDuplicateOfferIsIdempotent() {
        val ringing = send(VoiceCallSnapshot(), VoiceCallEventKind.INCOMING_OFFER).next
        assertTrue(send(ringing, VoiceCallEventKind.INCOMING_OFFER).effects.isEmpty())
        val busy = send(ringing, VoiceCallEventKind.INCOMING_OFFER, SECONDARY)
        assertEquals(ringing, busy.next)
        assertEquals(listOf(VoiceCallEffectKind.SEND_BUSY), kinds(busy))
        assertEquals(SECONDARY, busy.effects.single().key)

        val substitutedPeer = VoiceCallKey(PRIMARY.callId, OTHER_IDENTITY)
        val collision = send(ringing, VoiceCallEventKind.INCOMING_OFFER, substitutedPeer)
        assertEquals(ringing, collision.next)
        assertTrue(collision.effects.isEmpty())
    }

    @Test
    fun wrongIdentityOrCallIdCannotEndAnotherCall() {
        val active = establishOutgoing()
        val changedPeer = VoiceCallKey(PRIMARY.callId, OTHER_IDENTITY)
        for (wrong in listOf(SECONDARY, changedPeer)) {
            for (kind in listOf(
                VoiceCallEventKind.REMOTE_HANGUP,
                VoiceCallEventKind.REMOTE_REJECT,
                VoiceCallEventKind.REMOTE_ACCEPT,
                VoiceCallEventKind.MEDIA_FAILED,
                VoiceCallEventKind.CONNECT_TIMEOUT,
                VoiceCallEventKind.LOCAL_HANGUP,
            )) {
                val result = send(active, kind, wrong)
                assertEquals(active, result.next)
                assertTrue(result.effects.isEmpty())
            }
        }
    }

    @Test
    fun delayedTimeoutAndRepeatedAcceptAreHarmless() {
        val dialing = send(VoiceCallSnapshot(), VoiceCallEventKind.LOCAL_DIAL).next
        val connecting = send(dialing, VoiceCallEventKind.REMOTE_ACCEPT)
        assertTrue(send(connecting.next, VoiceCallEventKind.REMOTE_ACCEPT).effects.isEmpty())
        assertTrue(send(connecting.next, VoiceCallEventKind.RING_TIMEOUT).effects.isEmpty())
        val active = send(connecting.next, VoiceCallEventKind.MEDIA_CONNECTED).next
        assertTrue(send(active, VoiceCallEventKind.CONNECT_TIMEOUT).effects.isEmpty())
        assertTrue(send(active, VoiceCallEventKind.REMOTE_REJECT).effects.isEmpty())
        assertEquals(VoiceCallPhase.ACTIVE, active.phase)
    }

    @Test
    fun failuresAndTimeoutsStopMediaAtMostOnce() {
        for (kind in listOf(VoiceCallEventKind.MEDIA_FAILED, VoiceCallEventKind.CONNECT_TIMEOUT)) {
            val connecting = send(
                send(VoiceCallSnapshot(), VoiceCallEventKind.LOCAL_DIAL).next,
                VoiceCallEventKind.REMOTE_ACCEPT,
            ).next
            val done = send(connecting, kind)
            assertEquals(VoiceCallPhase.IDLE, done.next.phase)
            assertEquals(listOf(VoiceCallEffectKind.SEND_HANGUP, VoiceCallEffectKind.STOP_MEDIA), kinds(done))
            assertTrue(send(done.next, kind).effects.isEmpty())
        }
        val outgoingTimeout = send(
            send(VoiceCallSnapshot(), VoiceCallEventKind.LOCAL_DIAL).next,
            VoiceCallEventKind.RING_TIMEOUT,
        )
        assertEquals(listOf(VoiceCallEffectKind.SEND_HANGUP), kinds(outgoingTimeout))

        val incomingTimeout = send(
            send(VoiceCallSnapshot(), VoiceCallEventKind.INCOMING_OFFER).next,
            VoiceCallEventKind.RING_TIMEOUT,
        )
        assertEquals(listOf(VoiceCallEffectKind.SEND_REJECT), kinds(incomingTimeout))
    }

    @Test
    fun rejectedCallCannotBeAcceptedLateOrReplayedWhileRetired() {
        val ringing = send(VoiceCallSnapshot(), VoiceCallEventKind.INCOMING_OFFER).next
        val refused = send(ringing, VoiceCallEventKind.LOCAL_REJECT)
        assertEquals(VoiceCallPhase.IDLE, refused.next.phase)
        assertEquals(listOf(VoiceCallEffectKind.SEND_REJECT), kinds(refused))
        for (kind in listOf(
            VoiceCallEventKind.INCOMING_OFFER,
            VoiceCallEventKind.LOCAL_DIAL,
            VoiceCallEventKind.LOCAL_ACCEPT,
            VoiceCallEventKind.REMOTE_ACCEPT,
            VoiceCallEventKind.MEDIA_CONNECTED,
            VoiceCallEventKind.REMOTE_HANGUP,
        )) {
            val result = send(refused.next, kind)
            assertEquals(refused.next, result.next)
            assertTrue(result.effects.isEmpty())
        }
    }

    @Test
    fun completedCallCacheIsBoundedAndOldCallbacksCannotTerminateNewCall() {
        var snapshot = VoiceCallSnapshot()
        repeat(80) { index ->
            val call = keyFor(index + 1)
            val ringing = send(snapshot, VoiceCallEventKind.LOCAL_DIAL, call).next
            snapshot = send(ringing, VoiceCallEventKind.LOCAL_HANGUP, call).next
            assertTrue(snapshot.retiredCallIds.size <= 64)
        }
        assertEquals(64, snapshot.retiredCallIds.size)
        assertEquals(keyFor(17).callId, snapshot.retiredCallIds.first())
        val current = keyFor(100)
        val active = send(snapshot, VoiceCallEventKind.LOCAL_DIAL, current).next
        val stale = send(active, VoiceCallEventKind.REMOTE_HANGUP, keyFor(80))
        assertEquals(active, stale.next)
        assertTrue(stale.effects.isEmpty())
    }

    @Test
    fun mediaFailureInActiveCallTerminatesAndStopsMediaOnce() {
        val active = establishOutgoing()
        val failed = send(active, VoiceCallEventKind.MEDIA_FAILED)
        assertEquals(VoiceCallPhase.IDLE, failed.next.phase)
        assertEquals(listOf(VoiceCallEffectKind.SEND_HANGUP, VoiceCallEffectKind.STOP_MEDIA), kinds(failed))
        assertEquals(listOf(PRIMARY.callId), failed.next.retiredCallIds)

        val duplicate = send(failed.next, VoiceCallEventKind.MEDIA_FAILED)
        assertEquals(failed.next, duplicate.next)
        assertTrue(duplicate.effects.isEmpty())
    }

    @Test
    fun identifiersRequireCanonicalNonzeroBoundedBase64Url() {
        for (invalidCall in listOf("", "abc", "=", "!", encode(ByteArray(16)), encode(ByteArray(17)))) {
            assertThrows(IllegalArgumentException::class.java) {
                VoiceCallKey(invalidCall, IDENTITY)
            }
        }
        for (invalidPeer in listOf("", "abc", "!", encode(ByteArray(32)), encode(ByteArray(31)))) {
            assertThrows(IllegalArgumentException::class.java) {
                VoiceCallKey(PRIMARY.callId, invalidPeer)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            VoiceCallSnapshot(phase = VoiceCallPhase.CONNECTING)
        }
        assertThrows(IllegalArgumentException::class.java) {
            VoiceCallSnapshot(phase = VoiceCallPhase.IDLE, active = PRIMARY)
        }
    }

    private fun establishOutgoing(): VoiceCallSnapshot {
        val dialing = send(VoiceCallSnapshot(), VoiceCallEventKind.LOCAL_DIAL).next
        val connecting = send(dialing, VoiceCallEventKind.REMOTE_ACCEPT).next
        return send(connecting, VoiceCallEventKind.MEDIA_CONNECTED).next
    }

    private fun send(
        state: VoiceCallSnapshot,
        kind: VoiceCallEventKind,
        key: VoiceCallKey = PRIMARY,
    ) = VoiceCallReducer.apply(state, VoiceCallEvent(kind, key))

    private fun kinds(result: VoiceCallTransition): List<VoiceCallEffectKind> = result.effects.map { it.kind }

    private fun keyFor(value: Int): VoiceCallKey =
        VoiceCallKey(encode(ByteArray(16) { index -> if (index == 0) value.toByte() else 0.toByte() }), IDENTITY)

    private fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private companion object {
        val IDENTITY: String = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 1 })
        val OTHER_IDENTITY: String = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 2 })
        val PRIMARY = VoiceCallKey(
            Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16) { 3 }),
            IDENTITY,
        )
        val SECONDARY = VoiceCallKey(
            Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16) { 4 }),
            OTHER_IDENTITY,
        )
    }
}
