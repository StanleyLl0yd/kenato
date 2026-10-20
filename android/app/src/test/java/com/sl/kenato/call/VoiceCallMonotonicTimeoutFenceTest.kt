package com.sl.kenato.call

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class VoiceCallMonotonicTimeoutFenceTest {
    private val a = key(1, 11)
    private val b = key(2, 11)
    private val other = key(1, 12)

    @Test
    fun ringingTimeoutIsOneShotAndBoundToExactKey() {
        val fence = VoiceCallMonotonicTimeoutFence()
        val ringing = VoiceCallSnapshot(
            phase = VoiceCallPhase.OUTGOING_RINGING,
            active = a,
            direction = VoiceCallDirection.OUTGOING,
        )
        val ticket = fence.issue(ringing, 1000, 30000)
        assertNull(fence.consume(ticket, ringing, 30999))
        assertEquals(
            VoiceCallEvent(VoiceCallEventKind.RING_TIMEOUT, a),
            fence.consume(ticket, ringing, 31000),
        )
        assertNull(fence.consume(ticket, ringing, 31001))
    }

    @Test
    fun incomingRingAndConnectionProduceDifferentExplicitEvents() {
        val fence = VoiceCallMonotonicTimeoutFence()
        val incoming = VoiceCallSnapshot(
            phase = VoiceCallPhase.INCOMING_RINGING,
            active = a,
            direction = VoiceCallDirection.INCOMING,
        )
        val first = fence.issue(incoming, 10, 20)
        assertEquals(VoiceCallEventKind.RING_TIMEOUT, fence.consume(first, incoming, 30)?.kind)
        val connecting = incoming.copy(phase = VoiceCallPhase.CONNECTING)
        val second = fence.issue(connecting, 30, 20)
        assertEquals(VoiceCallEventKind.CONNECT_TIMEOUT, fence.consume(second, connecting, 50)?.kind)
    }

    @Test
    fun staleTicketCannotFireIntoNewCallOrDifferentPeer() {
        val fence = VoiceCallMonotonicTimeoutFence()
        val ringing = VoiceCallSnapshot(
            phase = VoiceCallPhase.OUTGOING_RINGING,
            active = a, direction = VoiceCallDirection.OUTGOING,
        )
        val ticket = fence.issue(ringing, 100, 10)
        assertNull(fence.consume(ticket, ringing.copy(active = b), 110))
        assertNull(fence.consume(ticket, ringing.copy(active = other), 110))
        assertNull(fence.consume(ticket, ringing.copy(phase = VoiceCallPhase.CONNECTING), 110))
        assertNull(fence.consume(ticket, VoiceCallSnapshot(), 110))
        assertEquals(a, fence.consume(ticket, ringing, 110)?.key)
    }

    @Test
    fun rearmedTimerSupersedesOldOneEvenForSameKeyAndPhase() {
        val fence = VoiceCallMonotonicTimeoutFence()
        val ringing = VoiceCallSnapshot(
            phase = VoiceCallPhase.OUTGOING_RINGING,
            active = a, direction = VoiceCallDirection.OUTGOING,
        )
        val first = fence.issue(ringing, 100, 10)
        val second = fence.issue(ringing, 105, 20)
        assertNull(fence.consume(first, ringing, 130))
        assertEquals(a, fence.consume(second, ringing, 130)?.key)
        assertNull(fence.consume(second, ringing, 131))
    }

    @Test
    fun cancelledOrRevokedCallCannotFireLate() {
        val fence = VoiceCallMonotonicTimeoutFence()
        val ringing = VoiceCallSnapshot(
            phase = VoiceCallPhase.INCOMING_RINGING,
            active = a, direction = VoiceCallDirection.INCOMING,
        )
        val ticket = fence.issue(ringing, 100, 10)
        fence.cancel()
        assertNull(fence.consume(ticket, ringing, 999))
        val next = fence.issue(ringing, 1000, 10)
        assertEquals(a, fence.consume(next, ringing, 1010)?.key)
    }

    @Test
    fun copiedTicketWithEqualFieldsCannotConsumeOriginalDeadline() {
        val fence = VoiceCallMonotonicTimeoutFence()
        val ringing = VoiceCallSnapshot(
            phase = VoiceCallPhase.OUTGOING_RINGING,
            active = a, direction = VoiceCallDirection.OUTGOING,
        )
        val issued = fence.issue(ringing, 100, 10)
        val reconstructed = issued.copy()
        assertEquals(issued, reconstructed)
        assertNull(fence.consume(reconstructed, ringing, 111))
        // Rejecting a foreign object must not burn the authentic ticket.
        assertEquals(a, fence.consume(issued, ringing, 111)?.key)
        assertNull(fence.consume(issued, ringing, 112))
    }

    @Test
    fun identicalDeadlineTicketFromAnotherOwnerCannotFireAfterReplacement() {
        val first = VoiceCallMonotonicTimeoutFence()
        val replacement = VoiceCallMonotonicTimeoutFence()
        val ringing = VoiceCallSnapshot(
            phase = VoiceCallPhase.INCOMING_RINGING,
            active = a, direction = VoiceCallDirection.INCOMING,
        )
        val beforeReplacement = first.issue(ringing, 1000, 100)
        val newOwnerTicket = replacement.issue(ringing, 1000, 100)
        assertEquals(beforeReplacement, newOwnerTicket)
        assertNull(replacement.consume(beforeReplacement, ringing, 1100))
        assertEquals(VoiceCallEventKind.RING_TIMEOUT,
            replacement.consume(newOwnerTicket, ringing, 1100)?.kind)
    }

    @Test
    fun activeAndIdleCallsCannotArmTimers() {
        val fence = VoiceCallMonotonicTimeoutFence()
        assertThrows(IllegalArgumentException::class.java) {
            fence.issue(VoiceCallSnapshot(), 1, 10)
        }
        val active = VoiceCallSnapshot(
            phase = VoiceCallPhase.ACTIVE,
            active = a,
            direction = VoiceCallDirection.OUTGOING,
        )
        assertThrows(IllegalArgumentException::class.java) {
            fence.issue(active, 1, 10)
        }
    }

    @Test
    fun invalidDelayAndClockOverflowFailClosed() {
        val fence = VoiceCallMonotonicTimeoutFence()
        val ringing = VoiceCallSnapshot(
            phase = VoiceCallPhase.OUTGOING_RINGING,
            active = a, direction = VoiceCallDirection.OUTGOING,
        )
        for (delay in listOf(0L, -1L, 120001L)) {
            assertThrows(IllegalArgumentException::class.java) {
                fence.issue(ringing, 1, delay)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            fence.issue(ringing, -1, 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            fence.issue(ringing, Long.MAX_VALUE, 2)
        }
        val fine = fence.issue(ringing, 100, 10)
        assertNull(fence.consume(fine, ringing, -1))
        assertEquals(a, fence.consume(fine, ringing, 110)?.key)
    }

    private fun key(call: Int, peer: Int): VoiceCallKey =
        VoiceCallKey(
            Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16) { call.toByte() }),
            Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { peer.toByte() }),
        )
}
