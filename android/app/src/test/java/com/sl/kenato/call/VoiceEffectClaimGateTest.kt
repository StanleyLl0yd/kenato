package com.sl.kenato.call

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** Proposal-stage invariants only; NEVER evidence of executed native/media effects. */
class VoiceEffectClaimGateTest {
    private val owner = ByteArray(32) { 11 }
    private val peer = ByteArray(32) { 22 }
    private val other = ByteArray(32) { 33 }
    private val key = VoiceCallKey(encoded(ByteArray(16) { 44 }), encoded(peer))
    private val otherKey = VoiceCallKey(encoded(ByteArray(16) { 55 }), encoded(other))
    private val ringing = VoiceCallSnapshot(
        phase = VoiceCallPhase.OUTGOING_RINGING,
        active = key,
        direction = VoiceCallDirection.OUTGOING,
    )
    private val connecting = ringing.copy(phase = VoiceCallPhase.CONNECTING)
    private val retired = VoiceCallSnapshot(retiredCallIds = listOf(key.callId))

    @Test
    fun matchingFreshTicketAndConsentCanBeClaimedExactlyOnce() {
        val f = Fixture()
        val ticket = f.gate.replace(VoiceCallTransition(
            ringing, listOf(VoiceCallEffect(VoiceCallEffectKind.SEND_OFFER, key)),
        )).single()
        assertEquals(VoiceCallEffect(VoiceCallEffectKind.SEND_OFFER, key), f.claim(ticket, ringing))
        assertEquals(1, f.approvals)
        assertNull(f.claim(ticket, ringing))
        assertEquals(1, f.approvals)
    }

    @Test
    fun lostConsentNeverLeavesRetryableSendClaim() {
        val f = Fixture()
        val t = f.gate.replace(VoiceCallTransition(
            ringing, listOf(VoiceCallEffect(VoiceCallEffectKind.SEND_OFFER, key)),
        )).single()
        f.consent = false
        assertNull(f.claim(t, ringing))
        f.consent = true
        assertNull(f.claim(t, ringing))
        assertEquals(1, f.approvals)
    }

    @Test
    fun staleStateAndSupersededTicketCannotStartMedia() {
        val f = Fixture()
        val t = f.gate.replace(VoiceCallTransition(
            connecting, listOf(VoiceCallEffect(VoiceCallEffectKind.START_MEDIA, key)),
        )).single()
        assertNull(f.claim(t, ringing))
        f.gate.replace(VoiceCallTransition(retired))
        assertNull(f.claim(t, connecting))
        assertEquals(0, f.approvals)
    }

    @Test
    fun aSingleMismatchedSnapshotIrreversiblyConsumesTheProposal() {
        val f = Fixture()
        val ticket = f.gate.replace(VoiceCallTransition(
            connecting, listOf(VoiceCallEffect(VoiceCallEffectKind.START_MEDIA, key)),
        )).single()
        assertNull(f.claim(ticket, ringing))
        // Even if a caller later supplies the expected snapshot, the proposal
        // was already rejected and cannot reappear.
        assertNull(f.claim(ticket, connecting))
        assertEquals(0, f.approvals)
    }

    @Test
    fun oldStopTicketCannotCloseDifferentNewCall() {
        val f = Fixture()
        val stop = f.gate.replace(VoiceCallTransition(
            retired, listOf(VoiceCallEffect(VoiceCallEffectKind.STOP_MEDIA, key)),
        )).single()
        val another = VoiceCallSnapshot(
            phase = VoiceCallPhase.CONNECTING,
            active = otherKey,
            direction = VoiceCallDirection.OUTGOING,
            retiredCallIds = listOf(key.callId),
        )
        f.gate.replace(VoiceCallTransition(another))
        assertNull(f.claim(stop, another))
    }

    @Test
    fun revocationCannotBlockExactLocalMediaStop() {
        val f = Fixture()
        f.consent = false
        val stop = f.gate.replace(VoiceCallTransition(
            retired, listOf(VoiceCallEffect(VoiceCallEffectKind.STOP_MEDIA, key)),
        )).single()
        assertEquals(VoiceCallEffect(VoiceCallEffectKind.STOP_MEDIA, key), f.claim(stop, retired))
        assertNull(f.claim(stop, retired))
        assertEquals(0, f.approvals)
    }

    @Test
    fun busyProposalRevalidatesTheDifferentApprovedPeer() {
        val f = Fixture()
        val t = f.gate.replace(VoiceCallTransition(
            ringing, listOf(VoiceCallEffect(VoiceCallEffectKind.SEND_BUSY, otherKey)),
        )).single()
        f.expectedPeer = other
        assertEquals(VoiceCallEffect(VoiceCallEffectKind.SEND_BUSY, otherKey), f.claim(t, ringing))
        assertEquals(1, f.approvals)
    }

    @Test
    fun cancelInvalidatesUnclaimedTickets() {
        val f = Fixture()
        val t = f.gate.replace(VoiceCallTransition(
            ringing, listOf(VoiceCallEffect(VoiceCallEffectKind.SEND_OFFER, key)),
        )).single()
        f.gate.cancel()
        assertNull(f.claim(t, ringing))
        assertEquals(0, f.approvals)
    }

    @Test
    fun transitionEffectBoundRefusesForgedOversizedEffectBatch() {
        val f = Fixture()
        val repeated = List(3) { VoiceCallEffect(VoiceCallEffectKind.SEND_OFFER, key) }
        assertThrows(IllegalArgumentException::class.java) {
            f.gate.replace(VoiceCallTransition(ringing, repeated))
        }
    }

    private inner class Fixture {
        val gate = VoiceEffectClaimGate()
        var consent = true
        var approvals = 0
        var expectedPeer = peer
        val guard = VoiceCallVerifiedPeerAdmission { suppliedOwner, suppliedPeer ->
            approvals++
            require(suppliedOwner.contentEquals(owner))
            require(suppliedPeer.contentEquals(expectedPeer))
            if (!consent) throw VoiceCallAdmissionException("Revoked")
        }

        fun claim(t: VoiceEffectClaimGate.Ticket, state: VoiceCallSnapshot): VoiceCallEffect? =
            gate.claim(t, state, guard, owner)
    }

    private fun encoded(bytes: ByteArray) =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
