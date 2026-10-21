package com.sl.kenato.call

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A one-time durable claim may take time, including during the second pinned
 * consent check. The reducer must use a fresh, non-regressed admission clock.
 */
class VoiceCallClaimAdmissionFreshnessTest {
    @Test
    fun expiredIncomingOfferDuringClaimCannotStartRinging() {
        var now = NOW
        var claims = 0
        val c = coordinator(
            clock = { now },
            claim = {
                claims++
                now = NOW + 60
                signal(VoiceSignalKind.OFFER, expiry = NOW + 60)
            },
        )
        assertThrows(VoiceCallAdmissionException::class.java) {
            c.receiveClaimedControl(PEER, id(1))
        }
        assertEquals(1, claims)
        assertEquals(VoiceCallPhase.IDLE, c.snapshot().phase)
        assertTrue(c.snapshot().retiredCallIds.isEmpty())
    }

    @Test
    fun expiredAnswerDuringClaimCannotStartMedia() {
        var now = NOW
        val c = coordinator(
            clock = { now },
            claim = {
                now = NOW + 60
                signal(VoiceSignalKind.ANSWER, expiry = NOW + 60)
            },
        )
        val key = c.userDial(PEER, true).next.active!!
        assertThrows(VoiceCallAdmissionException::class.java) {
            c.receiveClaimedControl(PEER, id(1))
        }
        assertEquals(VoiceCallPhase.OUTGOING_RINGING, c.snapshot().phase)
        assertEquals(key, c.snapshot().active)
    }

    @Test
    fun expirationDuringSecondConsentCheckAlsoFailsClosed() {
        var now = NOW
        var approvals = 0
        val c = coordinator(
            clock = { now },
            claim = { signal(VoiceSignalKind.OFFER, expiry = NOW + 60) },
            approved = {
                approvals++
                if (approvals == 2) now = NOW + 60
            },
        )
        assertThrows(VoiceCallAdmissionException::class.java) {
            c.receiveClaimedControl(PEER, id(1))
        }
        assertEquals(2, approvals)
        assertEquals(VoiceCallPhase.IDLE, c.snapshot().phase)
    }

    @Test
    fun backwardsWallClockDuringClaimIsRejected() {
        var now = NOW
        val c = coordinator(
            clock = { now },
            claim = {
                now = NOW - 1
                signal(VoiceSignalKind.OFFER)
            },
        )
        assertThrows(VoiceCallAdmissionException::class.java) {
            c.receiveClaimedControl(PEER, id(1))
        }
        assertEquals(VoiceCallPhase.IDLE, c.snapshot().phase)
    }

    @Test
    fun stillFreshClaimAdmitsOriginalOffer() {
        var now = NOW
        val c = coordinator(
            clock = { now },
            claim = {
                now = NOW + 59
                signal(VoiceSignalKind.OFFER, expiry = NOW + 60)
            },
        )
        val transition = c.receiveClaimedControl(PEER, id(1))!!
        assertEquals(VoiceCallPhase.INCOMING_RINGING, transition.next.phase)
        assertTrue(transition.effects.isEmpty())
    }

    private fun coordinator(
        clock: () -> Long,
        claim: () -> VoiceSignalPlaintext,
        approved: () -> Unit = {},
    ) = VoiceCallAdmissionCoordinator(
        OWNER,
        VoiceCallVerifiedPeerAdmission { _, _ -> approved() },
        VoiceCallClaimedControlSource { _, _, _, _ -> claim() },
        VoiceCallCoordinatorClock { clock() },
        VoiceCallIdGenerator { CALL.copyOf() },
    )

    private fun signal(kind: VoiceSignalKind, expiry: Long = NOW + 60) =
        VoiceSignalPlaintext(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = id(1),
            callId = CALL.copyOf(),
            sentAtEpochSeconds = NOW,
            expiresAtEpochSeconds = expiry,
            kind = kind,
            payload = byteArrayOf(),
        )

    private companion object {
        const val NOW = 1_780_000_000L
        val OWNER = ByteArray(32) { 0x11 }
        val PEER = ByteArray(32) { 0x22 }
        val CALL = id(77)
        fun id(value: Int): ByteArray = ByteArray(16).also { it[0] = value.toByte() }
    }
}
