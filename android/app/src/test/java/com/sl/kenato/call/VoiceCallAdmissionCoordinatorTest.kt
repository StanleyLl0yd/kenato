package com.sl.kenato.call

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceCallAdmissionCoordinatorTest {
    @Test
    fun deniedConsentNeverClaimsOrProposesCallEffects() {
        val f = Fixture()
        f.permissionAllowed = false
        assertThrows(VoiceCallAdmissionException::class.java) {
            f.coordinator.userDial(PEER, explicitUserApproval = false)
        }
        assertThrows(VoiceCallAdmissionException::class.java) {
            f.coordinator.userDial(PEER, explicitUserApproval = true)
        }
        f.next = event(VoiceSignalKind.OFFER, 1)
        assertThrows(VoiceCallAdmissionException::class.java) {
            f.coordinator.receiveClaimedControl(PEER, id(1))
        }
        assertEquals(0, f.claims)
        assertEquals(VoiceCallPhase.IDLE, f.coordinator.snapshot().phase)
    }

    @Test
    fun claimedOfferNeedsExplicitLocalAcceptAndFreshCapability() {
        val f = Fixture()
        f.next = event(VoiceSignalKind.OFFER, 1)
        val proposed = f.coordinator.receiveClaimedControl(PEER, id(1))!!
        assertEquals(VoiceCallPhase.INCOMING_RINGING, proposed.next.phase)
        assertTrue(proposed.effects.isEmpty())
        val key = proposed.next.active!!
        assertThrows(VoiceCallAdmissionException::class.java) {
            f.coordinator.userAction(VoiceCallEventKind.LOCAL_ACCEPT, key)
        }
        assertEquals(VoiceCallPhase.INCOMING_RINGING, f.coordinator.snapshot().phase)
        val accepted = f.coordinator.userAction(
            VoiceCallEventKind.LOCAL_ACCEPT, key, explicitUserApproval = true,
        )
        assertEquals(VoiceCallPhase.CONNECTING, accepted.next.phase)
        assertEquals(
            listOf(VoiceCallEffectKind.SEND_ACCEPT, VoiceCallEffectKind.START_MEDIA),
            accepted.effects.map { it.kind },
        )
        val rejected = f.coordinator.callback(VoiceCallEventKind.MEDIA_FAILED, key)
        assertEquals(VoiceCallPhase.IDLE, rejected.next.phase)
        assertEquals(
            listOf(VoiceCallEffectKind.SEND_HANGUP, VoiceCallEffectKind.STOP_MEDIA),
            rejected.effects.map { it.kind },
        )
    }

    @Test
    fun onlyClaimedMatchingUnexpiredCallControlCanChangeState() {
        val f = Fixture()
        f.next = event(VoiceSignalKind.OFFER, 3).let {
            VoiceSignalPlaintext(
                senderIdentityId = OTHER,
                recipientIdentityId = OWNER,
                messageId = id(3),
                callId = CALL,
                sentAtEpochSeconds = NOW,
                expiresAtEpochSeconds = NOW + 60,
                kind = VoiceSignalKind.OFFER,
                payload = byteArrayOf(),
            )
        }
        assertThrows(VoiceCallAdmissionException::class.java) {
            f.coordinator.receiveClaimedControl(PEER, id(3))
        }
        assertEquals(VoiceCallPhase.IDLE, f.coordinator.snapshot().phase)

        f.next = event(VoiceSignalKind.OFFER, 4, expiry = NOW)
        assertThrows(VoiceCallAdmissionException::class.java) {
            f.coordinator.receiveClaimedControl(PEER, id(4))
        }
        f.next = null
        assertEquals(null, f.coordinator.receiveClaimedControl(PEER, id(5)))
        assertEquals(VoiceCallPhase.IDLE, f.coordinator.snapshot().phase)
    }

    @Test
    fun staleCallbackAndWrongPeerNeverHangUpAnotherCall() {
        val f = Fixture()
        val dial = f.coordinator.userDial(PEER, explicitUserApproval = true)
        val key = dial.next.active!!
        assertEquals(listOf(VoiceCallEffectKind.SEND_OFFER), dial.effects.map { it.kind })
        f.next = event(VoiceSignalKind.ANSWER, 5)
        val connecting = f.coordinator.receiveClaimedControl(PEER, id(5))!!
        assertEquals(VoiceCallPhase.CONNECTING, connecting.next.phase)

        val wrong = VoiceCallKey(key.callId, encoded(OTHER))
        assertTrue(f.coordinator.callback(VoiceCallEventKind.MEDIA_FAILED, wrong).effects.isEmpty())
        assertEquals(VoiceCallPhase.CONNECTING, f.coordinator.snapshot().phase)
        val active = f.coordinator.callback(VoiceCallEventKind.MEDIA_CONNECTED, key)
        assertEquals(VoiceCallPhase.ACTIVE, active.next.phase)
        f.coordinator.userAction(VoiceCallEventKind.LOCAL_HANGUP, key)
        assertEquals(VoiceCallPhase.IDLE, f.coordinator.snapshot().phase)
        assertTrue(f.coordinator.callback(VoiceCallEventKind.MEDIA_CONNECTED, key).effects.isEmpty())
    }

    @Test
    fun noDirectForgedNetworkEventsCanEnterUserOrCallbackChannels() {
        val f = Fixture()
        val key = VoiceCallKey(encoded(CALL), encoded(PEER))
        assertThrows(VoiceCallAdmissionException::class.java) {
            f.coordinator.userAction(VoiceCallEventKind.REMOTE_ACCEPT, key, true)
        }
        assertThrows(VoiceCallAdmissionException::class.java) {
            f.coordinator.callback(VoiceCallEventKind.INCOMING_OFFER, key)
        }
        assertEquals(VoiceCallPhase.IDLE, f.coordinator.snapshot().phase)
    }

    @Test
    fun callIdGeneratorCannotInjectZeroOrUnexpectedLength() {
        val deniedZero = VoiceCallAdmissionCoordinator(
            OWNER,
            VoiceCallVerifiedPeerAdmission { _, _ -> },
            VoiceCallClaimedControlSource { _, _, _, _ -> null },
            VoiceCallCoordinatorClock { NOW },
            VoiceCallIdGenerator { ByteArray(16) },
        )
        assertThrows(VoiceCallAdmissionException::class.java) {
            deniedZero.userDial(PEER, true)
        }
        assertEquals(VoiceCallPhase.IDLE, deniedZero.snapshot().phase)

        val deniedShort = VoiceCallAdmissionCoordinator(
            OWNER,
            VoiceCallVerifiedPeerAdmission { _, _ -> },
            VoiceCallClaimedControlSource { _, _, _, _ -> null },
            VoiceCallCoordinatorClock { NOW },
            VoiceCallIdGenerator { byteArrayOf(1, 2) },
        )
        assertThrows(VoiceCallAdmissionException::class.java) {
            deniedShort.userDial(PEER, true)
        }
    }

    @Test
    fun newIncomingOfferCannotResurrectRetiredCallAndReusedKeyIsIgnored() {
        val f = Fixture()
        f.next = event(VoiceSignalKind.OFFER, 7)
        val ringing = f.coordinator.receiveClaimedControl(PEER, id(7))!!
        val key = ringing.next.active!!
        f.coordinator.userAction(VoiceCallEventKind.LOCAL_REJECT, key)
        f.next = event(VoiceSignalKind.OFFER, 8)
        val duplicate = f.coordinator.receiveClaimedControl(PEER, id(8))!!
        assertEquals(VoiceCallPhase.IDLE, duplicate.next.phase)
        assertTrue(duplicate.effects.isEmpty())
    }

    @Test
    fun simultaneousOffersUseExistingDeterministicPinnedGlarePolicy() {
        val f = Fixture()
        val outgoing = f.coordinator.userDial(PEER, true)
        assertEquals(VoiceCallPhase.OUTGOING_RINGING, outgoing.next.phase)
        f.next = event(VoiceSignalKind.OFFER, 9, call = id(99))
        val result = f.coordinator.receiveClaimedControl(PEER, id(9))!!
        // Local owner 0x11 compares lower than peer 0x22; outgoing remains winner.
        assertEquals(VoiceCallPhase.OUTGOING_RINGING, result.next.phase)
        assertEquals(listOf(VoiceCallEffectKind.SEND_BUSY), result.effects.map { it.kind })
        assertEquals(encoded(CALL), result.next.active!!.callId)
    }

    @Test
    fun revokedCapabilityBlocksAcceptAndConnectedCallbackButAllowsTeardown() {
        val f = Fixture()
        f.next = event(VoiceSignalKind.OFFER, 10)
        val incoming = f.coordinator.receiveClaimedControl(PEER, id(10))!!
        val key = incoming.next.active!!
        f.permissionAllowed = false
        assertThrows(VoiceCallAdmissionException::class.java) {
            f.coordinator.userAction(VoiceCallEventKind.LOCAL_ACCEPT, key, true)
        }
        assertEquals(VoiceCallPhase.INCOMING_RINGING, f.coordinator.snapshot().phase)
        assertEquals(VoiceCallPhase.IDLE, f.coordinator.userAction(
            VoiceCallEventKind.LOCAL_REJECT, key,
        ).next.phase)
    }

    private class Fixture {
        var permissionAllowed = true
        var next: VoiceSignalPlaintext? = null
        var claims = 0
        val coordinator = VoiceCallAdmissionCoordinator(
            OWNER,
            VoiceCallVerifiedPeerAdmission { owner, peer ->
                if (!permissionAllowed) throw VoiceCallAdmissionException("Consent revoked")
                if (!owner.contentEquals(OWNER) || !peer.contentEquals(PEER)) {
                    throw VoiceCallAdmissionException("Unpinned peer")
                }
            },
            VoiceCallClaimedControlSource { owner, peer, message, now ->
                claims++
                if (!owner.contentEquals(OWNER) || !peer.contentEquals(PEER) ||
                    now != NOW
                ) throw VoiceCallAdmissionException("Untrusted claim request")
                next?.takeIf { it.messageId.contentEquals(message) }
            },
            VoiceCallCoordinatorClock { NOW },
            VoiceCallIdGenerator { CALL.copyOf() },
        )
    }

    private companion object {
        const val NOW = 1_780_000_000L
        val OWNER = ByteArray(32) { 0x11.toByte() }
        val PEER = ByteArray(32) { 0x22.toByte() }
        val OTHER = ByteArray(32) { 0x33.toByte() }
        val CALL = id(77)
        fun id(n: Int) = ByteArray(16).also { it[0] = (n and 255).toByte() }
        fun encoded(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
        fun event(
            kind: VoiceSignalKind, n: Int, call: ByteArray = CALL,
            expiry: Long = NOW + 60,
        ) = VoiceSignalPlaintext(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = id(n),
            callId = call.copyOf(),
            sentAtEpochSeconds = NOW,
            expiresAtEpochSeconds = expiry,
            kind = kind,
            payload = byteArrayOf(),
        )
    }
}
