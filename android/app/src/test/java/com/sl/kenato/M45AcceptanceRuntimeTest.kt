package com.sl.kenato

import com.sl.kenato.contact.PinnedContact
import com.sl.kenato.contact.ShareableInvite
import com.sl.kenato.identity.IdentityBundle
import com.sl.kenato.identity.OneTimePreKey
import com.sl.kenato.identity.SignedPreKey
import com.sl.kenato.messaging.MessagingConversationDeliveryState
import com.sl.kenato.messaging.MessagingConversationDirection
import com.sl.kenato.messaging.MessagingConversationMessage
import com.sl.kenato.messaging.MessagingConversationState
import com.sl.kenato.messaging.MessagingWssState
import com.sl.kenato.session.EstablishedSession
import com.sl.kenato.session.SessionBootstrapRole
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class M45AcceptanceRuntimeTest {
    @Test
    fun serviceOriginRequiresExactHttpsOrigin() {
        assertEquals("https://example.com/", M45ServiceOrigin.parse(" https://EXAMPLE.com ").toString())
        assertEquals("https://example.com:8443/", M45ServiceOrigin.parse("https://example.com:8443/").toString())

        listOf(
            "",
            "http://example.com",
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com/?query=1",
            "https://example.com/#fragment",
        ).forEach { invalid ->
            assertThrows(IllegalArgumentException::class.java) {
                M45ServiceOrigin.parse(invalid)
            }
        }
    }

    @Test
    fun identityIdDecoderRequiresCanonicalThirtyTwoByteBase64Url() {
        val expected = ByteArray(32) { index -> (index + 1).toByte() }
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(expected)

        assertArrayEquals(expected, decodeM45IdentityId(encoded))
        assertThrows(IllegalArgumentException::class.java) { decodeM45IdentityId("$encoded=") }
        assertThrows(IllegalArgumentException::class.java) {
            decodeM45IdentityId(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(31)))
        }
    }

    @Test
    fun creatorFlowPausesTransportMaintainsBootstrapThenRestarts() {
        val fixture = Fixture()
        val runtime = fixture.runtime()

        runtime.startMessaging()
        fixture.events.clear()

        val invite = runtime.createInvite()

        assertEquals("kenato://invite/test", invite.uri)
        assertEquals(
            listOf(
                "messaging.stop",
                "identity.load",
                "contacts.publish",
                "sessions.maintain",
                "contacts.create",
                "messaging.start",
            ),
            fixture.events,
        )
        assertTrue(fixture.messaging.started)
    }

    @Test
    fun redeemerFlowPinsBeforeEstablishingOutboundSession() {
        val fixture = Fixture()
        val runtime = fixture.runtime()

        val pin = runtime.redeemAndEstablish("kenato://invite/test")

        assertArrayEquals(fixture.pin.localId, pin.localId)
        assertEquals(
            listOf(
                "identity.load",
                "contacts.redeem",
                "sessions.outbound",
            ),
            fixture.events,
        )
        assertArrayEquals(fixture.pin.localId, requireNotNull(fixture.sessions.outboundLocalContactId))
    }

    @Test
    fun creatorClaimUsesSessionClaimBoundaryNotSeparateM2Claim() {
        val fixture = Fixture()
        val runtime = fixture.runtime()

        val established = runtime.claimAndEstablish("kenato://invite/test")

        assertEquals(SessionBootstrapRole.RESPONDER, established.role)
        assertEquals(
            listOf(
                "identity.load",
                "sessions.claim",
            ),
            fixture.events,
        )
    }

    @Test
    fun failedTrustMutationLeavesMessagingStopped() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        runtime.startMessaging()
        fixture.events.clear()
        fixture.sessions.failMaintain = true

        assertThrows(IllegalStateException::class.java) {
            runtime.createInvite()
        }

        assertEquals(
            listOf(
                "messaging.stop",
                "identity.load",
                "contacts.publish",
                "sessions.maintain",
            ),
            fixture.events,
        )
        assertFalse(fixture.messaging.started)
    }

    @Test
    fun runtimeCloseStillReleasesBoundaryWhenStopFails() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        runtime.startMessaging()
        fixture.events.clear()
        val failure = IllegalStateException("simulated stop failure")
        fixture.messaging.stopFailure = failure
        val actual = assertThrows(IllegalStateException::class.java) { runtime.close() }
        assertTrue(actual === failure)
        assertEquals(listOf("messaging.stop", "messaging.close"), fixture.events)
        assertFalse(fixture.messaging.started)
    }

    @Test
    fun runtimeClosePreservesDistinctStopAndReleaseFailures() {
        val fixture = Fixture()
        val failure = IllegalStateException("simulated stop failure")
        val secondary = IllegalArgumentException("simulated release failure")
        fixture.messaging.stopFailure = failure
        fixture.messaging.closeFailure = secondary
        val actual = assertThrows(IllegalStateException::class.java) { fixture.runtime().close() }
        assertTrue(actual === failure)
        assertEquals(listOf(secondary), actual.suppressed.toList())
        assertEquals(listOf("messaging.stop", "messaging.close"), fixture.events)
    }

    @Test
    fun resourceCloseDoesNotSuppressTheSameThrowableInstance() {
        val failure = IllegalStateException("shared teardown failure")
        var releaseAttempted = false
        val actual = assertThrows(IllegalStateException::class.java) {
            closeM45Resources({ throw failure }, {
                releaseAttempted = true
                throw failure
            })
        }
        assertTrue(releaseAttempted)
        assertTrue(actual === failure)
        assertTrue(actual.suppressed.isEmpty())
    }

    @Test
    fun resourceCloseReportsReleaseFailureAndAttemptsBothSteps() {
        val events = ArrayList<String>()
        val failure = IllegalStateException("simulated release failure")
        val actual = assertThrows(IllegalStateException::class.java) {
            closeM45Resources({ events += "stop" }, {
                events += "release"
                throw failure
            })
        }
        assertEquals(listOf("stop", "release"), events)
        assertTrue(actual === failure)
    }

    @Test
    fun resourceCloseRunsBothStepsInOrderOnSuccess() {
        val events = ArrayList<String>()
        closeM45Resources({ events += "stop" }, { events += "release" })
        assertEquals(listOf("stop", "release"), events)
    }

    @Test
    fun secondRuntimeCannotStartOrStageWorkUntilFirstStops() {
        val gate = M45ProcessTransportGate()
        val first = Fixture()
        val second = Fixture()
        val owner = first.runtime(gate)
        val other = second.runtime(gate)
        owner.startMessaging()
        assertThrows(IllegalStateException::class.java) { other.startMessaging() }
        assertThrows(IllegalStateException::class.java) { other.createInvite() }
        assertThrows(IllegalStateException::class.java) { other.currentIdentity() }
        assertThrows(IllegalStateException::class.java) {
            other.sendText(ByteArray(32), "blocked")
        }
        assertTrue(second.events.isEmpty())
        owner.stopMessaging()
        other.startMessaging()
        assertTrue(second.messaging.started)
        owner.close()
        assertTrue(second.messaging.started)
        other.close()
    }

    @Test
    fun partialStartIsStoppedBeforeAnotherRuntimeMayStart() {
        val gate = M45ProcessTransportGate()
        val first = Fixture()
        val second = Fixture()
        val owner = first.runtime(gate)
        val other = second.runtime(gate)
        val failure = IllegalStateException("simulated partial start")
        first.messaging.startFailure = failure
        assertTrue(assertThrows(IllegalStateException::class.java) { owner.startMessaging() } === failure)
        assertFalse(first.messaging.started)
        assertEquals(listOf("identity.load", "messaging.start", "messaging.stop"), first.events)
        other.startMessaging()
        assertTrue(second.messaging.started)
        other.close()
        owner.close()
    }

    @Test
    fun uncertainStopPoisonsProcessAndAbortsTrustMutationBeforeStoreAccess() {
        val gate = M45ProcessTransportGate()
        val first = Fixture()
        val second = Fixture()
        val owner = first.runtime(gate)
        val other = second.runtime(gate)
        owner.startMessaging()
        first.events.clear()
        val failure = IllegalStateException("simulated uncertain stop")
        first.messaging.stopFailure = failure
        assertTrue(assertThrows(IllegalStateException::class.java) { owner.createInvite() } === failure)
        assertEquals(listOf("messaging.stop", "messaging.close"), first.events)
        assertEquals(MessagingWssState.FAILED, owner.messagingState())
        assertThrows(IllegalStateException::class.java) { owner.stopMessaging() }
        assertThrows(IllegalStateException::class.java) { other.startMessaging() }
        assertThrows(IllegalStateException::class.java) { other.createInvite() }
        assertTrue(second.events.isEmpty())
        owner.close()
        other.close()
    }

    @Test
    fun uncertainCloseCannotBeBypassedByNewRuntime() {
        val gate = M45ProcessTransportGate()
        val first = Fixture()
        val owner = first.runtime(gate)
        owner.startMessaging()
        first.messaging.stopFailure = IllegalStateException("uncertain shutdown")
        assertThrows(IllegalStateException::class.java) { owner.close() }
        owner.close()
        val second = Fixture()
        assertThrows(IllegalStateException::class.java) { second.runtime(gate).startMessaging() }
        assertTrue(second.events.isEmpty())
    }

    @Test
    fun successfullyClosedRuntimeCannotRestartOrTouchTrustState() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        runtime.close()
        fixture.events.clear()
        assertThrows(IllegalStateException::class.java) { runtime.startMessaging() }
        assertThrows(IllegalStateException::class.java) { runtime.createInvite() }
        assertThrows(IllegalStateException::class.java) { runtime.initializeIdentity() }
        assertTrue(fixture.events.isEmpty())
        runtime.stopMessaging()
        runtime.close()
        assertTrue(fixture.events.isEmpty())
    }

    @Test
    fun callbackAuthorityDoesNotSurviveStopRestartOrPoison() {
        val gate = M45ProcessTransportGate()
        val owner = Any()
        val other = Any()
        val beforeStart = gate.captureCallbackPermission(owner)
        gate.claim(owner)
        val first = gate.captureCallbackPermission(owner)
        val wrongOwner = gate.captureCallbackPermission(other)
        assertTrue(first())
        assertFalse(beforeStart())
        assertFalse(wrongOwner())
        gate.suspendCallbacks(owner)
        assertFalse(first())
        gate.release(owner)
        gate.claim(owner)
        val second = gate.captureCallbackPermission(owner)
        assertFalse(first())
        assertTrue(second())
        gate.poison()
        assertFalse(second())
        gate.release(owner)
        assertThrows(IllegalStateException::class.java) { gate.claim(other) }
    }

    @Test
    fun controllerLocalGrantsUseActiveOwnerAndFenceStartsWithoutDisconnectingM4() {
        val gate = M45ProcessTransportGate()
        val first = Fixture()
        val owner = first.runtime(gate)
        val other = Fixture().runtime(gate)
        owner.startMessaging()
        first.events.clear()
        val before = gate.mutationEpoch
        val result = owner.localTrustMutation {
            assertEquals(before + 1L, gate.mutationEpoch)
            "local proof"
        }
        assertEquals("local proof", result)
        assertEquals(before + 2L, gate.mutationEpoch)
        assertTrue(first.messaging.started)
        assertTrue(first.events.isEmpty())
        assertThrows(IllegalStateException::class.java) {
            other.localTrustMutation { throw AssertionError("Competing grant must not execute") }
        }
        assertThrows(IllegalStateException::class.java) {
            gate.localTrustMutation(Any()) { throw AssertionError("Offline competing grant must not execute") }
        }
        owner.close()
        other.close()
    }

    @Test
    fun offlineGrantNeedsNoRuntimeAndFailureStillClosesMutationEpoch() {
        val gate = M45ProcessTransportGate()
        val failure = IllegalStateException("synthetic grant failure")
        val owner = Any()
        assertTrue(assertThrows(IllegalStateException::class.java) {
            gate.localTrustMutation(owner) {
                assertEquals(1L, gate.mutationEpoch)
                throw failure
            }
        } === failure)
        assertEquals(2L, gate.mutationEpoch)
        assertEquals("offline", gate.localTrustMutation(owner) { "offline" })
        assertEquals(4L, gate.mutationEpoch)
    }

    @Test
    fun snapshotConversationAdmissionRejectsCompetingClosedAndPoisonedRuntime() {
        val gate = M45ProcessTransportGate()
        val owner = Fixture().runtime(gate)
        val other = Fixture().runtime(gate)
        val localOwner = Any()
        assertTrue(gate.isAvailable(localOwner))
        assertTrue(other.canReadConversation())
        owner.startMessaging()
        assertTrue(owner.canReadConversation())
        assertFalse(other.canReadConversation())
        assertFalse(gate.isAvailable(localOwner))
        assertEquals("revoked", gate.localRevocation { "revoked" })
        assertFalse(other.canReadConversation())
        owner.close()
        assertFalse(owner.canReadConversation())
        assertTrue(other.canReadConversation())
        assertTrue(gate.isAvailable(localOwner))
        gate.poison()
        assertFalse(other.canReadConversation())
        assertFalse(gate.isAvailable(localOwner))
        other.close()
    }

    @Test
    fun localRevocationDoesNotRequireHealthyOrOwnedTransport() {
        val gate = M45ProcessTransportGate()
        val first = Fixture()
        val owner = first.runtime(gate)
        owner.startMessaging()
        first.events.clear()
        val before = gate.mutationEpoch
        assertEquals("revoked", gate.localRevocation {
            assertEquals(before + 1L, gate.mutationEpoch)
            "revoked"
        })
        assertEquals(before + 2L, gate.mutationEpoch)
        assertTrue(first.messaging.started)
        assertTrue(first.events.isEmpty())
        gate.poison()
        var attempts = 0
        val failure = IllegalStateException("synthetic local persistence failure")
        assertTrue(assertThrows(IllegalStateException::class.java) {
            gate.localRevocation {
                attempts++
                throw failure
            }
        } === failure)
        gate.localRevocation { attempts++ }
        assertEquals(2, attempts)
        assertEquals(before + 6L, gate.mutationEpoch)
        assertTrue(gate.isPoisoned())
        assertThrows(IllegalStateException::class.java) {
            owner.localTrustMutation { throw AssertionError("Poisoned grant must not execute") }
        }
        owner.close()
    }

    private class Fixture {
        val events = ArrayList<String>()
        val identity = FakeIdentity(events)
        val pin = PinnedContact(
            localId = ByteArray(16) { 0x11 },
            identityId = ByteArray(32) { 0x22 },
            identityPublicKey = byteArrayOf(1, 2, 3),
            pinnedAtEpochSeconds = 1_000,
        )
        val contacts = FakeContacts(events, pin)
        val sessions = FakeSessions(events, pin)
        val messaging = FakeMessaging(events)

        fun runtime(gate: M45ProcessTransportGate = M45ProcessTransportGate()) =
            M45AcceptanceRuntime(identity, contacts, sessions, messaging, gate)
    }

    private class FakeIdentity(
        private val events: MutableList<String>,
    ) : M45IdentityBoundary {
        private val bundle = IdentityBundle(
            identityId = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 0x33 }),
            identityPublicKey = "AQ",
            signedPreKey = SignedPreKey(
                id = 1,
                publicKey = "Ag",
                signature = "Aw",
                createdAtEpochSeconds = 1,
            ),
            oneTimePreKeys = listOf(
                OneTimePreKey(
                    id = 2,
                    publicKey = "BA",
                    createdAtEpochSeconds = 1,
                ),
            ),
        )

        override fun loadOrCreate(): IdentityBundle {
            events += "identity.load"
            return bundle
        }

        override fun current(): IdentityBundle? = bundle
    }

    private class FakeContacts(
        private val events: MutableList<String>,
        private val pin: PinnedContact,
    ) : M45ContactBoundary {
        override fun publishIdentity() {
            events += "contacts.publish"
        }

        override fun createInvite(): ShareableInvite {
            events += "contacts.create"
            return ShareableInvite(
                uri = "kenato://invite/test",
                qrPayload = "kenato://invite/test",
                expiresAtEpochSeconds = 2_000,
            )
        }

        override fun redeemInvite(uri: String): PinnedContact {
            events += "contacts.redeem"
            return pin
        }

        override fun pendingInvites(): List<ShareableInvite> = emptyList()

        override fun contacts(): List<PinnedContact> = listOf(pin)
    }

    private class FakeSessions(
        private val events: MutableList<String>,
        private val pin: PinnedContact,
    ) : M45SessionBoundary {
        var failMaintain = false
        var outboundLocalContactId: ByteArray? = null

        override fun maintainBootstrap() {
            events += "sessions.maintain"
            if (failMaintain) throw IllegalStateException("simulated bootstrap failure")
        }

        override fun establishOutbound(
            inviteUri: String,
            localContactId: ByteArray,
        ): EstablishedSession {
            events += "sessions.outbound"
            outboundLocalContactId = localContactId.copyOf()
            return EstablishedSession(
                localContactId = localContactId.copyOf(),
                peerIdentityId = pin.identityId.copyOf(),
                localAccountGeneration = 1,
                peerAccountGeneration = 1,
                role = SessionBootstrapRole.INITIATOR,
            )
        }

        override fun claimInbound(inviteUri: String): EstablishedSession {
            events += "sessions.claim"
            return EstablishedSession(
                localContactId = pin.localId.copyOf(),
                peerIdentityId = pin.identityId.copyOf(),
                localAccountGeneration = 1,
                peerAccountGeneration = 1,
                role = SessionBootstrapRole.RESPONDER,
            )
        }
    }

    private class FakeMessaging(
        private val events: MutableList<String>,
    ) : M45MessagingBoundary {
        var started = false
        var startFailure: Throwable? = null
        var stopFailure: Throwable? = null
        var closeFailure: Throwable? = null

        override fun start() {
            events += "messaging.start"
            started = true
            startFailure?.let { throw it }
        }

        override fun stop() {
            events += "messaging.stop"
            stopFailure?.let { throw it }
            started = false
        }

        override fun currentState(): MessagingWssState =
            if (started) MessagingWssState.AUTHENTICATED else MessagingWssState.STOPPED

        override fun sendText(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            text: String,
        ): MessagingConversationMessage = MessagingConversationMessage(
            messageId = "message",
            direction = MessagingConversationDirection.OUTBOUND,
            deliveryState = MessagingConversationDeliveryState.PENDING_SEND,
            sentAtEpochSeconds = 1,
            expiresAtEpochSeconds = 2,
            text = text,
        )

        override fun conversation(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
        ): MessagingConversationState = MessagingConversationState(
            peerIdentityId = "peer",
            messages = emptyList(),
        )

        override fun close() {
            events += "messaging.close"
            started = false
            closeFailure?.let { throw it }
        }
    }
}
