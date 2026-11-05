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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class M45AcceptanceRuntimeTest {
    private fun awaitRuntimeOperationBlocked(thread: Thread, operation: String) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            if (
                thread.state == Thread.State.BLOCKED &&
                thread.stackTrace.any {
                    it.className == M45AcceptanceRuntime::class.java.name &&
                        it.methodName == operation
                }
            ) {
                return
            }
            Thread.yield()
        }
        throw AssertionError("Queued $operation never reached the runtime monitor")
    }

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
    fun activeWssIsPausedAroundBothM3SessionEstablishmentDirections() {
        for (inbound in listOf(false, true)) {
            val fixture = Fixture()
            val runtime = fixture.runtime()
            runtime.startMessaging()
            fixture.events.clear()

            if (inbound) {
                runtime.claimAndEstablish("kenato://invite/test")
            } else {
                runtime.redeemAndEstablish("kenato://invite/test")
            }
            val expected = if (inbound) listOf(
                "messaging.stop", "identity.load", "sessions.claim", "messaging.start",
            ) else listOf(
                "messaging.stop", "identity.load", "contacts.redeem",
                "sessions.outbound", "messaging.start",
            )
            assertEquals(expected, fixture.events)
            assertTrue(fixture.messaging.started)
        }
    }

    @Test
    fun explicitStartCannotResumeWssDuringAnUnfinishedTrustMutation() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val started = CountDownLatch(1)
        fixture.sessions.maintainEntered = entered
        fixture.sessions.maintainRelease = release
        fixture.messaging.startEntered = started
        val workers = Executors.newFixedThreadPool(2)
        try {
            val mutation = workers.submit { runtime.createInvite() }
            assertTrue(entered.await(10, TimeUnit.SECONDS))
            val dispatched = CountDownLatch(1)
            val startThread = AtomicReference<Thread>()
            val explicitStart = workers.submit {
                startThread.set(Thread.currentThread())
                dispatched.countDown()
                runtime.startMessaging()
            }
            assertTrue(dispatched.await(10, TimeUnit.SECONDS))
            awaitRuntimeOperationBlocked(startThread.get(), "startMessaging")
            assertFalse(started.await(250, TimeUnit.MILLISECONDS))
            release.countDown()
            mutation.get(10, TimeUnit.SECONDS)
            assertThrows(java.util.concurrent.ExecutionException::class.java) {
                explicitStart.get(10, TimeUnit.SECONDS)
            }
            assertFalse(fixture.messaging.started)
            runtime.startMessaging()
            assertTrue(started.await(10, TimeUnit.SECONDS))
            assertEquals(
                listOf(
                    "identity.load", "contacts.publish", "sessions.maintain",
                    "contacts.create", "identity.load", "messaging.start",
                ),
                fixture.events,
            )
        } finally {
            release.countDown()
            workers.shutdownNow()
            runtime.close()
        }
    }

    @Test
    fun queuedStartCannotResurrectWssAfterFailedTrustMutation() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val started = CountDownLatch(1)
        fixture.sessions.failMaintain = true
        fixture.sessions.maintainEntered = entered
        fixture.sessions.maintainRelease = release
        fixture.messaging.startEntered = started
        val workers = Executors.newFixedThreadPool(2)
        try {
            val mutation = workers.submit { runtime.createInvite() }
            assertTrue(entered.await(10, TimeUnit.SECONDS))
            val dispatched = CountDownLatch(1)
            val startThread = AtomicReference<Thread>()
            val queuedStart = workers.submit {
                startThread.set(Thread.currentThread())
                dispatched.countDown()
                runtime.startMessaging()
            }
            assertTrue(dispatched.await(10, TimeUnit.SECONDS))
            awaitRuntimeOperationBlocked(startThread.get(), "startMessaging")
            release.countDown()
            assertThrows(java.util.concurrent.ExecutionException::class.java) {
                mutation.get(10, TimeUnit.SECONDS)
            }
            assertThrows(java.util.concurrent.ExecutionException::class.java) {
                queuedStart.get(10, TimeUnit.SECONDS)
            }
            assertFalse(fixture.messaging.started)
            assertFalse(started.await(250, TimeUnit.MILLISECONDS))
            runtime.startMessaging()
            assertTrue(fixture.messaging.started)
        } finally {
            release.countDown()
            workers.shutdownNow()
            runtime.close()
        }
    }

    @Test
    fun partiallyStartedWssIsStoppedBeforeAnyLaterTrustMutation() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        fixture.messaging.failStartAfterActivation = true

        assertThrows(IllegalStateException::class.java) { runtime.startMessaging() }
        assertFalse(fixture.messaging.started)
        assertEquals(
            listOf("identity.load", "messaging.start", "messaging.stop"),
            fixture.events,
        )
        fixture.events.clear()
        runtime.createInvite()
        assertFalse(fixture.messaging.started)
        assertFalse(fixture.events.contains("messaging.start"))
        runtime.close()
    }

    @Test
    fun partiallyStartedWssDuringTrustRestartIsStoppedAndNeedsFreshStart() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        runtime.startMessaging()
        fixture.events.clear()
        fixture.messaging.failStartAfterActivation = true

        assertThrows(IllegalStateException::class.java) { runtime.createInvite() }
        assertFalse(fixture.messaging.started)
        assertEquals(
            listOf(
                "messaging.stop", "identity.load", "contacts.publish",
                "sessions.maintain", "contacts.create", "messaging.start",
                "messaging.stop",
            ),
            fixture.events,
        )
        fixture.messaging.failStartAfterActivation = false
        runtime.startMessaging()
        assertTrue(fixture.messaging.started)
        runtime.close()
    }

    @Test
    fun failedWssStopAbortsMutationAndPermanentlyClosesRuntime() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        runtime.startMessaging()
        fixture.events.clear()
        fixture.messaging.failStopAfterAttempt = true

        assertThrows(IllegalStateException::class.java) { runtime.createInvite() }
        assertEquals(listOf("messaging.stop", "messaging.close"), fixture.events)
        assertFalse(fixture.messaging.started)
        assertThrows(IllegalStateException::class.java) { runtime.startMessaging() }
        assertThrows(IllegalStateException::class.java) { runtime.createInvite() }
        assertThrows(IllegalStateException::class.java) {
            runtime.sendText(ByteArray(32) { 2 }, "not staged")
        }
        runtime.close()
    }

    @Test
    fun partialWssStartAndStopFailureClosesRuntimeWithBothCauses() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        fixture.messaging.failStartAfterActivation = true
        fixture.messaging.failStopAfterAttempt = true

        val failure = assertThrows(IllegalStateException::class.java) {
            runtime.startMessaging()
        }
        assertEquals(1, failure.suppressed.size)
        assertFalse(fixture.messaging.started)
        assertEquals(
            listOf("identity.load", "messaging.start", "messaging.stop", "messaging.close"),
            fixture.events,
        )
        assertThrows(IllegalStateException::class.java) { runtime.startMessaging() }
        runtime.close()
    }

    @Test
    fun selectedPeerIsResolvedInsideTrustGateAfterConcurrentMutation() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val resolverCalled = CountDownLatch(1)
        val selected = AtomicReference(ByteArray(32) { 0x22 })
        fixture.sessions.maintainEntered = entered
        fixture.sessions.maintainRelease = release
        val workers = Executors.newFixedThreadPool(2)
        try {
            val mutation = workers.submit { runtime.createInvite() }
            assertTrue(entered.await(10, TimeUnit.SECONDS))
            val dispatched = CountDownLatch(1)
            val sendThread = AtomicReference<Thread>()
            val send = workers.submit {
                sendThread.set(Thread.currentThread())
                dispatched.countDown()
                runtime.sendTextSelectingPeer({
                    resolverCalled.countDown()
                    selected.get()
                }, "hello")
            }
            assertTrue(dispatched.await(10, TimeUnit.SECONDS))
            awaitRuntimeOperationBlocked(sendThread.get(), "sendTextSelectingPeer")
            assertFalse(resolverCalled.await(250, TimeUnit.MILLISECONDS))
            selected.set(ByteArray(32) { 0x44 })
            release.countDown()
            mutation.get(10, TimeUnit.SECONDS)
            send.get(10, TimeUnit.SECONDS)
            assertEquals(0L, resolverCalled.count)
            assertArrayEquals(selected.get(), fixture.messaging.lastSentPeer)
        } finally {
            release.countDown()
            workers.shutdownNow()
            runtime.close()
        }
    }

    @Test
    fun localConsentMutationPausesActiveWssAndResumesOnlyAfterCommit() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        runtime.startMessaging()
        fixture.events.clear()

        val result = runtime.withLocalTrustMutation {
            assertFalse(fixture.messaging.started)
            fixture.events += "consent.persist"
            "consent committed"
        }

        assertEquals("consent committed", result)
        assertEquals(
            listOf("messaging.stop", "consent.persist", "messaging.start"),
            fixture.events,
        )
        assertTrue(fixture.messaging.started)
        runtime.close()
    }

    @Test
    fun failedWssStopPreventsLocalConsentMutation() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        runtime.startMessaging()
        fixture.messaging.failStopAfterAttempt = true
        var persisted = false

        assertThrows(IllegalStateException::class.java) {
            runtime.withLocalTrustMutation { persisted = true }
        }

        assertFalse(persisted)
        assertThrows(IllegalStateException::class.java) {
            runtime.withLocalTrustMutation { persisted = true }
        }
        runtime.close()
    }

    @Test
    fun standaloneTrustWriteRejectsActiveTransportAndInvalidatesQueuedStart() {
        val gate = M45ProcessTransportGate()
        val owner = Fixture().runtime(gate)
        val other = Fixture().runtime(gate)
        owner.startMessaging()
        var executed = false
        assertThrows(IllegalStateException::class.java) {
            gate.withStandaloneTrustMutation { executed = true }
        }
        assertFalse(executed)
        owner.stopMessaging()

        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val beforeEpoch = gate.mutationEpoch
            val mutation = pool.submit {
                gate.withStandaloneTrustMutation {
                    entered.countDown()
                    assertTrue(release.await(10, TimeUnit.SECONDS))
                }
            }
            assertTrue(entered.await(10, TimeUnit.SECONDS))
            val dispatched = CountDownLatch(1)
            val startThread = AtomicReference<Thread>()
            val queued = pool.submit {
                startThread.set(Thread.currentThread())
                dispatched.countDown()
                other.startMessaging()
            }
            assertTrue(dispatched.await(10, TimeUnit.SECONDS))
            awaitRuntimeOperationBlocked(startThread.get(), "startMessaging")
            release.countDown()
            mutation.get(10, TimeUnit.SECONDS)
            assertEquals(beforeEpoch + 2L, gate.mutationEpoch)
            assertThrows(java.util.concurrent.ExecutionException::class.java) {
                queued.get(10, TimeUnit.SECONDS)
            }
            other.startMessaging()
        } finally {
            release.countDown()
            pool.shutdownNow()
            owner.close()
            other.close()
        }
    }

    @Test
    fun secondRuntimeCannotStartWssOrMutateTrustWhileAnotherOwnsTransport() {
        val gate = M45ProcessTransportGate()
        val first = Fixture()
        val second = Fixture()
        val owner = first.runtime(gate)
        val other = second.runtime(gate)
        try {
            owner.startMessaging()
            assertThrows(IllegalStateException::class.java) { other.startMessaging() }
            assertThrows(IllegalStateException::class.java) { other.createInvite() }
            assertThrows(IllegalStateException::class.java) {
                other.sendText(ByteArray(32) { 2 }, "blocked")
            }
            // Even read-looking entry points may lazily create an M1 identity.
            assertThrows(IllegalStateException::class.java) { other.initializeIdentity() }
            assertThrows(IllegalStateException::class.java) { other.pendingInvites() }
            assertThrows(IllegalStateException::class.java) { other.contacts() }
            assertThrows(IllegalStateException::class.java) {
                other.conversation(ByteArray(32) { 2 })
            }
            assertTrue(second.events.isEmpty())
            owner.stopMessaging()
            other.initializeIdentity()
            assertTrue(other.pendingInvites().isEmpty())
            assertEquals(1, other.contacts().size)
            assertTrue(other.conversation(ByteArray(32) { 2 }).messages.isEmpty())
            other.createInvite()
            assertTrue(second.events.contains("contacts.create"))
        } finally {
            owner.close()
            other.close()
        }
    }

    @Test
    fun queuedStartFromSecondRuntimeIsFencedByFirstRuntimeMutationEpoch() {
        val gate = M45ProcessTransportGate()
        val first = Fixture()
        val second = Fixture()
        val owner = first.runtime(gate)
        val other = second.runtime(gate)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        first.sessions.maintainEntered = entered
        first.sessions.maintainRelease = release
        val started = CountDownLatch(1)
        second.messaging.startEntered = started
        val pool = Executors.newFixedThreadPool(2)
        try {
            val mutation = pool.submit { owner.createInvite() }
            assertTrue(entered.await(10, TimeUnit.SECONDS))
            val dispatched = CountDownLatch(1)
            val startThread = AtomicReference<Thread>()
            val pendingStart = pool.submit {
                startThread.set(Thread.currentThread())
                dispatched.countDown()
                other.startMessaging()
            }
            assertTrue(dispatched.await(10, TimeUnit.SECONDS))
            awaitRuntimeOperationBlocked(startThread.get(), "startMessaging")
            assertFalse(started.await(250, TimeUnit.MILLISECONDS))
            release.countDown()
            mutation.get(10, TimeUnit.SECONDS)
            assertThrows(java.util.concurrent.ExecutionException::class.java) {
                pendingStart.get(10, TimeUnit.SECONDS)
            }
            assertFalse(second.messaging.started)
            other.startMessaging()
            assertTrue(second.messaging.started)
        } finally {
            release.countDown()
            pool.shutdownNow()
            owner.close()
            other.close()
        }
    }

    @Test
    fun uncertainStopPoisonsSharedGateAndDeniesAnotherRuntime() {
        val gate = M45ProcessTransportGate()
        val first = Fixture()
        val second = Fixture()
        val owner = first.runtime(gate)
        val other = second.runtime(gate)
        owner.startMessaging()
        first.messaging.failStopAfterAttempt = true
        assertThrows(IllegalStateException::class.java) { owner.createInvite() }
        assertThrows(IllegalStateException::class.java) { other.startMessaging() }
        assertThrows(IllegalStateException::class.java) { other.createInvite() }
        assertTrue(second.events.isEmpty())
        owner.close()
        other.close()
    }

    @Test
    fun identityReadCannotBypassClosedOrCompetingTransportOwner() {
        val shared = M45ProcessTransportGate()
        val first = Fixture()
        val second = Fixture()
        val owner = first.runtime(shared)
        val other = second.runtime(shared)

        owner.startMessaging()
        assertThrows(IllegalStateException::class.java) { other.currentIdentity() }
        assertEquals(0, second.identity.currentReadCount)

        owner.stopMessaging()
        assertEquals(0, second.identity.currentReadCount)
        assertEquals(second.identity.loadOrCreate(), other.currentIdentity())
        assertEquals(1, second.identity.currentReadCount)

        other.close()
        assertThrows(IllegalStateException::class.java) { other.currentIdentity() }
        assertEquals(1, second.identity.currentReadCount)
        owner.close()
    }

    @Test
    fun poisonedProcessOwnerDeniesIdentityReadsBeforeTouchingStore() {
        val gate = M45ProcessTransportGate()
        val fixture = Fixture()
        val runtime = fixture.runtime(gate)
        gate.poison()
        assertThrows(IllegalStateException::class.java) { runtime.currentIdentity() }
        assertEquals(0, fixture.identity.currentReadCount)
        runtime.close()
    }

    @Test
    fun closedRuntimeCannotRestartWssOrStageNewOutgoingWork() {
        val fixture = Fixture()
        val runtime = fixture.runtime()
        runtime.startMessaging()
        runtime.close()
        assertFalse(fixture.messaging.started)
        assertThrows(IllegalStateException::class.java) { runtime.startMessaging() }
        assertThrows(IllegalStateException::class.java) { runtime.createInvite() }
        assertThrows(IllegalStateException::class.java) {
            runtime.sendText(ByteArray(32) { 2 }, "test")
        }
        assertThrows(IllegalStateException::class.java) { runtime.initializeIdentity() }
        assertThrows(IllegalStateException::class.java) { runtime.pendingInvites() }
        assertThrows(IllegalStateException::class.java) { runtime.contacts() }
        assertThrows(IllegalStateException::class.java) {
            runtime.conversation(ByteArray(32) { 2 })
        }
        runtime.stopMessaging()
        runtime.close()
        assertFalse(fixture.messaging.started)
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

        var currentReadCount = 0
            private set

        override fun current(): IdentityBundle? {
            currentReadCount++
            return bundle
        }
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
        var maintainEntered: CountDownLatch? = null
        var maintainRelease: CountDownLatch? = null
        var outboundLocalContactId: ByteArray? = null

        override fun maintainBootstrap() {
            events += "sessions.maintain"
            maintainEntered?.countDown()
            if (maintainRelease?.await(10, TimeUnit.SECONDS) == false) {
                throw IllegalStateException("simulated bootstrap gate timed out")
            }
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
        var failStartAfterActivation = false
        var failStopAfterAttempt = false
        var startEntered: CountDownLatch? = null
        var lastSentPeer: ByteArray? = null

        override fun start() {
            startEntered?.countDown()
            events += "messaging.start"
            started = true
            if (failStartAfterActivation) {
                throw IllegalStateException("simulated partial WSS start")
            }
        }

        override fun stop() {
            events += "messaging.stop"
            if (failStopAfterAttempt) {
                throw IllegalStateException("simulated failed WSS stop")
            }
            started = false
        }

        override fun currentState(): MessagingWssState =
            if (started) MessagingWssState.AUTHENTICATED else MessagingWssState.STOPPED

        override fun sendText(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            text: String,
        ): MessagingConversationMessage {
            lastSentPeer = peerIdentityId.copyOf()
            return MessagingConversationMessage(
                messageId = "message",
                direction = MessagingConversationDirection.OUTBOUND,
                deliveryState = MessagingConversationDeliveryState.PENDING_SEND,
                sentAtEpochSeconds = 1,
                expiresAtEpochSeconds = 2,
                text = text,
            )
        }

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
        }
    }
}
