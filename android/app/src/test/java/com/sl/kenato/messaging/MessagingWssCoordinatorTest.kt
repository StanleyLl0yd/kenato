package com.sl.kenato.messaging

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI

class MessagingWssCoordinatorTest {
    @Test
    fun startUsesExactWssEndpointAndOnlyOneActiveSocket() {
        val fixture = Fixture()

        fixture.coordinator.start()
        fixture.coordinator.start()

        assertEquals(listOf("wss://example.test/v1/messaging/ws"), fixture.sockets.urls)
        assertEquals(1, fixture.sockets.created.size)
        assertEquals(1, fixture.sockets.latest.connectCount)
        assertEquals(MessagingWssState.CONNECTING, fixture.coordinator.currentState())
    }

    @Test
    fun authenticationSignsExactCanonicalChallengePayload() {
        val fixture = Fixture()
        fixture.coordinator.start()
        val socket = fixture.sockets.latest
        socket.open()
        val challenge = MessagingAuthChallenge(CHALLENGE.copyOf(), 120)

        socket.serverFrame(MessagingServerFrame(authChallenge = challenge))

        assertEquals(MessagingWssState.AWAITING_AUTHENTICATED, fixture.coordinator.currentState())
        assertArrayEquals(
            MessagingProtocol.authPayload(OWNER, CHALLENGE, 120),
            fixture.identity.lastPayload,
        )
        val auth = MessagingWire.decodeClientFrame(socket.sent.single()).authResponse!!
        assertArrayEquals(OWNER, auth.identityId)
        assertArrayEquals(CHALLENGE, auth.challenge)
        assertEquals(120, auth.expiresAtEpochSeconds)
        assertArrayEquals(SIGNATURE, auth.signature)
    }

    @Test
    fun authenticatedConnectionReplaysExactDurableSendAndPendingAck() {
        val fixture = Fixture()
        val envelope = outboundEnvelope(1)
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    PEER.copyOf(),
                    envelope.messageId.copyOf(),
                    MessagingWire.encodeEnvelope(envelope),
                ),
            ),
            inboundAcks = listOf(MessagingRecoveredAck(PEER.copyOf(), messageId(2))),
        )
        val socket = fixture.authenticate()

        assertEquals(MessagingWssState.AUTHENTICATED, fixture.coordinator.currentState())
        assertEquals(3, socket.sent.size)
        val send = MessagingWire.decodeClientFrame(socket.sent[1]).send!!
        assertArrayEquals(MessagingWire.encodeEnvelope(envelope), MessagingWire.encodeEnvelope(send))
        val ack = MessagingWire.decodeClientFrame(socket.sent[2]).ack!!
        assertArrayEquals(PEER, ack.senderIdentityId)
        assertArrayEquals(messageId(2), ack.messageId)
    }

    @Test
    fun expiredRecoveredSendIsTerminalizedBeforeSocketQueueing() {
        val fixture = Fixture()
        val envelope = outboundEnvelope(1)
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    PEER.copyOf(),
                    envelope.messageId.copyOf(),
                    MessagingWire.encodeEnvelope(envelope),
                ),
            ),
            inboundAcks = emptyList(),
        )
        fixture.recovery.expiredMessageIds += envelope.messageId.copyOf()

        val socket = fixture.authenticate()

        assertEquals(MessagingWssState.AUTHENTICATED, fixture.coordinator.currentState())
        assertEquals(1, socket.sent.size)
        assertEquals(1, fixture.recovery.expiryChecks.size)
        assertArrayEquals(envelope.messageId, fixture.recovery.expiryChecks.single())
        assertTrue(fixture.recovery.plan.outboundSends.isEmpty())
    }

    @Test
    fun sendAcceptedIsCommittedAndDoesNotResendAcceptedMessage() {
        val fixture = Fixture()
        val envelope = outboundEnvelope(1)
        fixture.recovery.plan = MessagingRecoveryPlan(
            listOf(MessagingRecoveredSend(PEER.copyOf(), envelope.messageId.copyOf(), MessagingWire.encodeEnvelope(envelope))),
            emptyList(),
        )
        val socket = fixture.authenticate()
        assertEquals(2, socket.sent.size)

        socket.serverFrame(
            MessagingServerFrame(
                sendAccepted = MessagingSendAccepted(PEER.copyOf(), envelope.messageId.copyOf()),
            ),
        )

        assertEquals(1, fixture.recovery.accepted.size)
        assertEquals(2, socket.sent.size)
    }

    @Test
    fun authenticatedDeliveryRevalidatesAndReacksDuplicateDelivery() {
        val fixture = Fixture()
        val delivery = inboundEnvelope(3)
        fixture.inbound.result = MessagingDeliveryAck(PEER.copyOf(), delivery.messageId.copyOf())
        val socket = fixture.authenticate()

        socket.serverFrame(MessagingServerFrame(delivery = delivery))
        socket.serverFrame(MessagingServerFrame(delivery = delivery))

        assertEquals(2, fixture.inbound.deliveries.size)
        assertEquals(3, socket.sent.size)
        socket.sent.drop(1).forEach { encoded ->
            val ack = MessagingWire.decodeClientFrame(encoded).ack!!
            assertArrayEquals(PEER, ack.senderIdentityId)
            assertArrayEquals(delivery.messageId, ack.messageId)
        }
    }

    @Test
    fun mismatchedDeliveryAckFailsClosedWithoutReconnect() {
        val fixture = Fixture()
        val delivery = inboundEnvelope(3)
        fixture.inbound.result = MessagingDeliveryAck(PEER.copyOf(), messageId(9))
        val socket = fixture.authenticate()

        socket.serverFrame(MessagingServerFrame(delivery = delivery))

        assertTrue(socket.cancelled)
        assertEquals(MessagingWssState.FAILED, fixture.coordinator.currentState())
        assertTrue(fixture.scheduler.pendingDelays().isEmpty())
    }

    @Test
    fun malformedServerFrameFailsClosedWithoutReconnect() {
        val fixture = Fixture()
        fixture.coordinator.start()
        val socket = fixture.sockets.latest
        socket.open()

        socket.rawServerFrame(byteArrayOf(0x01))

        assertTrue(socket.cancelled)
        assertEquals(MessagingWssState.FAILED, fixture.coordinator.currentState())
        assertTrue(fixture.scheduler.pendingDelays().isEmpty())
    }

    @Test
    fun unexpectedAuthenticatedConfirmationFailsClosed() {
        val fixture = Fixture()
        val socket = fixture.authenticate()

        socket.serverFrame(MessagingServerFrame(authenticated = true))

        assertTrue(socket.cancelled)
        assertEquals(MessagingWssState.FAILED, fixture.coordinator.currentState())
        assertTrue(fixture.scheduler.pendingDelays().isEmpty())
    }

    @Test
    fun authenticationTimeoutReconnectsWithBoundedBackoff() {
        val fixture = Fixture()
        fixture.coordinator.start()
        val socket = fixture.sockets.latest
        socket.open()
        assertEquals(listOf(MessagingWssCoordinator.AUTHENTICATION_TIMEOUT_MILLIS), fixture.scheduler.pendingDelays())

        fixture.scheduler.runNext()

        assertTrue(socket.cancelled)
        assertEquals(MessagingWssState.RETRY_WAIT, fixture.coordinator.currentState())
        assertEquals(listOf(1_000L), fixture.scheduler.pendingDelays())
    }

    @Test
    fun rejectedSocketSendReconnectsInsteadOfDroppingDurableWork() {
        val fixture = Fixture()
        fixture.coordinator.start()
        val socket = fixture.sockets.latest
        socket.open()
        socket.acceptSends = false

        socket.serverFrame(MessagingServerFrame(authChallenge = MessagingAuthChallenge(CHALLENGE.copyOf(), 120)))

        assertTrue(socket.cancelled)
        assertEquals(MessagingWssState.RETRY_WAIT, fixture.coordinator.currentState())
        assertEquals(listOf(1_000L), fixture.scheduler.pendingDelays())
    }

    @Test
    fun reconnectBackoffIsBoundedAndStopsAfterEightAutomaticRetries() {
        val fixture = Fixture()
        fixture.coordinator.start()

        repeat(MessagingWssCoordinator.MAX_RECONNECT_ATTEMPTS) {
            fixture.sockets.latest.fail()
            assertEquals(MessagingWssState.RETRY_WAIT, fixture.coordinator.currentState())
            fixture.scheduler.runNext()
        }
        fixture.sockets.latest.fail()

        assertEquals(MessagingWssState.FAILED, fixture.coordinator.currentState())
        assertEquals(
            listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 30_000L, 30_000L, 30_000L),
            fixture.scheduler.executedDelays,
        )
        assertEquals(9, fixture.sockets.created.size)
    }

    @Test
    fun successfulAuthenticationResetsReconnectBudget() {
        val fixture = Fixture()
        fixture.coordinator.start()
        fixture.sockets.latest.fail()
        fixture.scheduler.runNext()
        val socket = fixture.authenticateExisting()
        socket.fail()

        assertEquals(listOf(1_000L), fixture.scheduler.pendingDelays())
    }

    @Test
    fun retryLaterReconnectsButSendRejectedFailsClosed() {
        val retryFixture = Fixture()
        val retrySocket = retryFixture.authenticate()
        retrySocket.serverFrame(
            MessagingServerFrame(error = MessagingWireError(MESSAGING_ERROR_RETRY_LATER)),
        )
        assertEquals(MessagingWssState.RETRY_WAIT, retryFixture.coordinator.currentState())

        val rejectFixture = Fixture()
        val rejectSocket = rejectFixture.authenticate()
        rejectSocket.serverFrame(
            MessagingServerFrame(
                error = MessagingWireError(MESSAGING_ERROR_SEND_REJECTED, messageId(1)),
            ),
        )
        assertEquals(MessagingWssState.FAILED, rejectFixture.coordinator.currentState())
        assertTrue(rejectSocket.cancelled)
        assertTrue(rejectFixture.scheduler.pendingDelays().isEmpty())
    }

    @Test
    fun stopCancelsSocketAndPendingRetry() {
        val fixture = Fixture()
        fixture.coordinator.start()
        fixture.sockets.latest.fail()
        assertFalse(fixture.scheduler.pendingDelays().isEmpty())

        fixture.coordinator.stop()
        fixture.scheduler.runAll()

        assertEquals(MessagingWssState.STOPPED, fixture.coordinator.currentState())
        assertEquals(1, fixture.sockets.created.size)
        assertTrue(fixture.scheduler.pendingDelays().isEmpty())
    }

    @Test
    fun moreThanThirtyTwoRecoveredSendsFailsClosedWithoutSocketQueueGrowth() {
        val fixture = Fixture()
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = (1..MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS + 1).map { index ->
                val envelope = outboundEnvelope(index)
                MessagingRecoveredSend(PEER.copyOf(), envelope.messageId.copyOf(), MessagingWire.encodeEnvelope(envelope))
            },
            inboundAcks = emptyList(),
        )
        val socket = fixture.authenticate()

        assertTrue(socket.cancelled)
        assertEquals(MessagingWssState.FAILED, fixture.coordinator.currentState())
        assertEquals(1, socket.sent.size)
        assertTrue(fixture.scheduler.pendingDelays().isEmpty())
    }

    @Test
    fun nonHttpsServiceOriginIsRejected() {
        assertThrows(MessagingWssException::class.java) {
            Fixture(URI("http://example.test/"))
        }
    }

    private class Fixture(origin: URI = URI("https://example.test/")) {
        val sockets = FakeSocketFactory()
        val identity = FakeIdentity()
        val recovery = FakeRecovery()
        val inbound = FakeInbound()
        val scheduler = FakeScheduler()
        val coordinator = MessagingWssCoordinator(
            serviceOrigin = origin,
            sockets = sockets,
            identity = identity,
            recovery = recovery,
            inbound = inbound,
            scheduler = scheduler,
            clock = MessagingWssClock { 100 },
        )

        fun authenticate(): FakeSocket {
            coordinator.start()
            return authenticateExisting()
        }

        fun authenticateExisting(): FakeSocket {
            val socket = sockets.latest
            socket.open()
            socket.serverFrame(MessagingServerFrame(authChallenge = MessagingAuthChallenge(CHALLENGE.copyOf(), 120)))
            socket.serverFrame(MessagingServerFrame(authenticated = true))
            return socket
        }
    }

    private class FakeSocketFactory : MessagingSocketFactory {
        val urls = ArrayList<String>()
        val created = ArrayList<FakeSocket>()
        val latest: FakeSocket get() = created.last()

        override fun create(url: String, listener: MessagingSocketListener): MessagingSocket {
            urls += url
            return FakeSocket(listener).also(created::add)
        }
    }

    private class FakeSocket(
        private val listener: MessagingSocketListener,
    ) : MessagingSocket {
        val sent = ArrayList<ByteArray>()
        var connectCount = 0
        var cancelled = false
        var acceptSends = true

        override fun connect() {
            connectCount++
        }

        override fun sendBinary(value: ByteArray): Boolean {
            if (cancelled || !acceptSends) return false
            sent += value.copyOf()
            return true
        }

        override fun cancel() {
            cancelled = true
        }

        fun open() = listener.onOpen(this)

        fun serverFrame(frame: MessagingServerFrame) =
            rawServerFrame(MessagingWire.encodeServerFrame(frame))

        fun rawServerFrame(value: ByteArray) = listener.onBinaryMessage(this, value)

        fun fail() = listener.onFailure(this, IllegalStateException("network"))
    }

    private class FakeIdentity : MessagingIdentityAuthenticator {
        var lastPayload = ByteArray(0)

        override fun identityId(): ByteArray = OWNER.copyOf()

        override fun signProtocolPayload(payload: ByteArray): ByteArray {
            lastPayload = payload.copyOf()
            return SIGNATURE.copyOf()
        }
    }

    private class FakeRecovery : MessagingRecoveryDriver {
        var plan = MessagingRecoveryPlan(emptyList(), emptyList())
        val accepted = ArrayList<MessagingSendAccepted>()
        val expiredMessageIds = ArrayList<ByteArray>()
        val expiryChecks = ArrayList<ByteArray>()

        override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan = plan

        override fun expireOutboundIfDue(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
            nowEpochSeconds: Long,
        ): Boolean {
            expiryChecks += messageId.copyOf()
            val expired = expiredMessageIds.any { it.contentEquals(messageId) }
            if (expired) {
                plan = plan.copy(
                    outboundSends = plan.outboundSends.filterNot {
                        it.peerIdentityId.contentEquals(peerIdentityId) &&
                            it.messageId.contentEquals(messageId)
                    },
                )
            }
            return expired
        }

        override fun recordSendAccepted(ownerIdentityId: ByteArray, accepted: MessagingSendAccepted) {
            this.accepted += accepted
            plan = plan.copy(
                outboundSends = plan.outboundSends.filterNot {
                    it.peerIdentityId.contentEquals(accepted.recipientIdentityId) &&
                        it.messageId.contentEquals(accepted.messageId)
                },
            )
        }
    }

    private class FakeInbound : MessagingInboundDeliveryHandler {
        var result: MessagingDeliveryAck? = null
        val deliveries = ArrayList<MessagingEnvelope>()

        override fun handle(envelope: MessagingEnvelope): MessagingDeliveryAck? {
            deliveries += envelope
            return result
        }
    }

    private class FakeScheduler : MessagingRetryScheduler {
        private val tasks = ArrayList<Task>()
        val executedDelays = ArrayList<Long>()

        override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask =
            Task(delayMillis, task).also(tasks::add)

        fun pendingDelays(): List<Long> = tasks.filterNot { it.cancelled || it.executed }.map { it.delay }

        fun runNext() {
            val task = tasks.firstOrNull { !it.cancelled && !it.executed } ?: return
            task.executed = true
            executedDelays += task.delay
            task.block()
        }

        fun runAll() {
            while (tasks.any { !it.cancelled && !it.executed }) runNext()
        }

        private class Task(
            val delay: Long,
            val block: () -> Unit,
        ) : MessagingScheduledTask {
            var cancelled = false
            var executed = false

            override fun cancel() {
                cancelled = true
            }
        }
    }

    companion object {
        private val OWNER = bytes(0x11, MESSAGING_IDENTITY_BYTES)
        private val PEER = bytes(0x22, MESSAGING_IDENTITY_BYTES)
        private val CHALLENGE = bytes(0x44, MESSAGING_AUTH_CHALLENGE_BYTES)
        private val SIGNATURE = byteArrayOf(0x30, 0x01, 0x01)

        private fun outboundEnvelope(index: Int): MessagingEnvelope = MessagingEnvelope(
            senderIdentityId = OWNER.copyOf(),
            recipientIdentityId = PEER.copyOf(),
            messageId = messageId(index),
            ciphertext = "ciphertext-$index".toByteArray(),
            expiresAtEpochSeconds = 200,
        )

        private fun inboundEnvelope(index: Int): MessagingEnvelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = messageId(index),
            ciphertext = "ciphertext-$index".toByteArray(),
            expiresAtEpochSeconds = 200,
        )

        private fun messageId(index: Int): ByteArray = ByteArray(MESSAGING_MESSAGE_ID_BYTES).also {
            it[0] = ((index ushr 24) and 0xff).toByte()
            it[1] = ((index ushr 16) and 0xff).toByte()
            it[2] = ((index ushr 8) and 0xff).toByte()
            it[3] = (index and 0xff).toByte()
            if (it.all { value -> value == 0.toByte() }) it[0] = 1
        }

        private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
    }
}
