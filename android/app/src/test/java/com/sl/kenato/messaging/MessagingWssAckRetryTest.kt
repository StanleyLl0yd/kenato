package com.sl.kenato.messaging

import java.net.URI
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingWssAckRetryTest {
    @Test
    fun recoveredAckRetryLaterBacksOffOnSameSocketWithoutReconnect() {
        val fixture = Fixture()
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = emptyList(),
            inboundAcks = listOf(MessagingRecoveredAck(PEER.copyOf(), MESSAGE_ID.copyOf())),
        )
        val socket = fixture.authenticate()
        assertEquals(2, socket.sent.size)

        socket.serverFrame(
            MessagingServerFrame(
                error = MessagingWireError(MESSAGING_ERROR_RETRY_LATER, MESSAGE_ID.copyOf()),
            ),
        )

        assertEquals(MessagingWssState.AUTHENTICATED, fixture.coordinator.currentState())
        assertFalse(socket.cancelled)
        assertEquals(listOf(1_000L), fixture.scheduler.pendingDelays())

        fixture.scheduler.runNext()

        assertEquals(MessagingWssState.AUTHENTICATED, fixture.coordinator.currentState())
        assertEquals(3, socket.sent.size)
        val retried = MessagingWire.decodeClientFrame(socket.sent.last()).ack!!
        assertArrayEquals(PEER, retried.senderIdentityId)
        assertArrayEquals(MESSAGE_ID, retried.messageId)

        socket.serverFrame(
            MessagingServerFrame(
                error = MessagingWireError(MESSAGING_ERROR_RETRY_LATER, MESSAGE_ID.copyOf()),
            ),
        )
        assertEquals(listOf(2_000L), fixture.scheduler.pendingDelays())
    }

    @Test
    fun ackRetryLaterStopsAutomaticRetriesAfterEightAttempts() {
        val fixture = Fixture()
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = emptyList(),
            inboundAcks = listOf(MessagingRecoveredAck(PEER.copyOf(), MESSAGE_ID.copyOf())),
        )
        val socket = fixture.authenticate()

        val expected = listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 30_000L, 30_000L, 30_000L)
        expected.forEach { delay ->
            socket.serverFrame(
                MessagingServerFrame(
                    error = MessagingWireError(MESSAGING_ERROR_RETRY_LATER, MESSAGE_ID.copyOf()),
                ),
            )
            assertEquals(listOf(delay), fixture.scheduler.pendingDelays())
            fixture.scheduler.runNext()
        }

        socket.serverFrame(
            MessagingServerFrame(
                error = MessagingWireError(MESSAGING_ERROR_RETRY_LATER, MESSAGE_ID.copyOf()),
            ),
        )

        assertTrue(fixture.scheduler.pendingDelays().isEmpty())
        assertEquals(expected, fixture.scheduler.executedDelays)
        assertEquals(MessagingWssState.AUTHENTICATED, fixture.coordinator.currentState())
        assertFalse(socket.cancelled)
        assertEquals(1, fixture.sockets.created.size)
    }

    @Test
    fun liveDeliveryAckRetryLaterReusesDurableRecoveredAck() {
        val fixture = Fixture()
        val delivery = inboundEnvelope()
        fixture.inbound.onDelivery = {
            fixture.recovery.plan = MessagingRecoveryPlan(
                outboundSends = emptyList(),
                inboundAcks = listOf(MessagingRecoveredAck(PEER.copyOf(), MESSAGE_ID.copyOf())),
            )
        }
        val socket = fixture.authenticate()

        socket.serverFrame(MessagingServerFrame(delivery = delivery))
        val firstAck = MessagingWire.decodeClientFrame(socket.sent.last()).ack!!
        assertArrayEquals(MESSAGE_ID, firstAck.messageId)

        socket.serverFrame(
            MessagingServerFrame(
                error = MessagingWireError(MESSAGING_ERROR_RETRY_LATER, MESSAGE_ID.copyOf()),
            ),
        )
        fixture.scheduler.runNext()

        val retried = MessagingWire.decodeClientFrame(socket.sent.last()).ack!!
        assertArrayEquals(PEER, retried.senderIdentityId)
        assertArrayEquals(MESSAGE_ID, retried.messageId)
        assertFalse(socket.cancelled)
        assertEquals(MessagingWssState.AUTHENTICATED, fixture.coordinator.currentState())
    }

    @Test
    fun uncorrelatedRetryLaterFailsClosed() {
        val fixture = Fixture()
        val socket = fixture.authenticate()

        socket.serverFrame(
            MessagingServerFrame(
                error = MessagingWireError(MESSAGING_ERROR_RETRY_LATER, MESSAGE_ID.copyOf()),
            ),
        )

        assertTrue(socket.cancelled)
        assertEquals(MessagingWssState.FAILED, fixture.coordinator.currentState())
        assertTrue(fixture.scheduler.pendingDelays().isEmpty())
    }

    private class Fixture {
        val sockets = FakeSocketFactory()
        val recovery = FakeRecovery()
        val scheduler = FakeScheduler()
        val inbound = FakeInbound()
        val coordinator = MessagingWssCoordinator(
            serviceOrigin = URI("https://example.test/"),
            sockets = sockets,
            identity = FakeIdentity(),
            recovery = recovery,
            inbound = inbound,
            scheduler = scheduler,
            clock = MessagingWssClock { NOW },
        )

        fun authenticate(): FakeSocket {
            coordinator.start()
            val socket = sockets.latest
            socket.open()
            socket.serverFrame(
                MessagingServerFrame(
                    authChallenge = MessagingAuthChallenge(CHALLENGE.copyOf(), NOW + 20),
                ),
            )
            socket.serverFrame(MessagingServerFrame(authenticated = true))
            return socket
        }
    }

    private class FakeSocketFactory : MessagingSocketFactory {
        val created = ArrayList<FakeSocket>()
        val latest: FakeSocket get() = created.last()

        override fun create(url: String, listener: MessagingSocketListener): MessagingSocket =
            FakeSocket(listener).also(created::add)
    }

    private class FakeSocket(
        private val listener: MessagingSocketListener,
    ) : MessagingSocket {
        val sent = ArrayList<ByteArray>()
        var cancelled = false

        override fun connect() = Unit

        override fun sendBinary(value: ByteArray): Boolean {
            if (cancelled) return false
            sent += value.copyOf()
            return true
        }

        override fun cancel() {
            cancelled = true
        }

        fun open() = listener.onOpen(this)

        fun serverFrame(frame: MessagingServerFrame) =
            listener.onBinaryMessage(this, MessagingWire.encodeServerFrame(frame))
    }

    private class FakeIdentity : MessagingIdentityAuthenticator {
        override fun identityId(): ByteArray = OWNER.copyOf()

        override fun signProtocolPayload(payload: ByteArray): ByteArray = byteArrayOf(0x30, 0x01, 0x01)
    }

    private class FakeRecovery : MessagingRecoveryDriver {
        var plan = MessagingRecoveryPlan(emptyList(), emptyList())

        override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan = plan

        override fun expireOutboundIfDue(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
            nowEpochSeconds: Long,
        ): Boolean = false

        override fun recordSendAccepted(
            ownerIdentityId: ByteArray,
            accepted: MessagingSendAccepted,
        ) = Unit
    }

    private class FakeInbound : MessagingInboundDeliveryHandler {
        var onDelivery: () -> Unit = {}

        override fun handle(
            envelope: MessagingEnvelope,
            receivedAtEpochSeconds: Long,
        ): MessagingDeliveryAck {
            onDelivery()
            return MessagingDeliveryAck(
                senderIdentityId = envelope.senderIdentityId.copyOf(),
                messageId = envelope.messageId.copyOf(),
            )
        }
    }

    private class FakeScheduler : MessagingRetryScheduler {
        private val tasks = ArrayList<Task>()
        val executedDelays = ArrayList<Long>()

        override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask =
            Task(delayMillis, task).also(tasks::add)

        fun pendingDelays(): List<Long> =
            tasks.filterNot { it.cancelled || it.executed }.map { it.delayMillis }

        fun runNext() {
            val task = tasks.firstOrNull { !it.cancelled && !it.executed } ?: return
            task.executed = true
            executedDelays += task.delayMillis
            task.block()
        }

        private class Task(
            val delayMillis: Long,
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
        private const val NOW = 100L
        private val OWNER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x11 }
        private val PEER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x22 }
        private val MESSAGE_ID = ByteArray(MESSAGING_MESSAGE_ID_BYTES) { 0x33 }
        private val CHALLENGE = ByteArray(MESSAGING_AUTH_CHALLENGE_BYTES) { 0x44 }

        private fun inboundEnvelope(): MessagingEnvelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = MESSAGE_ID.copyOf(),
            ciphertext = byteArrayOf(1, 2, 3, 4),
            expiresAtEpochSeconds = 200,
        )
    }
}
