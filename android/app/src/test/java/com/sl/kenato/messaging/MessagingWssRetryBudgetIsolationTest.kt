package com.sl.kenato.messaging

import java.net.URI
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingWssRetryBudgetIsolationTest {
    @Test
    fun ackOnlyDisconnectUsesOrdinaryRetryBudgetAcrossSuccessfulReauth() {
        val fixture = Fixture()
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = emptyList(),
            inboundAcks = listOf(MessagingRecoveredAck(PEER.copyOf(), MESSAGE_ID.copyOf())),
        )

        val first = fixture.authenticateCurrentSocket()
        first.serverClosed()

        assertTrue(first.cancelled)
        assertEquals(MessagingWssState.RETRY_WAIT, fixture.coordinator.currentState())
        assertEquals(listOf(1_000L), fixture.scheduler.pendingDelays())

        fixture.scheduler.runNext()
        val second = fixture.authenticateCurrentSocket()
        second.serverClosed()

        assertTrue(second.cancelled)
        assertEquals(MessagingWssState.RETRY_WAIT, fixture.coordinator.currentState())
        assertEquals(listOf(1_000L), fixture.scheduler.pendingDelays())
    }

    @Test
    fun terminalizedExpiredSendDoesNotConsumeRetryBudgetForNextMessage() {
        val fixture = Fixture()
        val firstEnvelope = outboundEnvelope(MESSAGE_ID)
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    PEER.copyOf(),
                    MESSAGE_ID.copyOf(),
                    MessagingWire.encodeEnvelope(firstEnvelope),
                ),
            ),
            inboundAcks = emptyList(),
        )

        val first = fixture.authenticateCurrentSocket()
        first.serverClosed()
        assertEquals(listOf(1_000L), fixture.scheduler.pendingDelays())

        fixture.scheduler.runNext()
        fixture.recovery.expireAllOutbound = true
        val second = fixture.authenticateCurrentSocket()
        assertEquals(MessagingWssState.AUTHENTICATED, fixture.coordinator.currentState())
        assertTrue(fixture.recovery.plan.outboundSends.isEmpty())

        fixture.recovery.expireAllOutbound = false
        val nextId = NEXT_MESSAGE_ID.copyOf()
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    PEER.copyOf(),
                    nextId.copyOf(),
                    MessagingWire.encodeEnvelope(outboundEnvelope(nextId)),
                ),
            ),
            inboundAcks = emptyList(),
        )
        fixture.coordinator.flushDurableWork()
        second.serverClosed()

        assertTrue(second.cancelled)
        assertEquals(MessagingWssState.RETRY_WAIT, fixture.coordinator.currentState())
        assertEquals(listOf(1_000L), fixture.scheduler.pendingDelays())
    }

    private class Fixture {
        val sockets = FakeSocketFactory()
        val recovery = FakeRecovery()
        val scheduler = FakeScheduler()
        val coordinator = MessagingWssCoordinator(
            serviceOrigin = URI("https://example.test/"),
            sockets = sockets,
            identity = FakeIdentity(),
            recovery = recovery,
            inbound = MessagingInboundDeliveryHandler { _, _ -> null },
            scheduler = scheduler,
            clock = MessagingWssClock { NOW },
        )

        fun authenticateCurrentSocket(): FakeSocket {
            if (sockets.created.isEmpty()) coordinator.start()
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

        fun serverClosed() = listener.onClosed(this)
    }

    private class FakeIdentity : MessagingIdentityAuthenticator {
        override fun identityId(): ByteArray = OWNER.copyOf()

        override fun signProtocolPayload(payload: ByteArray): ByteArray = byteArrayOf(0x30, 0x01, 0x01)
    }

    private class FakeRecovery : MessagingRecoveryDriver {
        var plan = MessagingRecoveryPlan(emptyList(), emptyList())
        var expireAllOutbound = false

        override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan = plan

        override fun expireOutboundIfDue(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
            nowEpochSeconds: Long,
        ): Boolean {
            if (!expireAllOutbound) return false
            plan = plan.copy(
                outboundSends = plan.outboundSends.filterNot {
                    it.peerIdentityId.contentEquals(peerIdentityId) &&
                        it.messageId.contentEquals(messageId)
                },
            )
            return true
        }

        override fun recordSendAccepted(
            ownerIdentityId: ByteArray,
            accepted: MessagingSendAccepted,
        ) = Unit
    }

    private class FakeScheduler : MessagingRetryScheduler {
        private val tasks = ArrayList<Task>()

        override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask =
            Task(delayMillis, task).also(tasks::add)

        fun pendingDelays(): List<Long> =
            tasks.filterNot { it.cancelled || it.executed }.map { it.delayMillis }

        fun runNext() {
            val task = tasks.firstOrNull { !it.cancelled && !it.executed } ?: return
            task.executed = true
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
        private val NEXT_MESSAGE_ID = ByteArray(MESSAGING_MESSAGE_ID_BYTES) { 0x35 }
        private val CHALLENGE = ByteArray(MESSAGING_AUTH_CHALLENGE_BYTES) { 0x44 }

        private fun outboundEnvelope(messageId: ByteArray): MessagingEnvelope = MessagingEnvelope(
            senderIdentityId = OWNER.copyOf(),
            recipientIdentityId = PEER.copyOf(),
            messageId = messageId.copyOf(),
            ciphertext = byteArrayOf(1, 2, 3, 4),
            expiresAtEpochSeconds = 200,
        )
    }
}
