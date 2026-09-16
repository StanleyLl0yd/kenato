package com.sl.kenato.messaging

import java.net.URI
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingWssSendAcceptanceTimeoutTest {
    @Test
    fun missingSendAcceptedReconnectsAndReplaysExactEnvelope() {
        val fixture = Fixture()
        val envelope = outboundEnvelope()
        val encodedEnvelope = MessagingWire.encodeEnvelope(envelope)
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    PEER.copyOf(),
                    MESSAGE_ID.copyOf(),
                    encodedEnvelope.copyOf(),
                ),
            ),
            inboundAcks = emptyList(),
        )

        val first = fixture.authenticateCurrentSocket()
        assertEquals(
            listOf(MessagingWssCoordinator.SEND_ACCEPTANCE_TIMEOUT_MILLIS),
            fixture.scheduler.pendingDelays(),
        )

        fixture.scheduler.runNext()

        assertTrue(first.cancelled)
        assertEquals(MessagingWssState.RETRY_WAIT, fixture.coordinator.currentState())
        assertEquals(
            listOf(MessagingWssCoordinator.INITIAL_RECONNECT_DELAY_MILLIS),
            fixture.scheduler.pendingDelays(),
        )

        fixture.scheduler.runNext()
        val second = fixture.authenticateCurrentSocket()
        val replayed = MessagingWire.decodeClientFrame(second.sent[1]).send!!
        assertArrayEquals(encodedEnvelope, MessagingWire.encodeEnvelope(replayed))
    }

    @Test
    fun sendAcceptedCancelsOutstandingAcceptanceWatchdog() {
        val fixture = Fixture()
        val envelope = outboundEnvelope()
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    PEER.copyOf(),
                    MESSAGE_ID.copyOf(),
                    MessagingWire.encodeEnvelope(envelope),
                ),
            ),
            inboundAcks = emptyList(),
        )
        val socket = fixture.authenticateCurrentSocket()
        assertEquals(
            listOf(MessagingWssCoordinator.SEND_ACCEPTANCE_TIMEOUT_MILLIS),
            fixture.scheduler.pendingDelays(),
        )

        socket.serverFrame(
            MessagingServerFrame(
                sendAccepted = MessagingSendAccepted(PEER.copyOf(), MESSAGE_ID.copyOf()),
            ),
        )

        assertTrue(fixture.scheduler.pendingDelays().isEmpty())
        assertEquals(MessagingWssState.AUTHENTICATED, fixture.coordinator.currentState())
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
        ) {
            plan = plan.copy(
                outboundSends = plan.outboundSends.filterNot {
                    it.peerIdentityId.contentEquals(accepted.recipientIdentityId) &&
                        it.messageId.contentEquals(accepted.messageId)
                },
            )
        }
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
        private val CHALLENGE = ByteArray(MESSAGING_AUTH_CHALLENGE_BYTES) { 0x44 }

        private fun outboundEnvelope(): MessagingEnvelope = MessagingEnvelope(
            senderIdentityId = OWNER.copyOf(),
            recipientIdentityId = PEER.copyOf(),
            messageId = MESSAGE_ID.copyOf(),
            ciphertext = byteArrayOf(1, 2, 3, 4),
            expiresAtEpochSeconds = 200,
        )
    }
}
