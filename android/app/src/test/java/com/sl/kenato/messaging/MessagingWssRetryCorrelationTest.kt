package com.sl.kenato.messaging

import java.net.URI
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingWssRetryCorrelationTest {
    @Test
    fun retryLaterMatchingOutboundAndAckFailsClosed() {
        val fixture = Fixture()
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    PEER.copyOf(),
                    MESSAGE_ID.copyOf(),
                    MessagingWire.encodeEnvelope(outboundEnvelope()),
                ),
            ),
            inboundAcks = listOf(
                MessagingRecoveredAck(
                    PEER.copyOf(),
                    MESSAGE_ID.copyOf(),
                ),
            ),
        )
        val socket = fixture.authenticate()

        socket.serverFrame(
            MessagingServerFrame(
                error = MessagingWireError(
                    MESSAGING_ERROR_RETRY_LATER,
                    MESSAGE_ID.copyOf(),
                ),
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
        val coordinator = MessagingWssCoordinator(
            serviceOrigin = URI("https://example.test/"),
            sockets = sockets,
            identity = FakeIdentity(),
            recovery = recovery,
            inbound = MessagingInboundDeliveryHandler { _, _ -> null },
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
        var cancelled = false

        override fun connect() = Unit

        override fun sendBinary(value: ByteArray): Boolean = !cancelled

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

    private class FakeScheduler : MessagingRetryScheduler {
        private val tasks = ArrayList<Task>()

        override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask =
            Task(delayMillis, task).also(tasks::add)

        fun pendingDelays(): List<Long> =
            tasks.filterNot { it.cancelled }.map { it.delayMillis }

        private class Task(
            val delayMillis: Long,
            val block: () -> Unit,
        ) : MessagingScheduledTask {
            var cancelled = false

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
