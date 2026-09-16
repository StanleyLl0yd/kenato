package com.sl.kenato.messaging

import java.net.URI
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingWssProtocolFailureTest {
    @Test
    fun messagingProtocolFailureFailsClosedWithoutReconnect() {
        lateinit var listener: MessagingSocketListener
        val socket = FakeSocket()
        val scheduler = FakeScheduler()
        val coordinator = MessagingWssCoordinator(
            serviceOrigin = URI("https://example.test/"),
            sockets = MessagingSocketFactory { _, value ->
                listener = value
                socket
            },
            identity = object : MessagingIdentityAuthenticator {
                override fun identityId(): ByteArray = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x11 }

                override fun signProtocolPayload(payload: ByteArray): ByteArray = byteArrayOf(0x30, 0x01, 0x01)
            },
            recovery = object : MessagingRecoveryDriver {
                override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan =
                    MessagingRecoveryPlan(emptyList(), emptyList())

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
            },
            inbound = MessagingInboundDeliveryHandler { _, _ -> null },
            scheduler = scheduler,
            clock = MessagingWssClock { 100 },
        )

        coordinator.start()
        listener.onOpen(socket)
        assertEquals(
            listOf(MessagingWssCoordinator.AUTHENTICATION_TIMEOUT_MILLIS),
            scheduler.pendingDelays(),
        )

        listener.onFailure(
            socket,
            MessagingWssException("M4 WebSocket text frames are forbidden"),
        )

        assertTrue(socket.cancelled)
        assertEquals(MessagingWssState.FAILED, coordinator.currentState())
        assertTrue(scheduler.pendingDelays().isEmpty())
    }

    private class FakeSocket : MessagingSocket {
        var cancelled = false

        override fun connect() = Unit

        override fun sendBinary(value: ByteArray): Boolean = !cancelled

        override fun cancel() {
            cancelled = true
        }
    }

    private class FakeScheduler : MessagingRetryScheduler {
        private val tasks = ArrayList<Task>()

        override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask =
            Task(delayMillis).also(tasks::add)

        fun pendingDelays(): List<Long> = tasks.filterNot { it.isCancelled }.map { it.delayMillis }

        private class Task(
            val delayMillis: Long,
        ) : MessagingScheduledTask {
            var isCancelled = false

            override fun cancel() {
                isCancelled = true
            }
        }
    }
}
