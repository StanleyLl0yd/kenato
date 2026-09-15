package com.sl.kenato.messaging

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI

class MessagingWssLiveFlushTest {
    @Test
    fun flushDurableWorkSendsNewlyStagedEnvelopeOnlyOncePerConnection() {
        val fixture = Fixture()
        val socket = fixture.authenticate()
        val envelope = outboundEnvelope(7)
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    peerIdentityId = PEER.copyOf(),
                    messageId = envelope.messageId.copyOf(),
                    encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
                ),
            ),
            inboundAcks = emptyList(),
        )

        fixture.coordinator.flushDurableWork()
        fixture.coordinator.flushDurableWork()

        assertEquals(MessagingWssState.AUTHENTICATED, fixture.coordinator.currentState())
        assertEquals(2, socket.sent.size)
        val sent = MessagingWire.decodeClientFrame(socket.sent[1]).send!!
        assertArrayEquals(MessagingWire.encodeEnvelope(envelope), MessagingWire.encodeEnvelope(sent))
    }

    @Test
    fun flushDurableWorkDoesNothingBeforeAuthentication() {
        val fixture = Fixture()
        val envelope = outboundEnvelope(8)
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    peerIdentityId = PEER.copyOf(),
                    messageId = envelope.messageId.copyOf(),
                    encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
                ),
            ),
            inboundAcks = emptyList(),
        )

        fixture.coordinator.flushDurableWork()
        fixture.coordinator.start()
        val socket = fixture.sockets.latest
        fixture.coordinator.flushDurableWork()
        assertTrue(socket.sent.isEmpty())

        socket.open()
        fixture.coordinator.flushDurableWork()
        assertTrue(socket.sent.isEmpty())

        socket.serverFrame(MessagingServerFrame(authChallenge = MessagingAuthChallenge(CHALLENGE.copyOf(), 120)))
        fixture.coordinator.flushDurableWork()
        assertEquals(1, socket.sent.size)
        assertTrue(MessagingWire.decodeClientFrame(socket.sent.single()).authResponse != null)
    }

    @Test
    fun flushDurableWorkReconnectsWhenSocketCannotQueueDurableSend() {
        val fixture = Fixture()
        val socket = fixture.authenticate()
        val envelope = outboundEnvelope(9)
        fixture.recovery.plan = MessagingRecoveryPlan(
            outboundSends = listOf(
                MessagingRecoveredSend(
                    peerIdentityId = PEER.copyOf(),
                    messageId = envelope.messageId.copyOf(),
                    encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
                ),
            ),
            inboundAcks = emptyList(),
        )
        socket.acceptSends = false

        fixture.coordinator.flushDurableWork()

        assertTrue(socket.cancelled)
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
            inbound = MessagingInboundDeliveryHandler { null },
            scheduler = scheduler,
            clock = MessagingWssClock { 100 },
        )

        fun authenticate(): FakeSocket {
            coordinator.start()
            val socket = sockets.latest
            socket.open()
            socket.serverFrame(MessagingServerFrame(authChallenge = MessagingAuthChallenge(CHALLENGE.copyOf(), 120)))
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
        var acceptSends = true

        override fun connect() = Unit

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
            listener.onBinaryMessage(this, MessagingWire.encodeServerFrame(frame))
    }

    private class FakeIdentity : MessagingIdentityAuthenticator {
        override fun identityId(): ByteArray = OWNER.copyOf()

        override fun signProtocolPayload(payload: ByteArray): ByteArray = SIGNATURE.copyOf()
    }

    private class FakeRecovery : MessagingRecoveryDriver {
        var plan = MessagingRecoveryPlan(emptyList(), emptyList())

        override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan = plan

        override fun recordSendAccepted(ownerIdentityId: ByteArray, accepted: MessagingSendAccepted) = Unit
    }

    private class FakeScheduler : MessagingRetryScheduler {
        private val tasks = ArrayList<Task>()

        override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask =
            Task(delayMillis).also(tasks::add)

        fun pendingDelays(): List<Long> = tasks.filterNot { it.cancelled }.map { it.delayMillis }

        private class Task(
            val delayMillis: Long,
        ) : MessagingScheduledTask {
            var cancelled = false
                private set

            override fun cancel() {
                cancelled = true
            }
        }
    }

    companion object {
        private val OWNER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x11.toByte() }
        private val PEER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x22.toByte() }
        private val CHALLENGE = ByteArray(MESSAGING_AUTH_CHALLENGE_BYTES) { 0x44.toByte() }
        private val SIGNATURE = byteArrayOf(0x30, 0x01, 0x01)

        private fun outboundEnvelope(index: Int): MessagingEnvelope = MessagingEnvelope(
            senderIdentityId = OWNER.copyOf(),
            recipientIdentityId = PEER.copyOf(),
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
    }
}
