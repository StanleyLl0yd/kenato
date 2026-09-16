package com.sl.kenato.messaging

import com.sl.kenato.session.NativeSessionMessage
import com.sl.kenato.session.SESSION_OLM_MESSAGE_NORMAL
import com.sl.kenato.session.SessionMessageCryptoContext
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.net.URI
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingOfflineExpiryRecoveryTest {
    @Test
    fun expiredRecoveredQueueIsTerminalizedOfflineBeforeFreshAdmission() {
        val historyStore = MemoryHistoryStore()
        val history = ConversationHistoryRepository(historyStore, ConversationHistoryClock { 200 })
        val recoverySessions = FakeSessionHandoffs().also { sessions ->
            repeat(MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS) { index ->
                sessions.handoffs += outboundHandoff(index + 1)
            }
        }
        val recoveryCoordinator = MessagingRecoveryCoordinator(recoverySessions, history)
        val wss = stoppedWss(recoveryCoordinator)
        val outboundSessions = FakeOutboundSessions()
        val clock = SingleUseClock(200)
        val sender = DurableMessagingOutboundSender(
            sessions = outboundSessions,
            history = history,
            recovery = CoordinatorMessagingOutboundRecovery(recoveryCoordinator),
            admission = WssMessagingOutboundAdmission(wss, recoveryCoordinator),
            messageIds = MessagingMessageIdGenerator { messageId(10_000) },
            clock = clock,
        )

        val staged = sender.stageText(OWNER, PEER, "fresh", ttlSeconds = 60)

        assertEquals(ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE, staged.deliveryState)
        assertEquals(1, outboundSessions.stageCount)
        assertEquals(1, clock.calls)
        assertTrue(recoverySessions.handoffs.isEmpty())
        val persisted = history.currentState(OWNER)!!
        assertEquals(MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS + 1, persisted.messages.size)
        assertEquals(
            MessagingWssCoordinator.MAX_QUEUED_STAGED_SENDS,
            persisted.messages.count {
                it.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED
            },
        )
        assertEquals(
            1,
            persisted.messages.count {
                it.deliveryState == ConversationHistoryStateCodec.DELIVERY_STATE_PENDING_ACCEPTANCE
            },
        )
    }

    @Test
    fun outboundStageUsesOneClockSnapshotAcrossNativeEncryption() {
        val history = ConversationHistoryRepository(MemoryHistoryStore(), ConversationHistoryClock { 100 })
        val recoverySessions = FakeSessionHandoffs()
        val recoveryCoordinator = MessagingRecoveryCoordinator(recoverySessions, history)
        val wss = stoppedWss(recoveryCoordinator)
        val sessions = FakeOutboundSessions()
        val clock = SingleUseClock(100)
        val sender = DurableMessagingOutboundSender(
            sessions = sessions,
            history = history,
            recovery = CoordinatorMessagingOutboundRecovery(recoveryCoordinator),
            admission = WssMessagingOutboundAdmission(wss, recoveryCoordinator),
            messageIds = MessagingMessageIdGenerator { messageId(20_000) },
            clock = clock,
        )

        val record = sender.stageText(OWNER, PEER, "snapshot", ttlSeconds = 60)
        val handoff = requireNotNull(sessions.lastHandoff)
        val plaintext = MessagingWire.decodePlaintext(handoff.encodedPlaintext)
        val envelope = MessagingWire.decodeEnvelope(handoff.encodedEnvelope)

        assertEquals(1, clock.calls)
        assertEquals(100L, plaintext.sentAtEpochSeconds)
        assertEquals(160L, plaintext.expiresAtEpochSeconds)
        assertEquals(160L, envelope.expiresAtEpochSeconds)
        assertArrayEquals(record.messageId, envelope.messageId)
    }

    @Test
    fun authenticatedAdmissionDefersTerminalizationToTransport() {
        val history = ConversationHistoryRepository(MemoryHistoryStore(), ConversationHistoryClock { 100 })
        val recoveryCoordinator = MessagingRecoveryCoordinator(FakeSessionHandoffs(), history)
        val harness = authenticatedWss(recoveryCoordinator)
        val admission = WssMessagingOutboundAdmission(harness.coordinator, recoveryCoordinator)

        val terminal = admission.terminalizeIfSafe(
            ownerIdentityId = OWNER,
            peerIdentityId = PEER,
            messageId = messageId(30_000),
            nowEpochSeconds = 200,
        )

        assertFalse(terminal)
        assertEquals(MessagingWssState.AUTHENTICATED, harness.coordinator.currentState())
        assertTrue(history.currentState(OWNER) == null)
    }

    @Test
    fun staleExpiryPlanTreatsAlreadyAcceptedAndCleanedSendAsTerminal() {
        val fixture = RecoveryFixture()
        val outbound = outboundHandoff(1)
        fixture.sessions.handoffs += outbound
        val stalePlan = fixture.coordinator.recover(OWNER)
        assertEquals(1, stalePlan.outboundSends.size)

        fixture.coordinator.recordSendAccepted(
            OWNER,
            MessagingSendAccepted(PEER.copyOf(), outbound.messageId.copyOf()),
        )
        assertTrue(fixture.sessions.handoffs.isEmpty())

        val terminal = fixture.coordinator.expireOutboundIfDue(
            OWNER,
            PEER,
            stalePlan.outboundSends.single().messageId,
            nowEpochSeconds = 200,
        )

        assertTrue(terminal)
        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_ACCEPTED,
            fixture.history.currentState(OWNER)!!.messages.single().deliveryState,
        )
    }

    @Test
    fun repeatedExpiryAfterCleanupIsIdempotentlyTerminal() {
        val fixture = RecoveryFixture()
        val outbound = outboundHandoff(2)
        fixture.sessions.handoffs += outbound
        fixture.coordinator.recover(OWNER)

        assertTrue(
            fixture.coordinator.expireOutboundIfDue(
                OWNER,
                PEER,
                outbound.messageId,
                nowEpochSeconds = 200,
            ),
        )
        assertTrue(fixture.sessions.handoffs.isEmpty())

        assertTrue(
            fixture.coordinator.expireOutboundIfDue(
                OWNER,
                PEER,
                outbound.messageId,
                nowEpochSeconds = 200,
            ),
        )
        assertTrue(fixture.sessions.handoffs.isEmpty())
        assertEquals(
            ConversationHistoryStateCodec.DELIVERY_STATE_EXPIRED,
            fixture.history.currentState(OWNER)!!.messages.single().deliveryState,
        )
    }

    private fun stoppedWss(recoveryCoordinator: MessagingRecoveryCoordinator): MessagingWssCoordinator =
        MessagingWssCoordinator(
            serviceOrigin = URI("https://example.test/"),
            sockets = MessagingSocketFactory { _, _ -> throw AssertionError("stopped WSS must not create a socket") },
            identity = FakeIdentity(),
            recovery = DurableMessagingRecoveryDriver(recoveryCoordinator),
            inbound = MessagingInboundDeliveryHandler { _, _ -> null },
            scheduler = MessagingRetryScheduler { _, _ -> throw AssertionError("stopped WSS must not schedule") },
            clock = MessagingWssClock { 200 },
        )

    private fun authenticatedWss(recoveryCoordinator: MessagingRecoveryCoordinator): AuthHarness {
        val sockets = FakeSocketFactory()
        val coordinator = MessagingWssCoordinator(
            serviceOrigin = URI("https://example.test/"),
            sockets = sockets,
            identity = FakeIdentity(),
            recovery = DurableMessagingRecoveryDriver(recoveryCoordinator),
            inbound = MessagingInboundDeliveryHandler { _, _ -> null },
            scheduler = FakeScheduler(),
            clock = MessagingWssClock { 100 },
        )
        coordinator.start()
        val socket = sockets.latest
        socket.open()
        socket.serverFrame(
            MessagingServerFrame(
                authChallenge = MessagingAuthChallenge(CHALLENGE.copyOf(), 120),
            ),
        )
        socket.serverFrame(MessagingServerFrame(authenticated = true))
        return AuthHarness(coordinator, socket)
    }

    private data class AuthHarness(
        val coordinator: MessagingWssCoordinator,
        val socket: FakeSocket,
    )

    private class FakeIdentity : MessagingIdentityAuthenticator {
        override fun identityId(): ByteArray = OWNER.copyOf()

        override fun signProtocolPayload(payload: ByteArray): ByteArray = SIGNATURE.copyOf()
    }

    private class FakeSocketFactory : MessagingSocketFactory {
        private val sockets = ArrayList<FakeSocket>()
        val latest: FakeSocket get() = sockets.last()

        override fun create(url: String, listener: MessagingSocketListener): MessagingSocket =
            FakeSocket(listener).also(sockets::add)
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

    private class FakeScheduler : MessagingRetryScheduler {
        override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask =
            object : MessagingScheduledTask {
                override fun cancel() = Unit
            }
    }

    private class FakeOutboundSessions : MessagingOutboundSessionDriver {
        var stageCount = 0
        var lastHandoff: SessionMessageHandoff? = null

        override fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray {
            assertArrayEquals(OWNER, ownerIdentityId)
            assertArrayEquals(PEER, peerIdentityId)
            return CONTACT.copyOf()
        }

        override fun encryptAndStageMessageHandoff(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            encodedPlaintext: ByteArray,
            buildHandoff: (SessionMessageCryptoContext, NativeSessionMessage) -> SessionMessageHandoff,
        ): SessionMessageHandoff {
            stageCount++
            val handoff = buildHandoff(
                SessionMessageCryptoContext(
                    ownerIdentityId = OWNER.copyOf(),
                    localContactId = CONTACT.copyOf(),
                    peerIdentityId = PEER.copyOf(),
                    localAccountGeneration = 7,
                    peerAccountGeneration = 8,
                ),
                NativeSessionMessage(
                    messageType = SESSION_OLM_MESSAGE_NORMAL,
                    ciphertext = byteArrayOf(9, 8, 7),
                ),
            )
            assertArrayEquals(encodedPlaintext, handoff.encodedPlaintext)
            lastHandoff = copyHandoff(handoff)
            return copyHandoff(handoff)
        }
    }

    private class SingleUseClock(private val value: Long) : MessagingOutboundClock {
        var calls = 0

        override fun nowEpochSeconds(): Long {
            calls++
            if (calls > 1) throw AssertionError("outbound stage clock must be sampled once")
            return value
        }
    }

    private class RecoveryFixture {
        val store = MemoryHistoryStore()
        val history = ConversationHistoryRepository(store, ConversationHistoryClock { 100 })
        val sessions = FakeSessionHandoffs()
        val coordinator = MessagingRecoveryCoordinator(sessions, history)
    }

    private class FakeSessionHandoffs : MessagingSessionHandoffRepository {
        val handoffs = ArrayList<SessionMessageHandoff>()

        override fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff> =
            handoffs.map(::copyHandoff)

        override fun completeMessageHandoff(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
            direction: Int,
        ): Boolean {
            val index = handoffs.indexOfFirst {
                it.direction == direction &&
                    it.peerIdentityId.contentEquals(peerIdentityId) &&
                    it.messageId.contentEquals(messageId)
            }
            if (index < 0) return false
            handoffs.removeAt(index)
            return true
        }
    }

    private class MemoryHistoryStore : ConversationHistoryStore {
        private var value: ByteArray? = null

        override fun read(): ByteArray? = value?.copyOf()

        override fun write(value: ByteArray): Boolean {
            this.value = value.copyOf()
            return true
        }

        override fun clear(): Boolean {
            value = null
            return true
        }
    }

    companion object {
        private val OWNER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x11.toByte() }
        private val PEER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x22.toByte() }
        private val CONTACT = ByteArray(SessionStateCodec.LOCAL_CONTACT_ID_BYTES) { 0x33.toByte() }
        private val CHALLENGE = ByteArray(MESSAGING_AUTH_CHALLENGE_BYTES) { 0x44.toByte() }
        private val SIGNATURE = byteArrayOf(0x30, 0x01, 0x01)

        private fun outboundHandoff(index: Int): SessionMessageHandoff {
            val id = messageId(index)
            val plaintext = MessagingPlaintext(
                senderIdentityId = OWNER.copyOf(),
                recipientIdentityId = PEER.copyOf(),
                messageId = id.copyOf(),
                sentAtEpochSeconds = 100,
                expiresAtEpochSeconds = 200,
                text = "message-$index",
            )
            val envelope = MessagingEnvelope(
                senderIdentityId = OWNER.copyOf(),
                recipientIdentityId = PEER.copyOf(),
                messageId = id.copyOf(),
                ciphertext = "ciphertext-$index".toByteArray(),
                expiresAtEpochSeconds = 200,
            )
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = PEER.copyOf(),
                messageId = id,
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                encodedPlaintext = MessagingWire.encodePlaintext(plaintext),
                encodedEnvelope = MessagingWire.encodeEnvelope(envelope),
            )
        }

        private fun copyHandoff(value: SessionMessageHandoff): SessionMessageHandoff = value.copy(
            localContactId = value.localContactId.copyOf(),
            peerIdentityId = value.peerIdentityId.copyOf(),
            messageId = value.messageId.copyOf(),
            encodedPlaintext = value.encodedPlaintext.copyOf(),
            encodedEnvelope = value.encodedEnvelope.copyOf(),
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
