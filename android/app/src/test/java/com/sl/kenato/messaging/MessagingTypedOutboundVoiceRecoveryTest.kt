package com.sl.kenato.messaging

import com.sl.kenato.call.VoiceOutboundHandoffRecovery
import com.sl.kenato.call.VoiceOutboundRecoveryException
import com.sl.kenato.call.VoiceSignalKind
import com.sl.kenato.call.VoiceSignalPlaintext
import com.sl.kenato.call.VoiceSignalingWire
import com.sl.kenato.session.SESSION_OLM_MESSAGE_NORMAL
import com.sl.kenato.session.SessionCiphertext
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingTypedOutboundVoiceRecoveryTest {
    @Test
    fun exactStagedVoiceCiphertextIsRecoveredWithoutChatHistory() {
        val f = Fixture()
        val plan = f.coordinator().recover(OWNER)
        assertEquals(1, plan.outboundSends.size)
        assertTrue(plan.inboundAcks.isEmpty())
        assertArrayEquals(f.handoff.encodedEnvelope, plan.outboundSends.single().encodedEnvelope)
        assertArrayEquals(f.handoff.messageId, plan.outboundSends.single().messageId)
        assertTrue(f.history.currentState(OWNER)?.messages.isNullOrEmpty())
        assertEquals(1, f.handoffs.items.size)
    }

    @Test
    fun oldTextOnlyRecoveryFailsClosedWithNoImportOrRemoval() {
        val f = Fixture()
        assertThrows(MessagingRecoveryException::class.java) {
            MessagingRecoveryCoordinator(
                sessions = f.handoffs,
                history = f.history,
                clock = MessagingRecoveryClock { NOW },
            ).recover(OWNER)
        }
        assertEquals(1, f.handoffs.items.size)
        assertTrue(f.history.currentState(OWNER)?.messages.isNullOrEmpty())
    }

    @Test
    fun authenticatedAcceptedRemovesOnlyExactVoiceHandoff() {
        val f = Fixture()
        val coordinator = f.coordinator()
        coordinator.recordSendAccepted(OWNER, MessagingSendAccepted(PEER, MESSAGE_ID))
        assertTrue(f.handoffs.items.isEmpty())
        assertTrue(f.history.currentState(OWNER)?.messages.isNullOrEmpty())
        assertThrows(MessagingRecoveryException::class.java) {
            coordinator.recordSendAccepted(OWNER, MessagingSendAccepted(PEER, MESSAGE_ID))
        }
    }

    @Test
    fun expiredRecoveredVoiceNeverNeedsPlaintextOrSecondRatchetEncryption() {
        val f = Fixture()
        val coordinator = f.coordinator(now = EXPIRES + 1)
        val plan = coordinator.recover(OWNER)
        assertEquals(1, plan.outboundSends.size)
        assertTrue(coordinator.expireOutboundIfDue(OWNER, PEER, MESSAGE_ID, EXPIRES + 1))
        assertTrue(f.handoffs.items.isEmpty())
        assertTrue(f.history.currentState(OWNER)?.messages.isNullOrEmpty())
    }

    @Test
    fun notYetExpiredVoiceCannotBeTerminalized() {
        val f = Fixture()
        assertFalse(f.coordinator().expireOutboundIfDue(OWNER, PEER, MESSAGE_ID, EXPIRES - 1))
        assertEquals(1, f.handoffs.items.size)
    }

    @Test
    fun ciphertextOwnerAndPeerSubstitutionsFailBeforeAnyEffect() {
        val f = Fixture()
        val original = MessagingWire.decodeEnvelope(f.handoff.encodedEnvelope)
        f.handoffs.items[0] = f.handoff.copy(
            encodedEnvelope = MessagingWire.encodeEnvelope(
                original.copy(senderIdentityId = PEER.copyOf(), recipientIdentityId = OWNER.copyOf()),
            ),
        )
        assertThrows(VoiceOutboundRecoveryException::class.java) {
            f.coordinator().recover(OWNER)
        }
        assertEquals(1, f.handoffs.items.size)
    }

    @Test
    fun duplicateMixedTypePendingKeysFailBeforeAnyTextHistoryImport() {
        val f = Fixture()
        val text = MessagingPlaintext(
            senderIdentityId = OWNER.copyOf(),
            recipientIdentityId = PEER.copyOf(),
            messageId = MESSAGE_ID.copyOf(),
            sentAtEpochSeconds = NOW,
            expiresAtEpochSeconds = EXPIRES,
            text = "not voice",
        )
        f.handoffs.items.add(
            0, f.handoff.copy(encodedPlaintext = MessagingWire.encodePlaintext(text)),
        )
        assertThrows(MessagingRecoveryException::class.java) {
            f.coordinator().recover(OWNER)
        }
        assertTrue(f.history.currentState(OWNER)?.messages.isNullOrEmpty())
        assertEquals(2, f.handoffs.items.size)
    }

    @Test
    fun textHistoryWithSameOutboundKeyBlocksVoiceReplay() {
        val f = Fixture()
        val text = MessagingPlaintext(
            senderIdentityId = OWNER.copyOf(),
            recipientIdentityId = PEER.copyOf(),
            messageId = MESSAGE_ID.copyOf(),
            sentAtEpochSeconds = NOW,
            expiresAtEpochSeconds = EXPIRES,
            text = "text",
        )
        f.history.importOutboundPendingAcceptance(
            OWNER, f.handoff.copy(encodedPlaintext = MessagingWire.encodePlaintext(text)),
        )
        assertThrows(MessagingRecoveryException::class.java) {
            f.coordinator().recover(OWNER)
        }
        assertEquals(1, f.handoffs.items.size)
    }

    @Test
    fun tamperedVoiceSemanticPayloadNeverProducesRecoveredEnvelope() {
        val f = Fixture()
        f.handoffs.items[0] = f.handoff.copy(
            encodedPlaintext = f.handoff.encodedPlaintext.copyOf().also {
                it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
            },
        )
        assertThrows(VoiceOutboundRecoveryException::class.java) {
            f.coordinator().recover(OWNER)
        }
        assertEquals(1, f.handoffs.items.size)
    }

    @Test
    fun failedAtomicCompletionIsNeverReportedAsAcceptedOrExpired() {
        val f = Fixture()
        f.handoffs.failComplete = true
        val coordinator = f.coordinator()
        assertThrows(VoiceOutboundRecoveryException::class.java) {
            coordinator.recordSendAccepted(OWNER, MessagingSendAccepted(PEER, MESSAGE_ID))
        }
        assertThrows(VoiceOutboundRecoveryException::class.java) {
            coordinator.expireOutboundIfDue(OWNER, PEER, MESSAGE_ID, EXPIRES + 1)
        }
        assertEquals(1, f.handoffs.items.size)
    }

    @Test
    fun unknownMessageOrCrossPeerAcceptanceFailsClosed() {
        val f = Fixture()
        val coordinator = f.coordinator()
        assertThrows(MessagingRecoveryException::class.java) {
            coordinator.recordSendAccepted(OWNER, MessagingSendAccepted(OWNER, MESSAGE_ID))
        }
        assertThrows(VoiceOutboundRecoveryException::class.java) {
            VoiceOutboundHandoffRecovery(f.handoffs).expireIfDue(OWNER, PEER, ByteArray(16) { 9 }, EXPIRES + 1)
        }
        assertEquals(1, f.handoffs.items.size)
    }

    private class Fixture {
        val handoff: SessionMessageHandoff = outboundVoice()
        val handoffs = FakeHandoffs(mutableListOf(handoff))
        val history = ConversationHistoryRepository(
            object : ConversationHistoryStore {
                private var persisted: ByteArray? = null
                override fun read(): ByteArray? = persisted?.copyOf()
                override fun write(value: ByteArray): Boolean {
                    persisted = value.copyOf()
                    return true
                }
                override fun clear(): Boolean {
                    persisted = null
                    return true
                }
            },
            ConversationHistoryClock { NOW },
        )

        fun coordinator(now: Long = NOW) = MessagingRecoveryCoordinator(
            sessions = handoffs,
            history = history,
            clock = MessagingRecoveryClock { now },
            outboundVoice = VoiceOutboundHandoffRecovery(handoffs),
        )
    }

    private class FakeHandoffs(
        val items: MutableList<SessionMessageHandoff>,
    ) : MessagingSessionHandoffRepository {
        var failComplete = false
        override fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff> =
            items.toList()

        override fun completeMessageHandoff(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
            direction: Int,
        ): Boolean {
            if (failComplete) return false
            return items.removeAll {
                it.peerIdentityId.contentEquals(peerIdentityId) &&
                    it.messageId.contentEquals(messageId) &&
                    it.direction == direction
            }
        }
    }

    companion object {
        const val NOW = 100L
        const val EXPIRES = 160L
        val OWNER = ByteArray(32) { 1 }
        val PEER = ByteArray(32) { 2 }
        val MESSAGE_ID = ByteArray(16) { 3 }
        val CALL_ID = ByteArray(16) { 4 }
        val CONTACT = ByteArray(16) { 5 }

        fun outboundVoice(): SessionMessageHandoff {
            val plaintext = VoiceSignalingWire.encode(
                VoiceSignalPlaintext(
                    senderIdentityId = OWNER.copyOf(),
                    recipientIdentityId = PEER.copyOf(),
                    messageId = MESSAGE_ID.copyOf(),
                    callId = CALL_ID.copyOf(),
                    sentAtEpochSeconds = NOW,
                    expiresAtEpochSeconds = EXPIRES,
                    kind = VoiceSignalKind.HANGUP,
                    payload = byteArrayOf(),
                ),
            )
            val cipher = SessionCiphertextWire.encode(
                SessionCiphertext(
                    senderIdentityId = OWNER.copyOf(),
                    recipientIdentityId = PEER.copyOf(),
                    senderAccountGeneration = 7,
                    recipientAccountGeneration = 8,
                    olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
                    olmMessage = byteArrayOf(9, 8, 7),
                ),
            )
            val envelope = MessagingWire.encodeEnvelope(
                MessagingEnvelope(
                    senderIdentityId = OWNER.copyOf(),
                    recipientIdentityId = PEER.copyOf(),
                    messageId = MESSAGE_ID.copyOf(),
                    ciphertext = cipher,
                    expiresAtEpochSeconds = EXPIRES,
                ),
            )
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = PEER.copyOf(),
                messageId = MESSAGE_ID.copyOf(),
                direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                encodedPlaintext = plaintext,
                encodedEnvelope = envelope,
            )
        }
    }
}
