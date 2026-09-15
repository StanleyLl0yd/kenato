package com.sl.kenato.messaging

import com.sl.kenato.session.SESSION_OLM_MESSAGE_NORMAL
import com.sl.kenato.session.SessionCiphertext
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageCryptoContext
import com.sl.kenato.session.SessionMessageHandoff
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class MessagingInboundCiphertextCanonicalityTest {
    @Test
    fun nonCanonicalSessionCiphertextFailsBeforeSessionLookupOrDecrypt() {
        val sessions = RejectingSessionDriver()
        val history = ConversationHistoryRepository(EmptyHistoryStore())
        val handler = DurableMessagingInboundDeliveryHandler(
            sessions = sessions,
            history = history,
            clock = MessagingInboundClock { 100 },
        )
        val canonical = SessionCiphertextWire.encode(
            SessionCiphertext(
                senderIdentityId = PEER.copyOf(),
                recipientIdentityId = OWNER.copyOf(),
                senderAccountGeneration = 8,
                recipientAccountGeneration = 7,
                olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
                olmMessage = byteArrayOf(1, 2, 3),
            ),
        )
        // Unknown protobuf field 15, varint 1. The M3 decoder intentionally skips unknown fields,
        // so the inbound boundary must reject this alternate encoding before session lookup/decrypt.
        val nonCanonical = canonical + byteArrayOf(0x78, 0x01)
        val envelope = MessagingEnvelope(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            messageId = ByteArray(MESSAGING_MESSAGE_ID_BYTES).also { it[0] = 1 },
            ciphertext = nonCanonical,
            expiresAtEpochSeconds = 200,
        )

        assertThrows(MessagingInboundDeliveryException::class.java) {
            handler.handle(envelope)
        }

        assertEquals(0, sessions.resolveCount)
        assertEquals(0, sessions.decryptCount)
    }

    private class RejectingSessionDriver : MessagingInboundSessionDriver {
        var resolveCount = 0
        var decryptCount = 0

        override fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray {
            resolveCount++
            throw AssertionError("session lookup must not run")
        }

        override fun decryptAndStageMessageHandoff(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            ciphertext: SessionCiphertext,
            buildHandoff: (SessionMessageCryptoContext, ByteArray) -> SessionMessageHandoff,
        ): SessionMessageHandoff {
            decryptCount++
            throw AssertionError("native decrypt must not run")
        }

        override fun completeInboundMessageHandoff(
            ownerIdentityId: ByteArray,
            peerIdentityId: ByteArray,
            messageId: ByteArray,
        ): Boolean = throw AssertionError("handoff completion must not run")
    }

    private class EmptyHistoryStore : ConversationHistoryStore {
        override fun read(): ByteArray? = null

        override fun write(value: ByteArray): Boolean =
            throw AssertionError("history write must not run")

        override fun clear(): Boolean = true
    }

    companion object {
        private val OWNER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x11.toByte() }
        private val PEER = ByteArray(MESSAGING_IDENTITY_BYTES) { 0x22.toByte() }
    }
}
