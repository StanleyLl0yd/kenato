package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import com.sl.kenato.contact.PinnedContact
import com.sl.kenato.messaging.ConversationHistoryClock
import com.sl.kenato.messaging.ConversationHistoryRepository
import com.sl.kenato.messaging.ConversationHistoryStore
import com.sl.kenato.messaging.MessagingMessageIdGenerator
import com.sl.kenato.messaging.MessagingOutboundClock
import com.sl.kenato.messaging.MessagingOutboundSessionDriver
import com.sl.kenato.messaging.MessagingSessionHandoffRepository
import com.sl.kenato.messaging.MessagingWire
import com.sl.kenato.session.NativeSessionMessage
import com.sl.kenato.session.SESSION_OLM_MESSAGE_NORMAL
import com.sl.kenato.session.SessionCiphertextWire
import com.sl.kenato.session.SessionMessageCryptoContext
import com.sl.kenato.session.SessionMessageHandoff
import com.sl.kenato.session.SessionStateCodec
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceOutboundHandoffStagerTest {
    @Test
    fun signedPeerStagesCanonicalVoiceOnlyInAtomicM3Handoff() {
        val f = Fixture()
        f.approve()
        val staged = f.stager().stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.OFFER, SDP, 60)
        assertEquals(1, f.sessions.commits.size)
        assertEquals(SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND, staged.direction)
        val envelope = MessagingWire.decodeEnvelope(staged.encodedEnvelope)
        assertArrayEquals(staged.encodedEnvelope, MessagingWire.encodeEnvelope(envelope))
        val signal = VoiceSignalingWire.decode(
            staged.encodedPlaintext,
            VoiceSignalEnvelopeBinding(
                envelope.senderIdentityId, envelope.recipientIdentityId,
                envelope.messageId, envelope.expiresAtEpochSeconds,
            ),
            NOW,
        )
        assertEquals(VoiceSignalKind.OFFER, signal.kind)
        assertArrayEquals(CALL_ID, signal.callId)
        assertArrayEquals(SDP, signal.payload)
        assertEquals(NOW + 60, signal.expiresAtEpochSeconds)
        val encrypted = SessionCiphertextWire.decode(envelope.ciphertext)
        assertArrayEquals(OWNER, encrypted.senderIdentityId)
        assertArrayEquals(f.peer, encrypted.recipientIdentityId)
        assertEquals(7L, encrypted.senderAccountGeneration)
        assertEquals(8L, encrypted.recipientAccountGeneration)
        assertEquals(SESSION_OLM_MESSAGE_NORMAL, encrypted.olmMessageType)
    }

    @Test
    fun legacyUnapprovedAndRevokedPeersNeverReachEncryption() {
        val f = Fixture()
        assertThrows(VoiceOutboundEligibilityException::class.java) {
            f.stager().stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.HANGUP, byteArrayOf(), 30)
        }
        assertEquals(0, f.sessions.calls)
        f.approve()
        f.consent.revoke(OWNER, f.peer)
        assertThrows(VoiceOutboundEligibilityException::class.java) {
            f.stager().stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.HANGUP, byteArrayOf(), 30)
        }
        assertEquals(0, f.sessions.calls)
    }

    @Test
    fun invalidSignalFailsBeforeCryptoAndDoesNotCreateHandoff() {
        val f = Fixture()
        f.approve()
        val sender = f.stager()
        assertThrows(VoiceOutboundStagingException::class.java) {
            sender.stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.OFFER, SDP, 91)
        }
        assertThrows(VoiceOutboundStagingException::class.java) {
            sender.stage(OWNER, f.peer, ByteArray(16), VoiceSignalKind.HANGUP, byteArrayOf(), 30)
        }
        assertThrows(VoiceSignalingProtocolException::class.java) {
            sender.stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.ANSWER, byteArrayOf(), 30)
        }
        assertThrows(VoiceSignalingProtocolException::class.java) {
            sender.stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.ICE_CANDIDATE, ByteArray(4097) { 65 }, 30)
        }
        assertEquals(0, f.sessions.calls)
        assertTrue(f.sessions.commits.isEmpty())
    }

    @Test
    fun revocationBetweenPreflightAndAtomicCommitFailsClosed() {
        val f = Fixture()
        f.approve()
        f.sessions.beforeBuilder = { f.consent.revoke(OWNER, f.peer) }
        assertThrows(VoiceOutboundEligibilityException::class.java) {
            f.stager().stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.HANGUP, byteArrayOf(), 30)
        }
        assertEquals(1, f.sessions.calls)
        assertTrue(f.sessions.commits.isEmpty())
    }

    @Test
    fun cryptoContextSubstitutionCannotCreateHandoff() {
        val f = Fixture()
        f.approve()
        f.sessions.substitutePeer = true
        assertThrows(VoiceOutboundStagingException::class.java) {
            f.stager().stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.HANGUP, byteArrayOf(), 30)
        }
        assertTrue(f.sessions.commits.isEmpty())
    }

    @Test
    fun uncompletedVoiceWorkBlocksNewStagesBeforeFurtherRatchetMutation() {
        val f = Fixture()
        f.approve()
        val sender = f.stager()
        sender.stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.HANGUP, byteArrayOf(), 30)
        assertThrows(VoiceOutboundStagingException::class.java) {
            sender.stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.HANGUP, byteArrayOf(), 30)
        }
        assertEquals(1, f.sessions.calls)
        assertEquals(1, f.sessions.commits.size)
    }

    @Test
    fun exhaustionOfUniqueMessageIdsFailsBeforeEncryption() {
        val f = Fixture()
        f.approve()
        f.messageId = ByteArray(16)
        assertThrows(VoiceOutboundStagingException::class.java) {
            f.stager().stage(OWNER, f.peer, CALL_ID, VoiceSignalKind.HANGUP, byteArrayOf(), 30)
        }
        assertEquals(0, f.sessions.calls)
    }

    private class Fixture {
        val keys = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val peer: ByteArray = ContactCrypto.identityId(keys.public.encoded)
        val contact = PinnedContact(CONTACT_ID.copyOf(), peer.copyOf(), keys.public.encoded.copyOf(), NOW)
        val encryptedStore = MemoryCapabilityStore()
        val consent = DurableVoiceCapabilityConsentRepository(
            encryptedStore, JvmCapabilityCipher(), SecureRandom(),
            VoiceCapabilityConsentClock { NOW },
        )
        val sessions = FakeSessions(peer)
        var messageId = ByteArray(16) { 7 }
        private val history = ConversationHistoryRepository(
            object : ConversationHistoryStore {
                override fun read(): ByteArray? = null
                override fun write(value: ByteArray): Boolean = true
                override fun clear(): Boolean = true
            },
            ConversationHistoryClock { NOW },
        )
        private val guard = VoiceOutboundCapabilityGuard(
            VoicePinnedContactSource { owner, requested ->
                if (owner.contentEquals(OWNER) && requested.contentEquals(peer)) contact else null
            },
            VoiceSessionContactSource { owner, requested ->
                if (owner.contentEquals(OWNER) && requested.contentEquals(peer)) CONTACT_ID.copyOf() else null
            },
            consent,
        )

        fun stager() = VoiceOutboundHandoffStager(
            guard = guard,
            sessions = sessions,
            handoffs = sessions,
            history = history,
            messageIds = MessagingMessageIdGenerator { messageId.copyOf() },
            clock = MessagingOutboundClock { NOW },
        )

        fun approve() {
            val challenge = consent.issueChallenge(OWNER, peer, keys.public.encoded)
            val proof = VoiceCapabilityProofWire.sign(
                peer, OWNER, challenge.challenge, NOW, NOW + 300,
            ) { bytes ->
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(keys.private)
                    update(bytes)
                    sign()
                }
            }
            consent.confirmSignedProof(
                OWNER, peer, keys.public.encoded,
                VoiceCapabilityProofWire.encode(proof), true,
            )
        }
    }

    private class FakeSessions(private val peer: ByteArray) :
        MessagingOutboundSessionDriver, MessagingSessionHandoffRepository {
        val commits = mutableListOf<SessionMessageHandoff>()
        var calls = 0
        var substitutePeer = false
        var beforeBuilder: (() -> Unit)? = null

        override fun localContactIdForPeer(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray =
            CONTACT_ID.copyOf()

        override fun encryptAndStageMessageHandoff(
            ownerIdentityId: ByteArray,
            localContactId: ByteArray,
            encodedPlaintext: ByteArray,
            buildHandoff: (SessionMessageCryptoContext, NativeSessionMessage) -> SessionMessageHandoff,
        ): SessionMessageHandoff {
            calls++
            beforeBuilder?.invoke()
            val handoff = buildHandoff(
                SessionMessageCryptoContext(
                    ownerIdentityId = OWNER.copyOf(),
                    localContactId = localContactId.copyOf(),
                    peerIdentityId = if (substitutePeer) OWNER.copyOf() else peer.copyOf(),
                    localAccountGeneration = 7,
                    peerAccountGeneration = 8,
                ),
                NativeSessionMessage(SESSION_OLM_MESSAGE_NORMAL, byteArrayOf(9, 8, 7)),
            )
            assertArrayEquals(encodedPlaintext, handoff.encodedPlaintext)
            commits += handoff
            return handoff
        }

        override fun pendingMessageHandoffs(ownerIdentityId: ByteArray): List<SessionMessageHandoff> =
            commits.toList()

        override fun completeMessageHandoff(
            ownerIdentityId: ByteArray, peerIdentityId: ByteArray,
            messageId: ByteArray, direction: Int,
        ): Boolean = error("Not used by isolated staging")
    }

    private class MemoryCapabilityStore : VoiceCapabilityEncryptedStore {
        private var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(bytes: ByteArray): Boolean { this.bytes = bytes.copyOf(); return true }
        override fun clear(): Boolean { bytes = null; return true }
    }

    private class JvmCapabilityCipher : VoiceCapabilityPayloadCipher {
        private val key = SecretKeySpec(ByteArray(32) { 0x2a }, "AES")
        private val random = SecureRandom()
        override fun deleteCapabilityKeyForIdentityRecovery() = Unit
        override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
            val nonce = ByteArray(12).also(random::nextBytes)
            return Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
                updateAAD(aad)
                byteArrayOf(1) + nonce + doFinal(plaintext)
            }
        }
        override fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray =
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypted.copyOfRange(1, 13)))
                updateAAD(aad)
                doFinal(encrypted.copyOfRange(13, encrypted.size))
            }
    }

    private companion object {
        const val NOW = 1_780_000_000L
        val OWNER = ByteArray(32) { 1 }
        val CONTACT_ID = ByteArray(16) { 3 }
        val CALL_ID = ByteArray(16) { 4 }
        val SDP = "v=0\r\ns=- 1 1 IN IP4 127.0.0.1\r\n".toByteArray()
    }
}
