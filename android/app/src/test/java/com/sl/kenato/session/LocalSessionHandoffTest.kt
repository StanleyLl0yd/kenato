package com.sl.kenato.session

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalSessionHandoffTest {
    @Test
    fun outboundRatchetAndHandoffCommitInOneDurableWrite() {
        val fixture = Fixture().also(Fixture::establishReadyOutbound)
        val beforeWrites = fixture.store.writeCount
        val plaintext = "encoded-m4-plaintext".toByteArray()

        val handoff = fixture.repository.encryptAndStageMessageHandoff(
            OWNER,
            CONTACT,
            plaintext,
        ) { context, message ->
            assertArrayEquals(OWNER, context.ownerIdentityId)
            assertArrayEquals(PEER, context.peerIdentityId)
            assertEquals(1L, context.localAccountGeneration)
            assertEquals(4L, context.peerAccountGeneration)
            assertEquals(SESSION_OLM_MESSAGE_NORMAL, message.messageType)
            assertArrayEquals("ciphertext".toByteArray(), message.ciphertext)
            outboundHandoff(plaintext)
        }

        assertEquals(beforeWrites + 1, fixture.store.writeCount)
        val state = fixture.repository.currentState(OWNER)!!
        assertArrayEquals("session-encrypted".toByteArray(), state.sessions.single().snapshot.ciphertext)
        assertEquals(1, state.messageHandoffs.size)
        assertArrayEquals(handoff.messageId, state.messageHandoffs.single().messageId)

        handoff.encodedEnvelope[0] = 0
        assertArrayEquals("envelope".toByteArray(), fixture.repository.pendingMessageHandoffs(OWNER).single().encodedEnvelope)
    }

    @Test
    fun outboundBuilderFailureDoesNotCommitAdvancedRatchet() {
        val fixture = Fixture().also(Fixture::establishReadyOutbound)
        val before = fixture.store.value!!.copyOf()

        assertThrows(SessionStateException::class.java) {
            fixture.repository.encryptAndStageMessageHandoff(
                OWNER,
                CONTACT,
                "plaintext".toByteArray(),
            ) { _, _ -> throw SessionStateException("reject handoff") }
        }

        assertArrayEquals(before, fixture.store.value)
        assertEquals(1, fixture.engine.encryptCalls)
        assertTrue(fixture.repository.pendingMessageHandoffs(OWNER).isEmpty())
    }

    @Test
    fun failedDurableWriteDoesNotPublishOutboundHandoff() {
        val fixture = Fixture().also(Fixture::establishReadyOutbound)
        val before = fixture.store.value!!.copyOf()
        fixture.store.failWrites = true

        assertThrows(SessionStateException::class.java) {
            fixture.repository.encryptAndStageMessageHandoff(
                OWNER,
                CONTACT,
                "plaintext".toByteArray(),
            ) { _, _ -> outboundHandoff("plaintext".toByteArray()) }
        }

        assertArrayEquals(before, fixture.store.value)
        fixture.store.failWrites = false
        val state = fixture.repository.currentState(OWNER)!!
        assertArrayEquals("session-out".toByteArray(), state.sessions.single().snapshot.ciphertext)
        assertTrue(state.messageHandoffs.isEmpty())
    }

    @Test
    fun inboundProvenanceMismatchFailsBeforeNativeDecrypt() {
        val fixture = Fixture().also(Fixture::establishReadyOutbound)
        val wrong = inboundCiphertext().copy(senderIdentityId = bytes(0x66, 32))

        assertThrows(SessionStateException::class.java) {
            fixture.repository.decryptAndStageMessageHandoff(OWNER, CONTACT, wrong) { _, plaintext ->
                inboundHandoff(plaintext)
            }
        }

        assertEquals(0, fixture.engine.decryptCalls)
        assertTrue(fixture.repository.pendingMessageHandoffs(OWNER).isEmpty())
    }

    @Test
    fun inboundValidationAndRatchetHandoffCommitTogether() {
        val fixture = Fixture().also(Fixture::establishReadyOutbound)
        fixture.engine.decryptPlaintext = "decoded-m4-plaintext".toByteArray()
        val beforeWrites = fixture.store.writeCount

        val handoff = fixture.repository.decryptAndStageMessageHandoff(
            OWNER,
            CONTACT,
            inboundCiphertext(),
        ) { context, plaintext ->
            assertArrayEquals(PEER, context.peerIdentityId)
            assertArrayEquals("decoded-m4-plaintext".toByteArray(), plaintext)
            inboundHandoff(plaintext)
        }

        assertEquals(1, fixture.engine.decryptCalls)
        assertEquals(beforeWrites + 1, fixture.store.writeCount)
        val state = fixture.repository.currentState(OWNER)!!
        assertArrayEquals("session-decrypted".toByteArray(), state.sessions.single().snapshot.ciphertext)
        assertEquals(SessionStateCodec.HANDOFF_DIRECTION_INBOUND, state.messageHandoffs.single().direction)
        assertArrayEquals(handoff.encodedPlaintext, state.messageHandoffs.single().encodedPlaintext)
    }

    @Test
    fun inboundBuilderFailureLeavesPersistedRatchetUntouched() {
        val fixture = Fixture().also(Fixture::establishReadyOutbound)
        val before = fixture.store.value!!.copyOf()

        assertThrows(SessionStateException::class.java) {
            fixture.repository.decryptAndStageMessageHandoff(
                OWNER,
                CONTACT,
                inboundCiphertext(),
            ) { _, _ -> throw SessionStateException("inner/outer mismatch") }
        }

        assertEquals(1, fixture.engine.decryptCalls)
        assertArrayEquals(before, fixture.store.value)
        assertArrayEquals(
            "session-out".toByteArray(),
            fixture.repository.currentState(OWNER)!!.sessions.single().snapshot.ciphertext,
        )
    }

    @Test
    fun handoffJournalCapacityStopsBeforeNativeMutation() {
        val fixture = Fixture().also(Fixture::establishReadyOutbound)
        val state = fixture.repository.currentState(OWNER)!!
        val full = (1..SessionStateCodec.MAX_MESSAGE_HANDOFFS).map { index ->
            outboundHandoff("p-$index".toByteArray(), index)
        }
        fixture.store.value = SessionStateCodec.encode(state.copy(messageHandoffs = full))
        val encryptCalls = fixture.engine.encryptCalls
        val decryptCalls = fixture.engine.decryptCalls

        assertThrows(SessionStateException::class.java) {
            fixture.newRepository().encryptAndStageMessageHandoff(
                OWNER,
                CONTACT,
                "blocked".toByteArray(),
            ) { _, _ -> outboundHandoff("blocked".toByteArray(), 100) }
        }
        assertThrows(SessionStateException::class.java) {
            fixture.newRepository().decryptAndStageMessageHandoff(
                OWNER,
                CONTACT,
                inboundCiphertext(),
            ) { _, plaintext -> inboundHandoff(plaintext, 101) }
        }
        assertEquals(encryptCalls, fixture.engine.encryptCalls)
        assertEquals(decryptCalls, fixture.engine.decryptCalls)
    }

    @Test
    fun completedHandoffRemovalIsDurableAndIdempotent() {
        val fixture = Fixture().also(Fixture::establishReadyOutbound)
        val handoff = fixture.repository.encryptAndStageMessageHandoff(
            OWNER,
            CONTACT,
            "plaintext".toByteArray(),
        ) { _, _ -> outboundHandoff("plaintext".toByteArray()) }

        assertTrue(
            fixture.repository.completeMessageHandoff(
                OWNER,
                PEER,
                handoff.messageId,
                SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
            ),
        )
        assertTrue(fixture.newRepository().pendingMessageHandoffs(OWNER).isEmpty())
        assertFalse(
            fixture.newRepository().completeMessageHandoff(
                OWNER,
                PEER,
                handoff.messageId,
                SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
            ),
        )
    }

    private class Fixture {
        val engine = FakeEngine()
        val keys = FakeKeyBackend()
        val store = FakeStateStore()
        val repository = newRepository()

        fun newRepository(): LocalSessionRepository = LocalSessionRepository(engine, keys, store)

        fun establishReadyOutbound() {
            repository.loadOrCreateAccount(OWNER)
            repository.createOutboundSession(
                ownerIdentityId = OWNER,
                localContactId = CONTACT,
                peerIdentityId = PEER,
                peerAccountGeneration = 4,
                peerOlmEd25519IdentityKey = bytes(0x40, 32),
                peerOlmCurve25519IdentityKey = bytes(0x41, 32),
                creatorOneTimePreKeyId = 9,
                peerOneTimeKey = bytes(0x42, 32),
                inviteToken = INVITE,
                initialPlaintext = "control".toByteArray(),
            )
            repository.markOutboundInitSubmitted(OWNER, CONTACT, INVITE, 4, 9)
        }
    }

    private class FakeStateStore : SessionStateStore {
        var value: ByteArray? = null
        var writeCount = 0
        var failWrites = false

        override fun read(): ByteArray? = value?.copyOf()

        override fun write(value: ByteArray): Boolean {
            if (failWrites) return false
            this.value = value.copyOf()
            writeCount++
            return true
        }

        override fun clear(): Boolean {
            value = null
            return true
        }
    }

    private class FakeKeyBackend : SessionPickleKeyBackend {
        private var present = false
        private var nextId = 1
        private val wrapped = mutableMapOf<String, Pair<ByteArray, ByteArray>>()

        override fun hasWrappingKey(): Boolean = present

        override fun ensureWrappingKey() {
            present = true
        }

        override fun wrap(pickleKey: ByteArray, aad: ByteArray): ByteArray {
            check(present)
            val envelope = byteArrayOf((nextId ushr 8).toByte(), nextId.toByte())
            nextId++
            wrapped[key(envelope)] = aad.copyOf() to pickleKey.copyOf()
            return envelope
        }

        override fun unwrap(envelope: ByteArray, aad: ByteArray): ByteArray {
            check(present)
            val entry = wrapped[key(envelope)] ?: throw SessionStateException("Unknown fake wrapped key")
            if (!entry.first.contentEquals(aad)) throw SessionStateException("Fake wrapped key AAD mismatch")
            return entry.second.copyOf()
        }

        override fun deleteWrappingKey() {
            present = false
            wrapped.clear()
        }

        private fun key(value: ByteArray): String = Base64.getEncoder().encodeToString(value)
    }

    private class FakeEngine : SessionEngine {
        private val accountPublic = NativeAccountPublicState(
            olmEd25519IdentityKey = bytes(0x21, 32),
            olmCurve25519IdentityKey = bytes(0x22, 32),
            unpublishedOneTimeKeys = listOf(bytes(0x31, 32), bytes(0x32, 32)),
            storedOneTimeKeyCount = 2,
        )
        var decryptPlaintext = "plaintext".toByteArray()
        var encryptCalls = 0
        var decryptCalls = 0

        override fun createAccount(): NativeAccountMutation = NativeAccountMutation(
            NativeSessionSnapshot("account-0".toByteArray(), bytes(0x70, 32)),
            accountPublic.copy(unpublishedOneTimeKeys = accountPublic.unpublishedOneTimeKeys.map(ByteArray::copyOf)),
        )

        override fun inspectAccount(snapshot: NativeSessionSnapshot): NativeAccountPublicState {
            val unpublished = if (String(snapshot.ciphertext) == "account-0") {
                accountPublic.unpublishedOneTimeKeys.map(ByteArray::copyOf)
            } else {
                emptyList()
            }
            return accountPublic.copy(unpublishedOneTimeKeys = unpublished)
        }

        override fun markAccountKeysPublished(snapshot: NativeSessionSnapshot): NativeSessionSnapshot =
            NativeSessionSnapshot("account-published".toByteArray(), bytes(0x71, 32))

        override fun generateAccountOneTimeKeys(
            snapshot: NativeSessionSnapshot,
            count: Int,
        ): NativeAccountMutation = throw UnsupportedOperationException()

        override fun createOutboundSession(
            account: NativeSessionSnapshot,
            peerCurve25519IdentityKey: ByteArray,
            peerOneTimeKey: ByteArray,
            initialPlaintext: ByteArray,
        ): NativeOutboundSessionResult = NativeOutboundSessionResult(
            NativeSessionSnapshot("session-out".toByteArray(), bytes(0x72, 32)),
            "session-out-id",
            NativeSessionMessage(SESSION_OLM_MESSAGE_PRE_KEY, "pre-key-frame".toByteArray()),
        )

        override fun createInboundSession(
            account: NativeSessionSnapshot,
            expectedPeerCurve25519IdentityKey: ByteArray,
            messageType: Int,
            olmMessage: ByteArray,
        ): NativeInboundSessionResult = throw UnsupportedOperationException()

        override fun encryptSession(
            session: NativeSessionSnapshot,
            plaintext: ByteArray,
        ): NativeEncryptResult {
            encryptCalls++
            return NativeEncryptResult(
                NativeSessionSnapshot("session-encrypted".toByteArray(), bytes(0x75, 32)),
                NativeSessionMessage(SESSION_OLM_MESSAGE_NORMAL, "ciphertext".toByteArray()),
            )
        }

        override fun decryptSession(
            session: NativeSessionSnapshot,
            messageType: Int,
            olmMessage: ByteArray,
        ): NativeDecryptResult {
            decryptCalls++
            return NativeDecryptResult(
                NativeSessionSnapshot("session-decrypted".toByteArray(), bytes(0x76, 32)),
                decryptPlaintext.copyOf(),
            )
        }
    }

    companion object {
        private val OWNER = bytes(0x11, 32)
        private val CONTACT = bytes(0x20, 16)
        private val PEER = bytes(0x30, 32)
        private val INVITE = bytes(0x43, 32)

        private fun inboundCiphertext(): SessionCiphertext = SessionCiphertext(
            senderIdentityId = PEER.copyOf(),
            recipientIdentityId = OWNER.copyOf(),
            senderAccountGeneration = 4,
            recipientAccountGeneration = 1,
            olmMessageType = SESSION_OLM_MESSAGE_NORMAL,
            olmMessage = "ciphertext".toByteArray(),
        )

        private fun outboundHandoff(
            plaintext: ByteArray,
            index: Int = 1,
        ): SessionMessageHandoff = handoff(
            plaintext,
            index,
            SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
        )

        private fun inboundHandoff(
            plaintext: ByteArray,
            index: Int = 1,
        ): SessionMessageHandoff = handoff(
            plaintext,
            index,
            SessionStateCodec.HANDOFF_DIRECTION_INBOUND,
        )

        private fun handoff(
            plaintext: ByteArray,
            index: Int,
            direction: Int,
        ): SessionMessageHandoff {
            val messageId = ByteArray(SessionStateCodec.MESSAGE_ID_BYTES)
            messageId[0] = ((index ushr 8) and 0xff).toByte()
            messageId[1] = (index and 0xff).toByte()
            if (messageId.all { it == 0.toByte() }) messageId[0] = 1
            return SessionMessageHandoff(
                localContactId = CONTACT.copyOf(),
                peerIdentityId = PEER.copyOf(),
                messageId = messageId,
                direction = direction,
                encodedPlaintext = plaintext.copyOf(),
                encodedEnvelope = "envelope".toByteArray(),
            )
        }

        private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
    }
}
