package com.sl.kenato.session

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalSessionRepositoryTest {
    @Test
    fun accountCreationPersistsAndRestartValidatesNativeState() {
        val fixture = Fixture()
        val owner = bytes(0x11, 32)

        val created = fixture.repository.loadOrCreateAccount(owner)
        val restarted = fixture.newRepository().loadOrCreateAccount(owner)

        assertEquals(1L, created.accountGeneration)
        assertEquals(0L, created.publicationRevision)
        assertEquals(3L, created.nextOneTimeKeyId)
        assertEquals(2, created.oneTimeKeys.size)
        assertArrayEquals(created.olmEd25519IdentityKey, restarted.olmEd25519IdentityKey)
        assertArrayEquals(created.olmCurve25519IdentityKey, restarted.olmCurve25519IdentityKey)
        assertEquals(1, fixture.store.writeCount)
    }

    @Test
    fun persistedStateWithoutKeystoreKeyFailsClosed() {
        val fixture = Fixture()
        val owner = bytes(0x11, 32)
        fixture.repository.loadOrCreateAccount(owner)
        fixture.keys.deleteWrappingKey()

        assertThrows(SessionStateException::class.java) {
            fixture.newRepository().loadOrCreateAccount(owner)
        }
    }

    @Test
    fun keystoreKeyWithoutStateRequiresExplicitRecovery() {
        val fixture = Fixture()
        val owner = bytes(0x11, 32)
        fixture.keys.ensureWrappingKey()

        assertThrows(SessionStateException::class.java) {
            fixture.repository.loadOrCreateAccount(owner)
        }
    }

    @Test
    fun outboundCiphertextIsNotReturnedWhenPersistenceFails() {
        val fixture = Fixture()
        val owner = bytes(0x11, 32)
        fixture.repository.loadOrCreateAccount(owner)
        fixture.store.failWrites = true

        assertThrows(SessionStateException::class.java) {
            fixture.repository.createOutboundSession(
                ownerIdentityId = owner,
                localContactId = bytes(0x20, 16),
                peerIdentityId = bytes(0x30, 32),
                peerAccountGeneration = 4,
                peerOlmEd25519IdentityKey = bytes(0x40, 32),
                peerOlmCurve25519IdentityKey = bytes(0x41, 32),
                peerOneTimeKey = bytes(0x42, 32),
                initialPlaintext = "control".toByteArray(),
            )
        }
        assertEquals(0, fixture.repository.currentState(owner)!!.sessions.size)
    }

    @Test
    fun inboundControlMismatchDoesNotConsumeKeyOrCommitSession() {
        val fixture = Fixture()
        val owner = bytes(0x11, 32)
        fixture.repository.loadOrCreateAccount(owner)
        fixture.engine.inboundPlaintext = "wrong-control".toByteArray()
        val writesBefore = fixture.store.writeCount

        assertThrows(SessionStateException::class.java) {
            fixture.repository.createInboundSession(
                ownerIdentityId = owner,
                localContactId = bytes(0x20, 16),
                peerIdentityId = bytes(0x30, 32),
                peerAccountGeneration = 4,
                peerOlmEd25519IdentityKey = bytes(0x40, 32),
                peerOlmCurve25519IdentityKey = bytes(0x41, 32),
                consumedOneTimeKeyId = 1,
                expectedInitialPlaintext = "expected-control".toByteArray(),
                messageType = 0,
                olmMessage = "pre-key".toByteArray(),
            )
        }

        assertEquals(writesBefore, fixture.store.writeCount)
        val state = fixture.repository.currentState(owner)!!
        assertEquals(2, state.account.oneTimeKeys.size)
        assertTrue(state.sessions.isEmpty())
    }

    @Test
    fun inboundAccountAndSessionAdvanceInOneAtomicStateWrite() {
        val fixture = Fixture()
        val owner = bytes(0x11, 32)
        fixture.repository.loadOrCreateAccount(owner)
        fixture.engine.inboundPlaintext = "expected-control".toByteArray()
        val writesBefore = fixture.store.writeCount

        val plaintext = fixture.repository.createInboundSession(
            ownerIdentityId = owner,
            localContactId = bytes(0x20, 16),
            peerIdentityId = bytes(0x30, 32),
            peerAccountGeneration = 4,
            peerOlmEd25519IdentityKey = bytes(0x40, 32),
            peerOlmCurve25519IdentityKey = bytes(0x41, 32),
            consumedOneTimeKeyId = 1,
            expectedInitialPlaintext = "expected-control".toByteArray(),
            messageType = 0,
            olmMessage = "pre-key".toByteArray(),
        )

        assertArrayEquals("expected-control".toByteArray(), plaintext)
        assertEquals(writesBefore + 1, fixture.store.writeCount)
        val state = fixture.repository.currentState(owner)!!
        assertEquals(1, state.account.oneTimeKeys.size)
        assertEquals(1, state.sessions.size)
        assertFalse(state.sessions.single().initiator)
    }

    @Test
    fun encryptAndDecryptAdvanceStateBeforeReturningApplicationData() {
        val fixture = Fixture()
        val owner = bytes(0x11, 32)
        fixture.repository.loadOrCreateAccount(owner)
        val contact = bytes(0x20, 16)
        fixture.repository.createOutboundSession(
            owner,
            contact,
            bytes(0x30, 32),
            4,
            bytes(0x40, 32),
            bytes(0x41, 32),
            bytes(0x42, 32),
            "control".toByteArray(),
        )

        val encrypted = fixture.repository.encrypt(owner, contact, "hello".toByteArray())
        assertArrayEquals("ciphertext".toByteArray(), encrypted.ciphertext)

        fixture.engine.decryptPlaintext = "hello".toByteArray()
        val decrypted = fixture.repository.decrypt(owner, contact, 1, "ciphertext".toByteArray())
        assertArrayEquals("hello".toByteArray(), decrypted)

        fixture.store.failWrites = true
        assertThrows(SessionStateException::class.java) {
            fixture.repository.encrypt(owner, contact, "blocked".toByteArray())
        }
        assertThrows(SessionStateException::class.java) {
            fixture.repository.decrypt(owner, contact, 1, "blocked".toByteArray())
        }
    }

    @Test
    fun duplicateActiveSessionForPinnedContactFailsBeforeNativeMutation() {
        val fixture = Fixture()
        val owner = bytes(0x11, 32)
        fixture.repository.loadOrCreateAccount(owner)
        val contact = bytes(0x20, 16)
        fixture.repository.createOutboundSession(
            owner,
            contact,
            bytes(0x30, 32),
            4,
            bytes(0x40, 32),
            bytes(0x41, 32),
            bytes(0x42, 32),
            "control".toByteArray(),
        )
        val outboundCalls = fixture.engine.outboundCalls

        assertThrows(SessionStateException::class.java) {
            fixture.repository.createOutboundSession(
                owner,
                contact,
                bytes(0x31, 32),
                5,
                bytes(0x50, 32),
                bytes(0x51, 32),
                bytes(0x52, 32),
                "control-2".toByteArray(),
            )
        }
        assertEquals(outboundCalls, fixture.engine.outboundCalls)
    }

    private class Fixture {
        val engine = FakeEngine()
        val keys = FakeKeyBackend()
        val store = FakeStateStore()
        val repository = newRepository()

        fun newRepository(): LocalSessionRepository = LocalSessionRepository(engine, keys, store)
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
            if (!entry.first.contentEquals(aad)) {
                throw SessionStateException("Fake wrapped key AAD mismatch")
            }
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
        var inboundPlaintext = "control".toByteArray()
        var decryptPlaintext = "plaintext".toByteArray()
        var outboundCalls = 0

        override fun createAccount(): NativeAccountMutation = NativeAccountMutation(
            NativeSessionSnapshot("account-0".toByteArray(), bytes(0x70, 32)),
            accountPublic.copy(unpublishedOneTimeKeys = accountPublic.unpublishedOneTimeKeys.map(ByteArray::copyOf)),
        )

        override fun inspectAccount(snapshot: NativeSessionSnapshot): NativeAccountPublicState {
            val stored = if (String(snapshot.ciphertext).startsWith("account-consumed")) 1 else 2
            return accountPublic.copy(
                unpublishedOneTimeKeys = emptyList(),
                storedOneTimeKeyCount = stored,
            )
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
        ): NativeOutboundSessionResult {
            outboundCalls++
            return NativeOutboundSessionResult(
                NativeSessionSnapshot("session-out".toByteArray(), bytes(0x72, 32)),
                "session-out-id",
                NativeSessionMessage(0, "pre-key-frame".toByteArray()),
            )
        }

        override fun createInboundSession(
            account: NativeSessionSnapshot,
            expectedPeerCurve25519IdentityKey: ByteArray,
            messageType: Int,
            olmMessage: ByteArray,
        ): NativeInboundSessionResult = NativeInboundSessionResult(
            NativeSessionSnapshot("account-consumed".toByteArray(), bytes(0x73, 32)),
            NativeSessionSnapshot("session-in".toByteArray(), bytes(0x74, 32)),
            "session-in-id",
            inboundPlaintext.copyOf(),
        )

        override fun encryptSession(
            session: NativeSessionSnapshot,
            plaintext: ByteArray,
        ): NativeEncryptResult = NativeEncryptResult(
            NativeSessionSnapshot("session-encrypted".toByteArray(), bytes(0x75, 32)),
            NativeSessionMessage(1, "ciphertext".toByteArray()),
        )

        override fun decryptSession(
            session: NativeSessionSnapshot,
            messageType: Int,
            olmMessage: ByteArray,
        ): NativeDecryptResult = NativeDecryptResult(
            NativeSessionSnapshot("session-decrypted".toByteArray(), bytes(0x76, 32)),
            decryptPlaintext.copyOf(),
        )
    }

    companion object {
        private fun bytes(value: Int, size: Int): ByteArray = ByteArray(size) { value.toByte() }
    }
}
