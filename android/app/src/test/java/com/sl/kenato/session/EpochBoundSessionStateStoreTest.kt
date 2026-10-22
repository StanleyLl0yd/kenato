package com.sl.kenato.session

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Adversarial JVM model, NOT Android Keystore acceptance. */
class EpochBoundSessionStateStoreTest {
    @Test
    fun freshStateIsEncryptedAndRoundTripsWithOnlyOneKey() {
        val f = Fixture()
        val raw = state(withVoice = true)
        assertTrue(f.store.write(raw))
        assertEquals("KAE2", f.disk.bytes!!.copyOfRange(0, 4).toString(Charsets.UTF_8))
        assertFalse(f.disk.bytes!!.contentEquals(raw))
        assertFalse(f.disk.bytes!!.toString(Charsets.ISO_8859_1).contains("private-ip-sdp"))
        assertEquals(1, f.keys.epochIds().size)
        assertArrayEquals(raw, EpochBoundSessionStateStore(f.disk, f.keys).read())
    }

    @Test
    fun previousAuthenticEpochIsRejectedAfterSuccessfulReplacement() {
        val f = Fixture()
        val old = state()
        val advanced = state(withVoice = true)
        assertTrue(f.store.write(old))
        val prior = f.disk.bytes!!.copyOf()
        val oldEpoch = f.keys.epochIds().single()
        assertTrue(f.store.write(advanced))
        assertFalse(f.keys.epochIds().contains(oldEpoch))
        assertArrayEquals(advanced, f.store.read())
        f.disk.bytes = prior
        assertThrows(SessionStateException::class.java) { f.store.read() }
        assertThrows(SessionStateException::class.java) { f.store.write(old) }
    }

    @Test
    fun restoreOfOlderCiphertextFailsWhenNewKeyIsTheOnlyAlias() {
        val f = Fixture()
        f.store.write(state())
        val previous = f.disk.bytes!!.copyOf()
        f.store.write(state(withVoice = true))
        f.disk.bytes = previous
        assertThrows(SessionStateException::class.java) { EpochBoundSessionStateStore(f.disk, f.keys).read() }
    }

    @Test
    fun crashAfterCreatingNewKeyBeforeFileReplacementFailsClosed() {
        val f = Fixture()
        f.store.write(state())
        f.disk.failWrites = true
        assertThrows(SessionStateException::class.java) { f.store.write(state(withVoice = true)) }
        assertEquals(2, f.keys.epochIds().size)
        assertThrows(SessionStateException::class.java) { f.store.read() }
        assertThrows(SessionStateException::class.java) { f.store.write(state()) }
    }

    @Test
    fun atomicWriteThatCommitsButReportsFailureDoesNotAcknowledge() {
        val f = Fixture()
        f.store.write(state())
        f.disk.commitButReportFailure = true
        assertThrows(SessionStateException::class.java) { f.store.write(state(withVoice = true)) }
        assertEquals(2, f.keys.epochIds().size)
        assertThrows(SessionStateException::class.java) { f.store.read() }
    }

    @Test
    fun crashAfterDiskCommitBeforeOldAliasRetirementFailsClosed() {
        val f = Fixture()
        f.store.write(state())
        f.keys.failRetire = true
        assertThrows(SessionStateException::class.java) { f.store.write(state(withVoice = true)) }
        assertEquals(2, f.keys.epochIds().size)
        assertThrows(SessionStateException::class.java) { f.store.read() }
        f.keys.failRetire = false
        // No autonomous repair/retry is permitted on restart.
        assertThrows(SessionStateException::class.java) {
            EpochBoundSessionStateStore(f.disk, f.keys).read()
        }
    }

    @Test
    fun firstWriteFailureLeavesOrphanKeyAndRefusesFreshIdentity() {
        val f = Fixture()
        f.disk.failWrites = true
        assertThrows(SessionStateException::class.java) { f.store.write(state()) }
        assertNull(f.disk.bytes)
        assertEquals(1, f.keys.epochIds().size)
        f.disk.failWrites = false
        assertThrows(SessionStateException::class.java) { f.store.read() }
        assertThrows(SessionStateException::class.java) { f.store.write(state()) }
    }

    @Test
    fun deletingTheFileDoesNotEnableAnUnacknowledgedNewAccount() {
        val f = Fixture()
        f.store.write(state())
        f.disk.bytes = null
        assertThrows(SessionStateException::class.java) { f.store.read() }
        assertThrows(SessionStateException::class.java) { f.store.write(state()) }
    }

    @Test
    fun losingTheOnlyAliasCannotRegenerateItOrAcceptTheCiphertext() {
        val f = Fixture()
        f.store.write(state())
        val id = f.keys.epochIds().single()
        val encrypted = f.disk.bytes!!.copyOf()
        f.keys.retireEpoch(id)
        assertThrows(SessionStateException::class.java) { f.store.read() }
        assertThrows(SessionStateException::class.java) { f.store.write(state(withVoice = true)) }
        assertArrayEquals(encrypted, f.disk.bytes)
        assertTrue(f.keys.epochIds().isEmpty())
    }

    @Test
    fun extraUnexpectedAliasFailsClosedBeforeCryptoOrDiskMutation() {
        val f = Fixture()
        f.store.write(state())
        val unchanged = f.disk.bytes!!.copyOf()
        f.keys.createEpoch()
        assertThrows(SessionStateException::class.java) { f.store.read() }
        assertThrows(SessionStateException::class.java) { f.store.write(state()) }
        assertArrayEquals(unchanged, f.disk.bytes)
    }

    @Test
    fun corruptedCiphertextAndForgedEpochAreRejected() {
        val f = Fixture()
        f.store.write(state())
        val intact = f.disk.bytes!!.copyOf()
        f.disk.bytes = intact.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(SessionStateException::class.java) { f.store.read() }
        f.disk.bytes = intact.copyOf().also { it[8] = 'f'.code.toByte() }
        assertThrows(SessionStateException::class.java) { f.store.read() }
        f.disk.bytes = intact.copyOf().also { it[4] = 99 }
        assertThrows(SessionStateException::class.java) { f.store.read() }
        f.disk.bytes = intact.copyOfRange(0, 10)
        assertThrows(SessionStateException::class.java) { f.store.read() }
    }

    @Test
    fun legacyMigrationAndImplicitDestructiveRecoveryAreNotImplemented() {
        val f = Fixture()
        f.disk.bytes = state() // KNS3 plaintext must not be silently loaded by this prototype.
        assertThrows(SessionStateException::class.java) { f.store.read() }
        assertThrows(SessionStateException::class.java) { f.store.write(state()) }
        assertThrows(SessionStateException::class.java) { f.store.clear() }
        assertEquals(0, f.keys.epochIds().size)
        assertEquals(0, f.disk.writes)
    }

    @Test
    fun deliberateReadBackVerificationRejectsUnreliableBackingStore() {
        val f = Fixture()
        f.disk.corruptAfterWrite = true
        assertThrows(SessionStateException::class.java) { f.store.write(state()) }
        assertThrows(SessionStateException::class.java) { f.store.read() }
    }

    private class Fixture {
        val disk = Disk()
        val keys = JvmEpochKeys()
        val store = EpochBoundSessionStateStore(disk, keys)
    }

    private class Disk : SessionStateStore {
        var bytes: ByteArray? = null
        var writes = 0
        var failWrites = false
        var commitButReportFailure = false
        var corruptAfterWrite = false
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(value: ByteArray): Boolean {
            if (failWrites) return false
            bytes = value.copyOf()
            writes++
            if (corruptAfterWrite) bytes!![bytes!!.lastIndex] = (bytes!!.last().toInt() xor 1).toByte()
            return !commitButReportFailure
        }
        override fun clear(): Boolean {
            bytes = null
            return true
        }
    }

    private class JvmEpochKeys : SessionEpochKeyBackend {
        private val random = SecureRandom()
        private val keys = linkedMapOf<String, SecretKeySpec>()
        private var next = 0
        var failRetire = false
        override fun epochIds(): Set<String> = keys.keys.toSet()
        override fun createEpoch(): String {
            next++
            val epoch = next.toString(16).padStart(32, '0')
            keys[epoch] = SecretKeySpec(ByteArray(32).also(random::nextBytes), "AES")
            return epoch
        }
        override fun encrypt(epochId: String, plaintext: ByteArray, aad: ByteArray): ByteArray {
            val key = keys[epochId] ?: throw SessionStateException("Missing epoch")
            val iv = ByteArray(12).also(random::nextBytes)
            return Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
                updateAAD(aad)
                iv + doFinal(plaintext)
            }
        }
        override fun decrypt(epochId: String, envelope: ByteArray, aad: ByteArray): ByteArray {
            val key = keys[epochId] ?: throw SessionStateException("Missing epoch")
            return Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.copyOfRange(0, 12)))
                updateAAD(aad)
                doFinal(envelope.copyOfRange(12, envelope.size))
            }
        }
        override fun retireEpoch(epochId: String) {
            if (failRetire) throw SessionStateException("Simulated Keystore delete failure")
            if (keys.remove(epochId) == null) throw SessionStateException("Epoch already gone")
        }
    }

    private fun state(withVoice: Boolean = false): ByteArray {
        val contact = ByteArray(16) { 0x41.toByte() }
        val peer = ByteArray(32) { 0x42.toByte() }
        return SessionStateCodec.encode(
            SessionState(
                ownerIdentityId = ByteArray(32) { 0x11.toByte() },
                account = SessionAccountState(
                    accountGeneration = 1,
                    publicationRevision = 0,
                    nextOneTimeKeyId = 1,
                    olmEd25519IdentityKey = ByteArray(32) { 0x21.toByte() },
                    olmCurve25519IdentityKey = ByteArray(32) { 0x22.toByte() },
                    oneTimeKeys = emptyList(),
                    snapshot = WrappedSessionSnapshot(
                        ciphertext = "account-pickle".toByteArray(),
                        wrappedPickleKey = ByteArray(32) { 0x31.toByte() },
                    ),
                ),
                sessions = listOf(
                    PersistedSession(
                        localContactId = contact,
                        peerIdentityId = peer,
                        peerAccountGeneration = 2,
                        peerOlmEd25519IdentityKey = ByteArray(32) { 0x43.toByte() },
                        peerOlmCurve25519IdentityKey = ByteArray(32) { 0x44.toByte() },
                        sessionId = "session-1",
                        initiator = true,
                        snapshot = WrappedSessionSnapshot(
                            ciphertext = "session-pickle".toByteArray(),
                            wrappedPickleKey = ByteArray(32) { 0x45.toByte() },
                        ),
                        pendingInit = null,
                    ),
                ),
                messageHandoffs = if (withVoice) listOf(
                    SessionMessageHandoff(
                        localContactId = contact,
                        peerIdentityId = peer,
                        messageId = ByteArray(16) { 0x51.toByte() },
                        direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                        encodedPlaintext = "v=0\\r\\na=candidate: private-ip-sdp".toByteArray(),
                        encodedEnvelope = "opaque M4 encrypted".toByteArray(),
                    ),
                ) else emptyList(),
            ),
        )
    }
}
