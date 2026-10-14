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

class EncryptedSessionStateStoreTest {
    @Test
    fun fullM3StateAndPendingVoicePlaintextAreEncryptedBeforeAnyDiskWrite() {
        val disk = MemoryDisk()
        val crypto = JvmAesGcm()
        val store = EncryptedSessionStateStore(disk, crypto)
        val raw = rawState(includeVoice = true)
        assertTrue(String(raw, Charsets.ISO_8859_1).contains("v=0"))
        assertTrue(store.write(raw))
        assertEquals(1, disk.writes)
        assertEquals("KSAE", disk.bytes!!.copyOfRange(0, 4).toString(Charsets.UTF_8))
        assertFalse(disk.bytes!!.contentEquals(raw))
        assertFalse(disk.bytes!!.toString(Charsets.ISO_8859_1).contains("v=0"))
        val recovered = EncryptedSessionStateStore(disk, crypto).read()!!
        assertArrayEquals(raw, recovered)
        assertEquals(1, SessionStateCodec.decode(recovered).messageHandoffs.size)
    }

    @Test
    fun canonicalLegacyStateIsAtomicallyEncryptedBeforeReturningFromRead() {
        val legacy = rawState()
        val disk = MemoryDisk().also { it.bytes = legacy.copyOf() }
        val crypto = JvmAesGcm()
        val first = EncryptedSessionStateStore(disk, crypto)
        assertArrayEquals(legacy, first.read()!!)
        assertEquals(1, disk.writes)
        assertFalse(disk.bytes!!.contentEquals(legacy))
        assertEquals("KSAE", disk.bytes!!.copyOfRange(0, 4).toString(Charsets.UTF_8))
        assertArrayEquals(legacy, EncryptedSessionStateStore(disk, crypto).read()!!)
        assertEquals(1, disk.writes)
    }

    @Test
    fun failedLegacyReplacementFailsClosedWithoutReturningUnencryptedState() {
        val disk = MemoryDisk().also {
            it.bytes = rawState()
            it.failWrites = true
        }
        assertThrows(SessionStateException::class.java) {
            EncryptedSessionStateStore(disk, JvmAesGcm()).read()
        }
        assertEquals("KNS3", disk.bytes!!.copyOfRange(0, 4).toString(Charsets.UTF_8))
    }

    @Test
    fun wrongKeyOrTamperedEnvelopeFailClosedWithoutRegeneration() {
        val disk = MemoryDisk()
        val crypto = JvmAesGcm()
        val store = EncryptedSessionStateStore(disk, crypto)
        store.write(rawState())
        val original = disk.bytes!!.copyOf()
        crypto.rotateKey()
        assertThrows(SessionStateException::class.java) { store.read() }
        assertArrayEquals(original, disk.bytes)
        disk.bytes = original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(SessionStateException::class.java) { store.read() }
        disk.bytes = original.copyOf().also { it[4] = 99 }
        assertThrows(SessionStateException::class.java) { store.read() }
    }

    @Test
    fun lostKeystoreKeyCannotOverwriteProtectedRatchetOrVoiceHandoffs() {
        val disk = MemoryDisk()
        val crypto = JvmAesGcm()
        val store = EncryptedSessionStateStore(disk, crypto)
        assertTrue(store.write(rawState(includeVoice = true)))
        val protectedBefore = disk.bytes!!.copyOf()
        crypto.rotateKey()
        assertThrows(SessionStateException::class.java) {
            store.write(rawState(includeVoice = false))
        }
        assertArrayEquals(protectedBefore, disk.bytes)
        assertEquals(1, disk.writes)
    }

    @Test
    fun lostKeyBetweenAuthenticationAndReplacementCannotCreateNewAlias() {
        val disk = MemoryDisk()
        val crypto = JvmAesGcm()
        val store = EncryptedSessionStateStore(disk, crypto)
        assertTrue(store.write(rawState(includeVoice = true)))
        val original = disk.bytes!!.copyOf()
        crypto.simulateKeyLossAtEncrypt = true
        assertThrows(SessionStateException::class.java) {
            store.write(rawState(includeVoice = false))
        }
        assertArrayEquals(original, disk.bytes)
        assertEquals(1, disk.writes)
    }

    @Test
    fun corruptOrUnknownExistingStateCannotBeOverwrittenWithoutRecovery() {
        val disk = MemoryDisk()
        val store = EncryptedSessionStateStore(disk, JvmAesGcm())
        assertTrue(store.write(rawState(includeVoice = true)))
        val original = disk.bytes!!.copyOf()
        for (corrupted in listOf(
            original.copyOf().also { it[4] = 5 },
            original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
            ByteArray(40) { 0x55.toByte() },
        )) {
            disk.bytes = corrupted.copyOf()
            assertThrows(SessionStateException::class.java) {
                store.write(rawState(includeVoice = false))
            }
            assertArrayEquals(corrupted, disk.bytes)
        }
        assertEquals(1, disk.writes)
    }

    @Test
    fun unknownOrCorruptedLegacyStateIsNeverMigrated() {
        val disk = MemoryDisk()
        val store = EncryptedSessionStateStore(disk, JvmAesGcm())
        assertNull(store.read())
        disk.bytes = ByteArray(40) { 4 }
        assertThrows(SessionStateException::class.java) { store.read() }
        val bad = rawState().also { it[it.lastIndex] = 4 }
        disk.bytes = bad
        assertThrows(SessionStateException::class.java) { store.read() }
        assertEquals(0, disk.writes)
    }

    @Test
    fun explicitClearDeletesKeystoreKeyOnlyAfterDurableStoreDeletion() {
        val disk = MemoryDisk()
        val crypto = JvmAesGcm()
        val store = EncryptedSessionStateStore(disk, crypto)
        store.write(rawState())
        disk.failClear = true
        assertFalse(store.clear())
        assertEquals(0, crypto.deleted)
        assertTrue(disk.bytes != null)
        disk.failClear = false
        assertTrue(store.clear())
        assertNull(disk.bytes)
        assertEquals(1, crypto.deleted)
        assertNull(store.read())
    }


    @Test
    fun corruptedEncryptedFormatAndAuthenticatedNoncanonicalPlaintextFailClosed() {
        val disk = MemoryDisk()
        val crypto = JvmAesGcm()
        val store = EncryptedSessionStateStore(disk, crypto)
        assertTrue(store.write(rawState()))
        val original = disk.bytes!!.copyOf()

        // No legacy fallback is allowed once the stored envelope identifies KSAE.
        disk.bytes = original.copyOfRange(0, 5)
        assertThrows(SessionStateException::class.java) { store.read() }
        disk.bytes = original.copyOf().also { it[0] = 0 }
        assertThrows(SessionStateException::class.java) { store.read() }
        disk.bytes = original.copyOf().also { it[4] = 0 }
        assertThrows(SessionStateException::class.java) { store.read() }

        // Even valid AEAD cannot authorize malformed or noncanonical M3 state.
        val aad = "KENATO-M3-SESSION-STATE-AT-REST-V1\u0000".toByteArray(Charsets.UTF_8)
        val authenticatedButInvalid = crypto.encrypt(byteArrayOf(1, 2, 3, 4), aad, allowKeyCreation = true)
        disk.bytes = byteArrayOf('K'.code.toByte(), 'S'.code.toByte(), 'A'.code.toByte(),
            'E'.code.toByte(), 1) + authenticatedButInvalid
        assertThrows(SessionStateException::class.java) { store.read() }
        assertEquals(1, disk.writes)
    }

    @Test
    fun unsupportedOldReaderCannotSilentlyDowngradeProtectedFile() {
        val disk = MemoryDisk()
        val crypto = JvmAesGcm()
        val store = EncryptedSessionStateStore(disk, crypto)
        assertTrue(store.write(rawState(includeVoice = true)))
        val encryptedBefore = disk.bytes!!.copyOf()
        assertThrows(SessionStateException::class.java) {
            SessionStateCodec.decode(encryptedBefore)
        }
        assertArrayEquals(encryptedBefore, disk.bytes)
        assertArrayEquals(rawState(includeVoice = true), store.read()!!)
    }

    @Test
    fun failedEncryptedReplacementNeverWritesLegacyBytesOrReturnsDecryptedState() {
        val disk = MemoryDisk().also { it.failWrites = true }
        val crypto = JvmAesGcm()
        val store = EncryptedSessionStateStore(disk, crypto)
        assertFalse(store.write(rawState(includeVoice = true)))
        assertNull(disk.bytes)
        assertEquals(0, disk.writes)

        disk.bytes = rawState(includeVoice = true)
        assertThrows(SessionStateException::class.java) { store.read() }
        assertEquals("KNS3", disk.bytes!!.copyOfRange(0, 4).toString(Charsets.UTF_8))
        assertEquals(0, disk.writes)
    }

    @Test
    fun failureToRemoveKeyAfterFileDeletionMustSurfaceAndRemainRecoverable() {
        val disk = MemoryDisk()
        val crypto = JvmAesGcm()
        val store = EncryptedSessionStateStore(disk, crypto)
        assertTrue(store.write(rawState()))
        crypto.failDelete = true
        assertThrows(SessionStateException::class.java) { store.clear() }
        assertNull(disk.bytes)
        assertEquals(0, crypto.deleted)
        crypto.failDelete = false
        assertTrue(store.clear())
        assertEquals(1, crypto.deleted)
        assertNull(store.read())
    }

    private class MemoryDisk : SessionStateStore {
        var bytes: ByteArray? = null
        var writes = 0
        var failWrites = false
        var failClear = false
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(value: ByteArray): Boolean {
            if (failWrites) return false
            bytes = value.copyOf()
            writes++
            return true
        }
        override fun clear(): Boolean {
            if (failClear) return false
            bytes = null
            return true
        }
    }

    private class JvmAesGcm : SessionStateAtRestCipher {
        private var key = SecretKeySpec(ByteArray(32) { 0x37.toByte() }, "AES")
        private val random = SecureRandom()
        var deleted = 0
        var failDelete = false
        var simulateKeyLossAtEncrypt = false
        fun rotateKey() {
            key = SecretKeySpec(ByteArray(32) { 0x48.toByte() }, "AES")
        }
        override fun encrypt(
            plaintext: ByteArray, aad: ByteArray, allowKeyCreation: Boolean,
        ): ByteArray {
            if (simulateKeyLossAtEncrypt && !allowKeyCreation) {
                throw SessionStateException("Simulated missing Keystore alias after preflight")
            }
            val nonce = ByteArray(12).also(random::nextBytes)
            return Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
                updateAAD(aad)
                byteArrayOf(12) + nonce + doFinal(plaintext)
            }
        }
        override fun decrypt(envelope: ByteArray, aad: ByteArray): ByteArray =
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.copyOfRange(1, 13)))
                updateAAD(aad)
                doFinal(envelope.copyOfRange(13, envelope.size))
            }
        override fun deleteKeyForExplicitIdentityRecovery() {
            if (failDelete) throw SessionStateException("Simulated Keystore deletion failure")
            deleted++
        }
    }

    private fun rawState(includeVoice: Boolean = false): ByteArray {
        val contact = ByteArray(16) { 0x41.toByte() }
        val peer = ByteArray(32) { 0x42.toByte() }
        val state = SessionState(
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
            messageHandoffs = if (includeVoice) listOf(
                SessionMessageHandoff(
                    localContactId = contact,
                    peerIdentityId = peer,
                    messageId = ByteArray(16) { 0x51.toByte() },
                    direction = SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND,
                    encodedPlaintext = "v=0\\r\\na=candidate: private-ip-sdp".toByteArray(),
                    encodedEnvelope = "opaque M4 encrypted".toByteArray(),
                ),
            ) else emptyList(),
        )
        return SessionStateCodec.encode(state)
    }
}
