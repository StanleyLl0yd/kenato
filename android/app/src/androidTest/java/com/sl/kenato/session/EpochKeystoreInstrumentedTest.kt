package com.sl.kenato.session

import android.os.Build
import android.os.SystemClock
import android.security.keystore.KeyInfo
import android.util.AtomicFile
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Physical Android acceptance only. All keys and files are test-only; no production M3
 * store, aliases, ratchets, identity, voice permission or network transport are touched.
 * CI only compiles this APK; emulator/device results require separate evidence.
 */
@RunWith(AndroidJUnit4::class)
class EpochKeystoreInstrumentedTest {
    private val token = ByteArray(16).also(SecureRandom()::nextBytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private val prefix = "com.sl.kenato.session.epoch-acceptance.v1.$token."
    private val backend = AndroidKeystoreSessionEpochKeyBackend(prefix)
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val testFile = File(context.noBackupFilesDir, "kenato_epoch_probe_$token.bin")

    @After
    fun destroyOnlyThisTestNamespace() {
        try {
            backend.epochIds().forEach(backend::retireEpoch)
            assertTrue("Test Keystore aliases must be removed", backend.epochIds().isEmpty())
        } finally {
            AtomicFile(testFile).delete()
        }
    }

    @Test
    fun aesGcmKeyIsNonexportableAndRemainsUsableAfterBackendReopen() {
        val id = backend.createEpoch()
        val plaintext = "synthetic acceptance payload; no session identifiers".toByteArray()
        val aad = "M5-INSTRUMENT-TEST-V1".toByteArray()
        val encrypted = backend.encrypt(id, plaintext, aad)
        assertFalse(encrypted.contentEquals(plaintext))
        val reopened = AndroidKeystoreSessionEpochKeyBackend(prefix)
        assertEquals(setOf(id), reopened.epochIds())
        assertArrayEquals(plaintext, reopened.decrypt(id, encrypted, aad))
        assertThrows(SessionStateException::class.java) {
            reopened.decrypt(id, encrypted, "WRONG-AAD".toByteArray())
        }
        val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .getKey(prefix + id, null) as? SecretKey
            ?: throw AssertionError("Expected AndroidKeyStore AES SecretKey")
        assertTrue("Expected non-exportable AndroidKeyStore AES key", key.encoded == null)
        val keyInfo = SecretKeyFactory.getInstance("AES", "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val security = if (Build.VERSION.SDK_INT >= 31) {
            "level=${keyInfo.securityLevel}"
        } else {
            "insideSecureHardware=${keyInfo.isInsideSecureHardware}"
        }
        Log.i("KenatoM5Acceptance", "Android API=${Build.VERSION.SDK_INT} $security")
    }

    @Test
    fun realAtomicFileAndRealKeystoreRejectRestoredOldAuthenticCiphertext() {
        val backing = PhysicalAtomicFile(testFile)
        val store = EpochBoundSessionStateStore(backing, backend)
        val initial = canonicalState(revision = 0)
        val advanced = canonicalState(revision = 1)

        val firstStart = SystemClock.elapsedRealtimeNanos()
        assertTrue(store.write(initial))
        val firstMillis = (SystemClock.elapsedRealtimeNanos() - firstStart) / 1_000_000
        val oldCiphertext = backing.read()!!
        val retired = backend.epochIds().single()

        val secondStart = SystemClock.elapsedRealtimeNanos()
        assertTrue(store.write(advanced))
        val secondMillis = (SystemClock.elapsedRealtimeNanos() - secondStart) / 1_000_000
        assertEquals(1, backend.epochIds().size)
        assertFalse(backend.epochIds().contains(retired))
        assertArrayEquals(advanced, EpochBoundSessionStateStore(backing,
            AndroidKeystoreSessionEpochKeyBackend(prefix)).read())

        // Simulates a file-only attacker restoring a genuine previous AtomicFile snapshot.
        backing.write(oldCiphertext)
        assertThrows(SessionStateException::class.java) { store.read() }
        assertThrows(SessionStateException::class.java) { store.write(initial) }
        Log.i("KenatoM5Acceptance",
            "synthetic Keystore+AtomicFile commits: first=${firstMillis}ms second=${secondMillis}ms")
    }

    @Test
    fun unexpectedSecondKeystoreAliasBlocksAuthenticatedRead() {
        val backing = PhysicalAtomicFile(testFile)
        val store = EpochBoundSessionStateStore(backing, backend)
        assertTrue(store.write(canonicalState(revision = 0)))
        backend.createEpoch()
        assertEquals(2, backend.epochIds().size)
        assertThrows(SessionStateException::class.java) { store.read() }
        assertThrows(SessionStateException::class.java) {
            EpochBoundSessionStateStore(backing,
                AndroidKeystoreSessionEpochKeyBackend(prefix)).read()
        }
    }

    private class PhysicalAtomicFile(path: File) : SessionStateStore {
        private val file = AtomicFile(path)
        override fun read(): ByteArray? = try {
            file.openRead().use { it.readBytes() }
        } catch (_: java.io.FileNotFoundException) {
            null
        }
        override fun write(value: ByteArray): Boolean {
            val output = file.startWrite()
            return try {
                output.write(value)
                output.fd.sync()
                file.finishWrite(output)
                true
            } catch (error: Exception) {
                runCatching { file.failWrite(output) }
                throw error
            }
        }
        override fun clear(): Boolean {
            file.delete()
            return !file.baseFile.exists()
        }
    }

    private fun canonicalState(revision: Long): ByteArray = SessionStateCodec.encode(
        SessionState(
            ownerIdentityId = ByteArray(32) { 0x11.toByte() },
            account = SessionAccountState(
                accountGeneration = 1,
                publicationRevision = revision,
                nextOneTimeKeyId = 1,
                olmEd25519IdentityKey = ByteArray(32) { 0x21.toByte() },
                olmCurve25519IdentityKey = ByteArray(32) { 0x22.toByte() },
                oneTimeKeys = emptyList(),
                snapshot = WrappedSessionSnapshot(
                    ciphertext = "synthetic-account-pickle".toByteArray(),
                    wrappedPickleKey = ByteArray(32) { 0x31.toByte() },
                ),
            ),
            sessions = emptyList(),
            messageHandoffs = emptyList(),
        ),
    )
}
