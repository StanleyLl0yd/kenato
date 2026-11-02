package com.sl.kenato.call

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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Real-device only; CI compiles but NEVER runs or installs this isolated suite. */
@RunWith(AndroidJUnit4::class)
class VoiceDispatchEpochKeystoreInstrumentedTest {
    private val token = ByteArray(16).also(SecureRandom()::nextBytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private val prefix = "com.sl.kenato.dispatch.epoch-acceptance.v1.$token."
    private val fileName = "kenato_m5_dispatch_probe_$token.bin"
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val keys = AndroidKeystoreVoiceDispatchLedgerEpochKeys(prefix)
    private val raw = AndroidAtomicFileVoiceDispatchLedgerRawStore(context, fileName)
    private val disposable = File(context.noBackupFilesDir, fileName)

    @After fun cleanOnlyTestNamespace() {
        try {
            keys.epochIds().forEach(keys::retireEpoch)
            assertTrue(keys.epochIds().isEmpty())
        } finally {
            AtomicFile(disposable).delete()
        }
    }

    @Test fun realKeyPersistsAndIsNotExportable() {
        val start = SystemClock.elapsedRealtimeNanos()
        assertTrue(ledger().claim(OWNER, permit(1)))
        val elapsedMs = (SystemClock.elapsedRealtimeNanos() - start) / 1_000_000
        val id = keys.epochIds().single()
        assertTrue(ledger().hasClaim(OWNER, permit(1)))
        assertFalse(ledger().claim(OWNER, permit(1)))
        assertEquals(setOf(id), AndroidKeystoreVoiceDispatchLedgerEpochKeys(prefix).epochIds())
        val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .getKey(prefix + id, null) as? SecretKey
            ?: throw AssertionError("Isolated Android AES key unavailable")
        assertTrue(key.encoded == null)
        val info = SecretKeyFactory.getInstance("AES", "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val security = if (Build.VERSION.SDK_INT >= 31) {
            "securityLevel=" + info.securityLevel
        } else {
            "insideSecureHardware=" + info.isInsideSecureHardware
        }
        Log.i("KenatoM5DispatchProbe", "API=" + Build.VERSION.SDK_INT + " " + security + " firstMs=" + elapsedMs)
    }

    @Test fun restoredOldAuthenticFileCannotClaimAgain() {
        assertTrue(ledger().claim(OWNER, permit(2)))
        val old = requireNotNull(raw.read()).copyOf()
        val oldEpoch = keys.epochIds().single()
        assertTrue(ledger().claim(OWNER, permit(3)))
        assertFalse(keys.epochIds().contains(oldEpoch))
        assertTrue(raw.write(old))
        assertThrows(VoiceSignalReplayException::class.java) {
            ledger().claim(OWNER, permit(3))
        }
    }

    @Test fun extraEpochAliasIsRefused() {
        assertTrue(ledger().claim(OWNER, permit(4)))
        keys.createEpoch()
        assertEquals(2, keys.epochIds().size)
        assertThrows(VoiceSignalReplayException::class.java) {
            ledger().hasClaim(OWNER, permit(4))
        }
    }

    @Test fun keyLossNeverRecreatesAnOldEpoch() {
        assertTrue(ledger().claim(OWNER, permit(5)))
        val old = requireNotNull(raw.read()).copyOf()
        keys.retireEpoch(keys.epochIds().single())
        assertThrows(VoiceSignalReplayException::class.java) {
            ledger().claim(OWNER, permit(6))
        }
        assertTrue(old.contentEquals(raw.read()))
    }

    @Test fun realAtomicWriteWithSyntheticUncertainReturnIsFailClosed() {
        assertTrue(ledger().claim(OWNER, permit(7)))
        val before = requireNotNull(raw.read()).copyOf()
        val uncertain = object : VoiceDispatchLedgerRawStore {
            override fun read(): ByteArray? = raw.read()
            override fun write(bytes: ByteArray): Boolean {
                assertTrue(raw.write(bytes))
                return false
            }
        }
        assertThrows(VoiceSignalReplayException::class.java) {
            VoiceDispatchContinuityLedger(uncertain, keys).claim(OWNER, permit(8))
        }
        assertFalse(before.contentEquals(raw.read()))
        assertEquals(2, keys.epochIds().size)
        assertThrows(VoiceSignalReplayException::class.java) {
            ledger().hasClaim(OWNER, permit(8))
        }
        // This is NOT evidence of real reboot/power-loss/fsync failure.
    }

    private fun ledger() = VoiceDispatchContinuityLedger(
        AndroidAtomicFileVoiceDispatchLedgerRawStore(context, fileName),
        AndroidKeystoreVoiceDispatchLedgerEpochKeys(prefix),
    )

    private fun permit(n: Int) = VoiceSignalReplayDispatchPermit(
        PEER, ByteArray(16).also { it[0] = n.toByte() },
        ByteArray(16).also { it[0] = 77 }, VoiceSignalKind.OFFER, ByteArray(32) { 5 },
    )

    private companion object {
        val OWNER = ByteArray(32) { 1 }
        val PEER = ByteArray(32) { 2 }
    }
}
