package com.sl.kenato.call

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.SecureRandom
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Synthetic AndroidKeyStore/AtomicFile probe in a separate application ID.
 * CI compiles only. NO physical P23, microphone, network or production state.
 */
@RunWith(AndroidJUnit4::class)
class VoiceConsentEpochKeystoreInstrumentedTest {
    private val id = ByteArray(16).also(SecureRandom()::nextBytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private val keys = AndroidKeystoreVoiceConsentEpochAcceptanceKeys(id)
    private val backing = AndroidVoiceConsentEpochAcceptanceBacking(
        InstrumentationRegistry.getInstrumentation().targetContext, id,
    )

    @After
    fun destroyOnlyThisProbeNamespace() {
        try {
            keys.epochIds().forEach(keys::retire)
            assertTrue(keys.epochIds().isEmpty())
        } finally {
            backing.deleteOnlyProbeFile()
        }
    }

    @Test
    fun genuineOldConsentFileCannotRestoreGrantAfterRetirement() {
        val store = EpochBoundVoiceConsentStore(backing, keys)
        assertTrue(store.write(byteArrayOf(1)))
        val oldFile = backing.read()!!.copyOf()
        val old = keys.epochIds().single()
        assertTrue(store.write(byteArrayOf(2)))
        assertFalse(old in keys.epochIds())
        assertArrayEquals(
            byteArrayOf(2),
            EpochBoundVoiceConsentStore(backing,
                AndroidKeystoreVoiceConsentEpochAcceptanceKeys(id)).read(),
        )
        assertTrue(backing.write(oldFile))
        assertThrows(VoiceCapabilityConsentException::class.java) {
            EpochBoundVoiceConsentStore(backing,
                AndroidKeystoreVoiceConsentEpochAcceptanceKeys(id)).read()
        }
    }

    @Test
    fun orphanKeyAndMissingProbeFileAreNotFreshInstallation() {
        val store = EpochBoundVoiceConsentStore(backing, keys)
        assertTrue(store.write(byteArrayOf(1)))
        backing.deleteOnlyProbeFile()
        assertThrows(VoiceCapabilityConsentException::class.java) {
            EpochBoundVoiceConsentStore(backing, keys).read()
        }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            EpochBoundVoiceConsentStore(backing, keys).write(byteArrayOf(3))
        }
    }

    @Test
    fun extraAliasAndRemovedActiveKeyFailClosed() {
        val store = EpochBoundVoiceConsentStore(backing, keys)
        assertTrue(store.write(byteArrayOf(1)))
        val old = keys.epochIds().single()
        keys.createEpoch()
        assertEquals(2, keys.epochIds().size)
        assertThrows(VoiceCapabilityConsentException::class.java) { store.read() }
        keys.retire(old)
        assertThrows(VoiceCapabilityConsentException::class.java) {
            EpochBoundVoiceConsentStore(backing, keys).read()
        }
    }

    @Test
    fun realFileCommitWithSyntheticUncertainReturnStaysUnusable() {
        assertTrue(EpochBoundVoiceConsentStore(backing, keys).write(byteArrayOf(1)))
        val old = backing.read()!!.copyOf()
        val fault = object : VoiceConsentEpochRawStore {
            override fun read(): ByteArray? = backing.read()
            override fun write(bytes: ByteArray): Boolean {
                assertTrue(backing.write(bytes))
                return false
            }
        }
        assertThrows(VoiceCapabilityConsentException::class.java) {
            EpochBoundVoiceConsentStore(fault, keys).write(byteArrayOf(2))
        }
        assertFalse(old.contentEquals(backing.read()))
        assertEquals(2, keys.epochIds().size)
        assertThrows(VoiceCapabilityConsentException::class.java) {
            EpochBoundVoiceConsentStore(backing, keys).read()
        }
    }

    @Test
    fun probeKeyNonexportabilityAndWrongAadCheck() {
        val epoch = keys.createEpoch()
        val aad = "KENATO-M5-VOICE-CONSENT-EPOCH-V1\u0000".toByteArray(Charsets.UTF_8) +
            epoch.toByteArray(Charsets.US_ASCII)
        val sealed = keys.seal(epoch, byteArrayOf(13), aad)
        assertArrayEquals(
            byteArrayOf(13), AndroidKeystoreVoiceConsentEpochAcceptanceKeys(id).open(
                epoch, sealed, aad,
            ),
        )
        assertThrows(VoiceCapabilityConsentException::class.java) {
            keys.open(epoch, sealed, byteArrayOf(1, 2, 3))
        }
        val keystore = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "com.sl.kenato.m5.consent.epoch-acceptance.v1.$id.$epoch"
        assertEquals(null, keystore.getKey(alias, null)?.encoded)
    }
}
