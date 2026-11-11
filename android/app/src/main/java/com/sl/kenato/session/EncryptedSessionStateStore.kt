package com.sl.kenato.session

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal interface SessionStateAtRestCipher {
    /** Fresh IV for every write, authenticated using the domain-separated AAD. */
    fun encrypt(plaintext: ByteArray, aad: ByteArray, allowKeyCreation: Boolean): ByteArray
    fun decrypt(envelope: ByteArray, aad: ByteArray): ByteArray
    /** Invalidate the old recovery key before clearing the file; restored ciphertext must stay unreadable. */
    fun deleteKeyForExplicitIdentityRecovery()
}

internal class EncryptedSessionStateStore(
    private val backing: SessionStateStore,
    private val cipher: SessionStateAtRestCipher,
) : SessionStateStore {
    companion object {
        const val MAX_PERSISTED_BYTES = SessionStateCodec.MAX_STATE_BYTES + 64
        private val encryptedMagic = byteArrayOf('K'.code.toByte(), 'S'.code.toByte(), 'A'.code.toByte(), 'E'.code.toByte())
        private val legacyMagic = byteArrayOf('K'.code.toByte(), 'N'.code.toByte(), 'S'.code.toByte(), '3'.code.toByte())
        private val aad = "KENATO-M3-SESSION-STATE-AT-REST-V1\u0000".toByteArray(Charsets.UTF_8)
        private const val FORMAT_VERSION: Byte = 1
        private const val HEADER_BYTES = 5
    }

    /**
     * Migration is deliberate and fail closed. Never return legacy plaintext to a live
     * repository unless the immediate encrypted replacement has committed successfully.
     * This class is NOT yet used by the production LocalSessionRepository factory.
     */
    @Synchronized
    override fun read(): ByteArray? {
        val stored = backing.read() ?: return null
        if (stored.size > MAX_PERSISTED_BYTES || stored.size < HEADER_BYTES) {
            throw SessionStateException("Persisted protected M3 session state length invalid")
        }
        return when {
            stored.take(4).toByteArray().contentEquals(encryptedMagic) -> {
                if (stored[4] != FORMAT_VERSION) {
                    throw SessionStateException("Unsupported encrypted M3 session state format")
                }
                val decoded = try {
                    cipher.decrypt(stored.copyOfRange(HEADER_BYTES, stored.size), aad)
                } catch (error: Exception) {
                    throw SessionStateException("Unable to authenticate protected M3 session state", error)
                }
                try {
                    // The authenticated encrypted blob must also contain canonical M3 state.
                    SessionStateCodec.decode(decoded)
                    decoded
                } catch (error: Exception) {
                    decoded.fill(0)
                    throw SessionStateException("Protected M3 session state is invalid", error)
                }
            }
            stored.take(4).toByteArray().contentEquals(legacyMagic) -> {
                // Legacy M4.5 state must already be canonical before being migrated.
                SessionStateCodec.decode(stored)
                if (!write(stored)) {
                    throw SessionStateException("Unable to commit encrypted M3 session-state migration")
                }
                stored
            }
            else -> throw SessionStateException("Unknown M3 session state storage format")
        }
    }

    @Synchronized
    override fun write(value: ByteArray): Boolean {
        if (value.isEmpty() || value.size > SessionStateCodec.MAX_STATE_BYTES) {
            throw SessionStateException("M3 plaintext state exceeds original codec bound")
        }
        SessionStateCodec.decode(value)
        // An inaccessible existing KSAE must never be replaced by fresh ciphertext
        // under a newly generated alias, even when a caller bypassed read().
        val previous = backing.read()
        if (previous != null) {
            if (previous.size !in HEADER_BYTES..MAX_PERSISTED_BYTES) {
                throw SessionStateException("Existing protected M3 state length invalid")
            }
            when {
                previous.take(4).toByteArray().contentEquals(encryptedMagic) -> {
                    if (previous[4] != FORMAT_VERSION) {
                        throw SessionStateException("Existing M3 state format is unsupported")
                    }
                    val decrypted = try {
                        cipher.decrypt(previous.copyOfRange(HEADER_BYTES, previous.size), aad)
                    } catch (error: Exception) {
                        throw SessionStateException("Cannot replace unauthenticated M3 state", error)
                    }
                    try {
                        SessionStateCodec.decode(decrypted)
                    } finally {
                        decrypted.fill(0)
                    }
                }
                previous.take(4).toByteArray().contentEquals(legacyMagic) -> {
                    // Migration still requires a canonical legacy snapshot.
                    SessionStateCodec.decode(previous)
                }
                else -> throw SessionStateException("Cannot replace unknown M3 state format")
            }
        }
        val mayCreateKey = previous == null ||
            previous.take(4).toByteArray().contentEquals(legacyMagic)
        val encrypted = try {
            cipher.encrypt(value, aad, allowKeyCreation = mayCreateKey)
        } catch (error: Exception) {
            throw SessionStateException("Unable to encrypt M3 session state at rest", error)
        }
        if (encrypted.isEmpty() || encrypted.size + HEADER_BYTES > MAX_PERSISTED_BYTES) {
            throw SessionStateException("M3 authenticated session-state envelope is oversized")
        }
        val content = encryptedMagic + byteArrayOf(FORMAT_VERSION) + encrypted
        return backing.write(content)
    }

    @Synchronized
    override fun clear(): Boolean {
        // Explicit destructive recovery is fail-closed. Invalidate the alias first:
        // if AtomicFile clear subsequently fails, a restored valid KSAE snapshot
        // must not resurrect an old M3 ratchet or pending voice handoff.
        cipher.deleteKeyForExplicitIdentityRecovery()
        return backing.clear()
    }
}

/**
 * Dedicated non-exportable Keystore key for complete M3 state, including temporary
 * v2 SDP/ICE handoffs. Separate from the existing native pickle-key wrapping alias.
 */
internal class AndroidKeystoreSessionStateAtRestCipher : SessionStateAtRestCipher {
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun encrypt(plaintext: ByteArray, aad: ByteArray, allowKeyCreation: Boolean): ByteArray {
        validateAad(aad)
        return try {
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, if (allowKeyCreation) getOrCreateKey() else existingKey())
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv
            if (iv.size != IV_BYTES) {
                throw SessionStateException("Unexpected protected M3 session state IV length")
            }
            byteArrayOf(IV_BYTES.toByte()) + iv + ciphertext
        } catch (error: SessionStateException) {
            throw error
        } catch (error: Exception) {
            throw SessionStateException("Unable to encrypt protected M3 session state", error)
        }
    }

    override fun decrypt(envelope: ByteArray, aad: ByteArray): ByteArray {
        validateAad(aad)
        if (envelope.size !in (1 + IV_BYTES + TAG_BYTES + 1)..(EncryptedSessionStateStore.MAX_PERSISTED_BYTES - 5) ||
            envelope[0].toInt() != IV_BYTES
        ) {
            throw SessionStateException("Protected M3 session state envelope is malformed")
        }
        val iv = envelope.copyOfRange(1, 1 + IV_BYTES)
        return try {
            Cipher.getInstance(AES_GCM).run {
                init(Cipher.DECRYPT_MODE, existingKey(), GCMParameterSpec(128, iv))
                updateAAD(aad)
                doFinal(envelope.copyOfRange(1 + IV_BYTES, envelope.size))
            }
        } catch (error: Exception) {
            throw SessionStateException("Unable to authenticate protected M3 session state", error)
        }
    }

    override fun deleteKeyForExplicitIdentityRecovery() {
        try {
            if (store.containsAlias(KEY_ALIAS)) store.deleteEntry(KEY_ALIAS)
        } catch (error: Exception) {
            throw SessionStateException("Unable to clear protected M3 Keystore key", error)
        }
    }

    private fun existingKey(): SecretKey =
        (store.getKey(KEY_ALIAS, null) as? SecretKey)
            ?: throw SessionStateException("Protected M3 Keystore key missing: never replace a lost key")

    private fun getOrCreateKey(): SecretKey {
        if (store.containsAlias(KEY_ALIAS)) return existingKey()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun validateAad(aad: ByteArray) {
        if (aad.size !in 8..128) {
            throw SessionStateException("Protected M3 session state AAD is invalid")
        }
    }

    private companion object {
        const val AES_GCM = "AES/GCM/NoPadding"
        const val KEY_ALIAS = "com.sl.kenato.session.state-aead.v1"
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
    }
}
