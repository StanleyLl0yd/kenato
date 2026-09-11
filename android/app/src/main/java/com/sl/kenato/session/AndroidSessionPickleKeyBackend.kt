package com.sl.kenato.session

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal interface SessionPickleKeyBackend {
    fun hasWrappingKey(): Boolean

    fun ensureWrappingKey()

    fun wrap(pickleKey: ByteArray, aad: ByteArray): ByteArray

    fun unwrap(envelope: ByteArray, aad: ByteArray): ByteArray

    fun deleteWrappingKey()
}

internal class AndroidSessionPickleKeyBackend : SessionPickleKeyBackend {
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun hasWrappingKey(): Boolean = keyStore.containsAlias(WRAPPING_ALIAS)

    override fun ensureWrappingKey() {
        if (hasWrappingKey()) {
            wrappingKey()
            return
        }
        try {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            generator.init(
                KeyGenParameterSpec.Builder(
                    WRAPPING_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setKeySize(AES_KEY_SIZE_BITS)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generator.generateKey()
        } catch (error: Exception) {
            throw SessionStateException("Unable to create Android Keystore session wrapping key", error)
        }
    }

    override fun wrap(pickleKey: ByteArray, aad: ByteArray): ByteArray {
        validatePickleKey(pickleKey)
        validateAad(aad)
        return try {
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(pickleKey)
            val iv = cipher.iv
            if (iv.size !in MIN_IV_BYTES..MAX_IV_BYTES || ciphertext.size != PICKLE_CIPHERTEXT_BYTES) {
                throw SessionStateException("Android Keystore returned an invalid session-key envelope")
            }
            ByteBuffer.allocate(2 + iv.size + ciphertext.size)
                .put(ENVELOPE_VERSION)
                .put(iv.size.toByte())
                .put(iv)
                .put(ciphertext)
                .array()
        } catch (error: SessionStateException) {
            throw error
        } catch (error: Exception) {
            throw SessionStateException("Unable to wrap native session pickle key", error)
        }
    }

    override fun unwrap(envelope: ByteArray, aad: ByteArray): ByteArray {
        validateAad(aad)
        if (envelope.size !in MIN_ENVELOPE_BYTES..MAX_ENVELOPE_BYTES) {
            throw SessionStateException("Wrapped session pickle key size is invalid")
        }
        val input = ByteBuffer.wrap(envelope)
        if (input.get() != ENVELOPE_VERSION) {
            throw SessionStateException("Wrapped session pickle key version is unsupported")
        }
        val ivLength = input.get().toInt() and 0xff
        if (ivLength !in MIN_IV_BYTES..MAX_IV_BYTES || input.remaining() != ivLength + PICKLE_CIPHERTEXT_BYTES) {
            throw SessionStateException("Wrapped session pickle key IV is invalid")
        }
        val iv = ByteArray(ivLength).also(input::get)
        val ciphertext = ByteArray(input.remaining()).also(input::get)
        return try {
            val plaintext = Cipher.getInstance(AES_GCM).run {
                init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
                updateAAD(aad)
                doFinal(ciphertext)
            }
            if (plaintext.size != PICKLE_KEY_BYTES) {
                plaintext.fill(0)
                throw SessionStateException("Unwrapped session pickle key size is invalid")
            }
            plaintext
        } catch (error: SessionStateException) {
            throw error
        } catch (error: Exception) {
            throw SessionStateException("Unable to authenticate native session pickle key", error)
        }
    }

    override fun deleteWrappingKey() {
        try {
            if (keyStore.containsAlias(WRAPPING_ALIAS)) {
                keyStore.deleteEntry(WRAPPING_ALIAS)
            }
        } catch (error: Exception) {
            throw SessionStateException("Unable to delete Android Keystore session wrapping key", error)
        }
    }

    private fun wrappingKey(): SecretKey =
        (keyStore.getKey(WRAPPING_ALIAS, null) as? SecretKey)
            ?: throw SessionStateException("Android Keystore session wrapping key is unavailable")

    private fun validatePickleKey(pickleKey: ByteArray) {
        if (pickleKey.size != PICKLE_KEY_BYTES) {
            throw SessionStateException("Native session pickle key size is invalid")
        }
    }

    private fun validateAad(aad: ByteArray) {
        if (aad.isEmpty() || aad.size > MAX_AAD_BYTES) {
            throw SessionStateException("Session pickle-key AAD size is invalid")
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val WRAPPING_ALIAS = "com.sl.kenato.session.pickle-wrap.v1"
        const val AES_GCM = "AES/GCM/NoPadding"
        const val AES_KEY_SIZE_BITS = 256
        const val GCM_TAG_BITS = 128
        const val PICKLE_KEY_BYTES = 32
        const val GCM_TAG_BYTES = GCM_TAG_BITS / 8
        const val PICKLE_CIPHERTEXT_BYTES = PICKLE_KEY_BYTES + GCM_TAG_BYTES
        const val MIN_IV_BYTES = 12
        const val MAX_IV_BYTES = 32
        const val MIN_ENVELOPE_BYTES = 2 + MIN_IV_BYTES + PICKLE_CIPHERTEXT_BYTES
        const val MAX_ENVELOPE_BYTES = 2 + MAX_IV_BYTES + PICKLE_CIPHERTEXT_BYTES
        const val MAX_AAD_BYTES = 1024
        const val ENVELOPE_VERSION: Byte = 1
    }
}
