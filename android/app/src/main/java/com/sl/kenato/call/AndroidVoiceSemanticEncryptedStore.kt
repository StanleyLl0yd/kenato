package com.sl.kenato.call

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** No-backup atomic file storing ONLY AES-GCM-encrypted M5 event state. */
internal class AtomicFileVoiceSemanticEncryptedStore(context: Context) : VoiceSemanticEncryptedStore {
    private val file = AtomicFile(
        File(context.applicationContext.noBackupFilesDir, "kenato_m5_voice_events_v1.enc"),
    )

    override fun read(): ByteArray? {
        val stream = try {
            file.openRead()
        } catch (_: FileNotFoundException) {
            return null
        } catch (error: Exception) {
            throw VoiceSemanticEventException("Cannot open encrypted voice event state", error)
        }
        return try {
            stream.use { input ->
                val length = file.baseFile.length()
                if (length !in 1..VoiceSemanticEventStateCodec.MAX_ENCRYPTED_BYTES.toLong()) {
                    throw VoiceSemanticEventException("Encrypted voice event file length is invalid")
                }
                val output = ByteArrayOutputStream(length.toInt())
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > VoiceSemanticEventStateCodec.MAX_ENCRYPTED_BYTES) {
                        throw VoiceSemanticEventException("Encrypted voice event file exceeds limit")
                    }
                    output.write(buffer, 0, read)
                }
                output.toByteArray()
            }
        } catch (error: VoiceSemanticEventException) {
            throw error
        } catch (error: Exception) {
            throw VoiceSemanticEventException("Unable to read encrypted voice events", error)
        }
    }

    override fun write(value: ByteArray): Boolean {
        if (value.isEmpty() || value.size > VoiceSemanticEventStateCodec.MAX_ENCRYPTED_BYTES) {
            throw VoiceSemanticEventException("Encrypted voice event size is invalid")
        }
        val stream = try {
            file.startWrite()
        } catch (error: Exception) {
            throw VoiceSemanticEventException("Cannot start atomic voice event write", error)
        }
        return try {
            stream.write(value)
            stream.fd.sync()
            file.finishWrite(stream)
            true
        } catch (error: Exception) {
            runCatching { file.failWrite(stream) }
            throw VoiceSemanticEventException("Cannot atomically persist encrypted voice events", error)
        }
    }

    override fun clear(): Boolean = try {
        file.delete()
        !file.baseFile.exists()
    } catch (error: Exception) {
        throw VoiceSemanticEventException("Cannot clear encrypted voice events", error)
    }
}

/**
 * Non-exportable app-specific AES-256-GCM key, never the M3 pickle wrapping key.
 * Missing or invalidated keys fail closed on reads. Every write uses a provider
 * generated, randomized 12-byte nonce; owner identity is authenticated as AAD.
 */
internal class AndroidKeystoreVoiceSemanticPayloadCipher : VoiceSemanticPayloadCipher {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
        requireAad(aad)
        if (plaintext.isEmpty() || plaintext.size > VoiceSemanticEventStateCodec.MAX_STATE_BYTES) {
            throw VoiceSemanticEventException("Voice event plaintext size is invalid")
        }
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, ensureKey())
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv
            if (iv.size != IV_BYTES) {
                throw VoiceSemanticEventException("Android Keystore voice-event IV is invalid")
            }
            ByteBuffer.allocate(2 + IV_BYTES + ciphertext.size)
                .put(1.toByte())
                .put(IV_BYTES.toByte())
                .put(iv)
                .put(ciphertext)
                .array()
        } catch (error: VoiceSemanticEventException) {
            throw error
        } catch (error: Exception) {
            throw VoiceSemanticEventException("Cannot encrypt M5 semantic events", error)
        }
    }

    override fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray {
        requireAad(aad)
        if (encrypted.size !in (2 + IV_BYTES + GCM_TAG_BYTES + 1)..VoiceSemanticEventStateCodec.MAX_ENCRYPTED_BYTES) {
            throw VoiceSemanticEventException("Encrypted voice event envelope size is invalid")
        }
        val reader = ByteBuffer.wrap(encrypted)
        if (reader.get() != 1.toByte() || (reader.get().toInt() and 255) != IV_BYTES) {
            throw VoiceSemanticEventException("Encrypted voice event envelope version/IV is invalid")
        }
        val iv = ByteArray(IV_BYTES).also(reader::get)
        val ciphertext = ByteArray(reader.remaining()).also(reader::get)
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, requireExistingKey(), GCMParameterSpec(128, iv))
                updateAAD(aad)
                doFinal(ciphertext)
            }.also {
                if (it.isEmpty() || it.size > VoiceSemanticEventStateCodec.MAX_STATE_BYTES) {
                    it.fill(0)
                    throw VoiceSemanticEventException("Decrypted voice semantic state exceeds limits")
                }
            }
        } catch (error: VoiceSemanticEventException) {
            throw error
        } catch (error: Exception) {
            throw VoiceSemanticEventException("Cannot authenticate encrypted M5 semantic events", error)
        }
    }

    private fun ensureKey(): SecretKey {
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun requireExistingKey(): SecretKey =
        (keyStore.getKey(ALIAS, null) as? SecretKey)
            ?: throw VoiceSemanticEventException("Voice event encryption key is unavailable")

    private fun requireAad(aad: ByteArray) {
        if (aad.size !in 32..128) {
            throw VoiceSemanticEventException("Voice event AAD is invalid")
        }
    }

    private companion object {
        const val ALIAS = "com.sl.kenato.m5.voice-semantic.v1"
        const val IV_BYTES = 12
        const val GCM_TAG_BYTES = 16
    }
}
