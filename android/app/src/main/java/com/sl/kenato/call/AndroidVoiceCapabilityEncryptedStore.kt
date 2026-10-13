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

/**
 * Physically independent no-backup encrypted capability state. Never share
 * the M5 semantic SDP/ICE file or the M3 encrypted pickle file.
 */
internal class AtomicFileVoiceCapabilityEncryptedStore(context: Context) : VoiceCapabilityEncryptedStore {
    private val file = AtomicFile(
        File(context.applicationContext.noBackupFilesDir, "kenato_m5_voice_capabilities_v1.enc"),
    )

    override fun read(): ByteArray? {
        val stream = try {
            file.openRead()
        } catch (_: FileNotFoundException) {
            return null
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Cannot open encrypted voice capability state", error)
        }
        return try {
            stream.use { input ->
                val length = file.baseFile.length()
                if (length !in 1..VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES.toLong()) {
                    throw VoiceCapabilityConsentException("Voice capability file size invalid")
                }
                val out = ByteArrayOutputStream(length.toInt())
                val buffer = ByteArray(4096)
                var total = 0
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES) {
                        throw VoiceCapabilityConsentException("Voice capability file exceeds bound")
                    }
                    out.write(buffer, 0, read)
                }
                out.toByteArray()
            }
        } catch (error: VoiceCapabilityConsentException) {
            throw error
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Cannot read encrypted capability state", error)
        }
    }

    override fun write(bytes: ByteArray): Boolean {
        if (bytes.isEmpty() || bytes.size > VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES) {
            throw VoiceCapabilityConsentException("Encrypted capability write size invalid")
        }
        val stream = try {
            file.startWrite()
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Cannot start atomic capability write", error)
        }
        return try {
            stream.write(bytes)
            stream.fd.sync()
            file.finishWrite(stream)
            true
        } catch (error: Exception) {
            runCatching { file.failWrite(stream) }
            throw VoiceCapabilityConsentException("Cannot commit encrypted capability state", error)
        }
    }

    override fun clear(): Boolean = try {
        file.delete()
        !file.baseFile.exists()
    } catch (error: Exception) {
        throw VoiceCapabilityConsentException("Cannot clear encrypted capability state", error)
    }
}

/**
 * Separate AndroidKeyStore AES-256-GCM alias, independent from the voice
 * semantic-event key and all M3 session/identity keys.
 *
 * Provider-generated fresh IV and exact domain-separated owner AAD are required
 * for every write/read. Key invalidation and corrupt blobs always fail closed.
 */
internal class AndroidKeystoreVoiceCapabilityCipher : VoiceCapabilityPayloadCipher {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
        requireAad(aad)
        if (plaintext.isEmpty() || plaintext.size > VoiceCapabilityConsentStateCodec.MAX_BYTES) {
            throw VoiceCapabilityConsentException("Capability plaintext size invalid")
        }
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, ensureKey())
            cipher.updateAAD(aad)
            val result = cipher.doFinal(plaintext)
            val iv = cipher.iv
            if (iv.size != IV_BYTES) {
                throw VoiceCapabilityConsentException("Capability Keystore nonce size invalid")
            }
            ByteBuffer.allocate(2 + IV_BYTES + result.size)
                .put(1.toByte())
                .put(IV_BYTES.toByte())
                .put(iv)
                .put(result)
                .array()
        } catch (error: VoiceCapabilityConsentException) {
            throw error
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Unable to encrypt capability state", error)
        }
    }

    override fun decrypt(encrypted: ByteArray, aad: ByteArray): ByteArray {
        requireAad(aad)
        if (encrypted.size !in (2 + IV_BYTES + TAG_BYTES + 1)..VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES) {
            throw VoiceCapabilityConsentException("Capability encrypted envelope invalid")
        }
        val reader = ByteBuffer.wrap(encrypted)
        if (reader.get() != 1.toByte() || (reader.get().toInt() and 255) != IV_BYTES) {
            throw VoiceCapabilityConsentException("Unsupported capability envelope format")
        }
        val iv = ByteArray(IV_BYTES).also(reader::get)
        val ciphertext = ByteArray(reader.remaining()).also(reader::get)
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, requireExistingKey(), GCMParameterSpec(128, iv))
                updateAAD(aad)
                doFinal(ciphertext)
            }.also {
                if (it.isEmpty() || it.size > VoiceCapabilityConsentStateCodec.MAX_BYTES) {
                    it.fill(0)
                    throw VoiceCapabilityConsentException("Capability plaintext exceeds bound")
                }
            }
        } catch (error: VoiceCapabilityConsentException) {
            throw error
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Cannot authenticate capability state", error)
        }
    }

    override fun deleteCapabilityKeyForIdentityRecovery() {
        try {
            if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Cannot invalidate capability Keystore key", error)
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
            ?: throw VoiceCapabilityConsentException("Capability Keystore key unavailable")

    private fun requireAad(aad: ByteArray) {
        if (aad.size != AAD_PREFIX.size + 32 ||
            !aad.copyOfRange(0, AAD_PREFIX.size).contentEquals(AAD_PREFIX)
        ) {
            throw VoiceCapabilityConsentException("Capability owner AAD is invalid")
        }
    }

    private companion object {
        const val ALIAS = "com.sl.kenato.m5.voice-capability.v1"
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
        val AAD_PREFIX = "KENATO-M5-VOICE-CAPABILITY-CONSENT-V1\u0000".toByteArray(Charsets.UTF_8)
    }
}
