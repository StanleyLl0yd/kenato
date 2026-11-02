package com.sl.kenato.call

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Acceptance-only KCE2 Android Keystore backend. An explicit random 128-bit
 * probe namespace is mandatory: it cannot access or create production aliases.
 * This class is never instantiated by an Android application factory.
 */
internal class AndroidKeystoreVoiceConsentEpochAcceptanceKeys(
    probeId: String,
) : VoiceConsentEpochKeys {
    private val namespace: String

    init {
        require(PROBE_ID.matches(probeId)) { "A random 128-bit acceptance-only probe ID is required" }
        namespace = "com.sl.kenato.m5.consent.epoch-acceptance.v1.$probeId."
    }

    private val random = SecureRandom()

    override fun epochIds(): Set<String> = try {
        val result = HashSet<String>()
        val names = openKeystore().aliases()
        while (names.hasMoreElements()) {
            val name = names.nextElement()
            if (name.startsWith(namespace)) {
                // Malformed extra entries MUST be visible to the continuity gate.
                result.add(name.removePrefix(namespace))
            }
        }
        result
    } catch (error: Exception) {
        throw VoiceCapabilityConsentException("Unable to enumerate probe Keystore epochs", error)
    }

    override fun createEpoch(): String {
        val id = freshEpochId()
        try {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            generator.init(
                KeyGenParameterSpec.Builder(
                    namespace + id, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generator.generateKey()
            if (!openKeystore().containsAlias(namespace + id)) {
                throw VoiceCapabilityConsentException("New probe epoch unavailable")
            }
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Unable to create probe Keystore epoch", error)
        }
        return id
    }

    override fun seal(epoch: String, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        requireAad(epoch, aad)
        if (ciphertext.isEmpty() ||
            ciphertext.size > VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES
        ) {
            throw VoiceCapabilityConsentException("Probe consent payload size invalid")
        }
        return try {
            Cipher.getInstance(AES_GCM).run {
                init(Cipher.ENCRYPT_MODE, existingKey(epoch))
                updateAAD(aad)
                val protected = doFinal(ciphertext)
                val nonce = iv
                if (nonce.size != IV_BYTES) {
                    throw VoiceCapabilityConsentException("Probe Keystore nonce size invalid")
                }
                nonce + protected
            }
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Unable to seal probe consent epoch", error)
        }
    }

    override fun open(epoch: String, envelope: ByteArray, aad: ByteArray): ByteArray {
        requireAad(epoch, aad)
        if (envelope.size !in (IV_BYTES + TAG_BYTES + 1)..MAX_ENVELOPE_BYTES) {
            throw VoiceCapabilityConsentException("Probe epoch envelope size invalid")
        }
        return try {
            Cipher.getInstance(AES_GCM).run {
                init(
                    Cipher.DECRYPT_MODE, existingKey(epoch),
                    GCMParameterSpec(TAG_BYTES * 8, envelope.copyOfRange(0, IV_BYTES)),
                )
                updateAAD(aad)
                doFinal(envelope.copyOfRange(IV_BYTES, envelope.size))
            }.also {
                if (it.isEmpty() || it.size > VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES) {
                    it.fill(0)
                    throw VoiceCapabilityConsentException("Probe epoch plaintext size invalid")
                }
            }
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Unable to authenticate probe epoch", error)
        }
    }

    override fun retire(epoch: String) {
        checkEpoch(epoch)
        try {
            val store = openKeystore()
            val name = namespace + epoch
            if (!store.containsAlias(name)) {
                throw VoiceCapabilityConsentException("Probe epoch already absent")
            }
            store.deleteEntry(name)
            if (openKeystore().containsAlias(name)) {
                throw VoiceCapabilityConsentException("Probe epoch retirement unverified")
            }
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Unable to retire probe epoch", error)
        }
    }

    private fun existingKey(epoch: String): SecretKey {
        checkEpoch(epoch)
        return (openKeystore().getKey(namespace + epoch, null) as? SecretKey)
            ?: throw VoiceCapabilityConsentException("Probe Keystore epoch unavailable")
    }

    private fun freshEpochId(): String {
        repeat(4) {
            val bytes = ByteArray(16).also(random::nextBytes)
            val id = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
            if (!openKeystore().containsAlias(namespace + id)) return id
        }
        throw VoiceCapabilityConsentException("Unable to allocate unique probe epoch")
    }

    private fun requireAad(epoch: String, aad: ByteArray) {
        checkEpoch(epoch)
        if (!aad.contentEquals(AAD_PREFIX + epoch.toByteArray(Charsets.US_ASCII))) {
            throw VoiceCapabilityConsentException("Probe consent epoch AAD invalid")
        }
    }

    private fun checkEpoch(epoch: String) {
        if (!EPOCH_ID.matches(epoch)) {
            throw VoiceCapabilityConsentException("Probe epoch ID invalid")
        }
    }

    private fun openKeystore(): KeyStore =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val AES_GCM = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
        const val MAX_ENVELOPE_BYTES = VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES + IV_BYTES + TAG_BYTES
        val PROBE_ID = Regex("[0-9a-f]{32}")
        val EPOCH_ID = Regex("[0-9a-f]{32}")
        val AAD_PREFIX = "KENATO-M5-VOICE-CONSENT-EPOCH-V1\u0000".toByteArray(Charsets.UTF_8)
    }
}
