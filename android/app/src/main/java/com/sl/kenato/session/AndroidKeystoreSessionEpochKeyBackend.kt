package com.sl.kenato.session

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android platform implementation for the *isolated* KAE2 continuity experiment.
 * No production factory constructs this class. Physical Android 10/13/14+ Keystore
 * durability, enumeration and latency acceptance is mandatory before it may be used.
 */
internal class AndroidKeystoreSessionEpochKeyBackend(
    private val aliasPrefix: String = PRODUCTION_PREFIX,
) : SessionEpochKeyBackend {
    init {
        require(
            aliasPrefix == PRODUCTION_PREFIX ||
                ACCEPTANCE_PREFIX.matches(aliasPrefix)
        ) { "An isolated, random 128-bit acceptance namespace is required" }
    }
    private val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val random = SecureRandom()

    override fun epochIds(): Set<String> = try {
        val result = mutableSetOf<String>()
        val aliases = keystore.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            if (alias.startsWith(aliasPrefix)) {
                // Malformed namespace entries are deliberately visible to the caller;
                // they must never be filtered away to manufacture a matching singleton.
                result.add(alias.removePrefix(aliasPrefix))
            }
        }
        result
    } catch (error: Exception) {
        throw SessionStateException("Unable to enumerate protected M3 Keystore epochs", error)
    }

    override fun createEpoch(): String = try {
        // Each committed state MUST use an independent, freshly generated AES key.
        // A collision or stale entry cannot be silently replaced.
        val id = generateUniqueEpochId()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                aliasPrefix + id,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        generator.generateKey()
        id
    } catch (error: Exception) {
        throw SessionStateException("Unable to create protected M3 Keystore epoch", error)
    }

    override fun encrypt(epochId: String, plaintext: ByteArray, aad: ByteArray): ByteArray {
        checkId(epochId)
        return try {
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, existingKey(epochId))
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv
            if (iv.size != IV_BYTES) throw SessionStateException("Unexpected epoch GCM IV")
            iv + ciphertext
        } catch (error: Exception) {
            throw SessionStateException("Unable to encrypt protected M3 Keystore epoch", error)
        }
    }

    override fun decrypt(epochId: String, envelope: ByteArray, aad: ByteArray): ByteArray {
        checkId(epochId)
        if (envelope.size < IV_BYTES + TAG_BYTES + 1) {
            throw SessionStateException("Invalid protected M3 epoch GCM envelope")
        }
        return try {
            Cipher.getInstance(AES_GCM).run {
                init(
                    Cipher.DECRYPT_MODE,
                    existingKey(epochId),
                    GCMParameterSpec(TAG_BYTES * 8, envelope.copyOfRange(0, IV_BYTES)),
                )
                updateAAD(aad)
                doFinal(envelope.copyOfRange(IV_BYTES, envelope.size))
            }
        } catch (error: Exception) {
            throw SessionStateException("Unable to authenticate protected M3 Keystore epoch", error)
        }
    }

    override fun retireEpoch(epochId: String) {
        checkId(epochId)
        try {
            val alias = aliasPrefix + epochId
            if (!keystore.containsAlias(alias)) {
                throw SessionStateException("Protected M3 epoch key already missing")
            }
            keystore.deleteEntry(alias)
            if (keystore.containsAlias(alias)) {
                throw SessionStateException("Protected M3 epoch key deletion was not verified")
            }
        } catch (error: Exception) {
            throw SessionStateException("Unable to retire protected M3 Keystore epoch", error)
        }
    }

    private fun existingKey(epochId: String): SecretKey =
        (keystore.getKey(aliasPrefix + epochId, null) as? SecretKey)
            ?: throw SessionStateException("Protected M3 Keystore epoch key missing")

    private fun generateUniqueEpochId(): String {
        repeat(4) {
            val bytes = ByteArray(16).also(random::nextBytes)
            val hex = CharArray(32)
            for (index in bytes.indices) {
                val unsigned = bytes[index].toInt() and 0xff
                hex[index * 2] = HEX[unsigned ushr 4]
                hex[index * 2 + 1] = HEX[unsigned and 0x0f]
            }
            val id = String(hex)
            if (!keystore.containsAlias(aliasPrefix + id)) return id
        }
        throw SessionStateException("Unable to allocate a unique M3 epoch alias")
    }

    private fun checkId(epochId: String) {
        if (!EPOCH_PATTERN.matches(epochId)) {
            throw SessionStateException("Invalid M3 Keystore epoch alias identifier")
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val AES_GCM = "AES/GCM/NoPadding"
        const val PRODUCTION_PREFIX = "com.sl.kenato.session.epoch-continuity.v1."
        private val ACCEPTANCE_PREFIX =
            Regex("com[.]sl[.]kenato[.]session[.]epoch-acceptance[.]v1[.][0-9a-f]{32}[.]")
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
        const val HEX = "0123456789abcdef"
        val EPOCH_PATTERN = Regex("[0-9a-f]{32}")
    }
}
