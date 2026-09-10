package com.sl.kenato.identity

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal interface IdentityKeyBackend {
    fun hasAnyManagedKey(): Boolean

    fun hasAllManagedKeys(): Boolean

    fun createManagedKeys(): ByteArray

    fun identityPublicKey(): ByteArray

    fun signIdentity(payload: ByteArray): ByteArray

    fun generatePreKey(id: Int, kind: PreKeyKind): GeneratedPreKey

    fun validateEncryptedPreKey(preKey: StoredPreKey, kind: PreKeyKind): Boolean

    fun deleteManagedKeys()
}

internal class AndroidIdentityKeyBackend : IdentityKeyBackend {
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val secureRandom = SecureRandom()

    override fun hasAnyManagedKey(): Boolean =
        keyStore.containsAlias(IDENTITY_ALIAS) || keyStore.containsAlias(WRAPPING_ALIAS)

    override fun hasAllManagedKeys(): Boolean =
        keyStore.containsAlias(IDENTITY_ALIAS) && keyStore.containsAlias(WRAPPING_ALIAS)

    override fun createManagedKeys(): ByteArray {
        check(!hasAnyManagedKey()) { "Managed identity keys already exist" }

        try {
            val identityGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            identityGenerator.initialize(
                KeyGenParameterSpec.Builder(
                    IDENTITY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build(),
            )
            identityGenerator.generateKeyPair()

            val wrappingGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            wrappingGenerator.init(
                KeyGenParameterSpec.Builder(
                    WRAPPING_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setKeySize(AES_KEY_SIZE_BITS)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build(),
            )
            wrappingGenerator.generateKey()

            return identityPublicKey()
        } catch (error: Exception) {
            runCatching { deleteManagedKeys() }
            throw IdentityStateException("Unable to create Android Keystore identity material", error)
        }
    }

    override fun identityPublicKey(): ByteArray {
        val certificate = keyStore.getCertificate(IDENTITY_ALIAS)
            ?: throw IdentityStateException("Android Keystore identity key is unavailable")
        return certificate.publicKey.encoded
            ?: throw IdentityStateException("Android Keystore identity public key is not exportable")
    }

    override fun signIdentity(payload: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(IDENTITY_ALIAS, null)
            ?: throw IdentityStateException("Android Keystore identity private key is unavailable")
        return try {
            Signature.getInstance(ECDSA_SIGNATURE).run {
                initSign(privateKey)
                update(payload)
                sign()
            }
        } catch (error: Exception) {
            throw IdentityStateException("Unable to sign with the local identity key", error)
        }
    }

    override fun generatePreKey(id: Int, kind: PreKeyKind): GeneratedPreKey {
        require(id > 0) { "Prekey id must be positive" }

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC)
        generator.initialize(ECGenParameterSpec(P256_CURVE), secureRandom)
        val keyPair = generator.generateKeyPair()
        val publicKey = keyPair.public.encoded
            ?: throw IdentityStateException("Generated prekey public key is not exportable")
        val privateKey = keyPair.private.encoded
            ?: throw IdentityStateException("Generated prekey private key is not exportable")

        return try {
            GeneratedPreKey(
                publicKey = publicKey,
                encryptedPrivateKey = encryptPrivateKey(privateKey, id, kind, publicKey),
            )
        } finally {
            privateKey.fill(0)
        }
    }

    override fun validateEncryptedPreKey(preKey: StoredPreKey, kind: PreKeyKind): Boolean {
        if (preKey.id <= 0 || preKey.publicKey.isEmpty()) {
            return false
        }

        return try {
            KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
                .generatePublic(X509EncodedKeySpec(preKey.publicKey))

            val privateBytes = decryptPrivateKey(
                preKey.encryptedPrivateKey,
                preKey.id,
                kind,
                preKey.publicKey,
            )
            try {
                KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
                    .generatePrivate(PKCS8EncodedKeySpec(privateBytes))
                true
            } finally {
                privateBytes.fill(0)
            }
        } catch (_: Exception) {
            false
        }
    }

    override fun deleteManagedKeys() {
        var firstFailure: Exception? = null
        for (alias in listOf(IDENTITY_ALIAS, WRAPPING_ALIAS)) {
            try {
                if (keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
            } catch (error: Exception) {
                if (firstFailure == null) {
                    firstFailure = error
                }
            }
        }
        firstFailure?.let { throw IdentityStateException("Unable to delete Android Keystore identity material", it) }
    }

    private fun encryptPrivateKey(
        privateKey: ByteArray,
        id: Int,
        kind: PreKeyKind,
        publicKey: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        cipher.updateAAD(preKeyAad(id, kind, publicKey))
        val ciphertext = cipher.doFinal(privateKey)
        val iv = cipher.iv

        if (iv.isEmpty() || iv.size > MAX_IV_BYTES) {
            throw IdentityStateException("Android Keystore returned an invalid GCM IV")
        }
        if (ciphertext.isEmpty() || ciphertext.size > MAX_CIPHERTEXT_BYTES) {
            throw IdentityStateException("Encrypted prekey private key size is invalid")
        }

        return ByteBuffer.allocate(2 + iv.size + ciphertext.size)
            .put(ENVELOPE_VERSION)
            .put(iv.size.toByte())
            .put(iv)
            .put(ciphertext)
            .array()
    }

    private fun decryptPrivateKey(
        envelope: ByteArray,
        id: Int,
        kind: PreKeyKind,
        publicKey: ByteArray,
    ): ByteArray {
        if (envelope.size < MIN_ENVELOPE_BYTES || envelope.size > IdentityStateCodec.MAX_ENCRYPTED_PRIVATE_KEY_BYTES) {
            throw IdentityStateException("Encrypted prekey envelope size is invalid")
        }

        val input = ByteBuffer.wrap(envelope)
        if (input.get() != ENVELOPE_VERSION) {
            throw IdentityStateException("Encrypted prekey envelope version is unsupported")
        }
        val ivLength = input.get().toInt() and 0xff
        if (ivLength !in MIN_IV_BYTES..MAX_IV_BYTES || input.remaining() <= ivLength) {
            throw IdentityStateException("Encrypted prekey envelope IV is invalid")
        }

        val iv = ByteArray(ivLength)
        input.get(iv)
        val ciphertext = ByteArray(input.remaining())
        input.get(ciphertext)
        if (ciphertext.size > MAX_CIPHERTEXT_BYTES) {
            throw IdentityStateException("Encrypted prekey ciphertext is too large")
        }

        return Cipher.getInstance(AES_GCM).run {
            init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            updateAAD(preKeyAad(id, kind, publicKey))
            doFinal(ciphertext)
        }
    }

    private fun wrappingKey(): SecretKey =
        (keyStore.getKey(WRAPPING_ALIAS, null) as? SecretKey)
            ?: throw IdentityStateException("Android Keystore wrapping key is unavailable")

    private fun preKeyAad(id: Int, kind: PreKeyKind, publicKey: ByteArray): ByteArray {
        if (publicKey.isEmpty() || publicKey.size > IdentityPrimitives.MAX_PUBLIC_KEY_BYTES) {
            throw IdentityStateException("Prekey public key size is invalid")
        }

        return ByteBuffer.allocate(PREKEY_AAD_DOMAIN.size + 1 + Int.SIZE_BYTES + Int.SIZE_BYTES + publicKey.size)
            .put(PREKEY_AAD_DOMAIN)
            .put(kind.code.toByte())
            .putInt(id)
            .putInt(publicKey.size)
            .put(publicKey)
            .array()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val IDENTITY_ALIAS = "com.sl.kenato.identity.signing.v1"
        const val WRAPPING_ALIAS = "com.sl.kenato.identity.prekey-wrap.v1"
        const val P256_CURVE = "secp256r1"
        const val ECDSA_SIGNATURE = "SHA256withECDSA"
        const val AES_GCM = "AES/GCM/NoPadding"
        const val AES_KEY_SIZE_BITS = 256
        const val GCM_TAG_BITS = 128
        const val MIN_IV_BYTES = 12
        const val MAX_IV_BYTES = 32
        const val MAX_CIPHERTEXT_BYTES = 4 * 1024
        const val MIN_ENVELOPE_BYTES = 2 + MIN_IV_BYTES + 16
        const val ENVELOPE_VERSION: Byte = 1
        val PREKEY_AAD_DOMAIN = "KENATO-PREKEY-PRIVATE-V1\u0000".toByteArray(StandardCharsets.UTF_8)
    }
}
