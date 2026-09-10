package com.sl.kenato.identity

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

internal object IdentityPrimitives {
    const val MAX_PUBLIC_KEY_BYTES = 2_048
    const val MAX_SIGNATURE_BYTES = 2_048

    private val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()
    private val signedPreKeyDomain = "KENATO-SIGNED-PREKEY-V1\u0000".toByteArray(StandardCharsets.UTF_8)

    fun base64Url(bytes: ByteArray): String = base64UrlEncoder.encodeToString(bytes)

    fun identityId(identityPublicKey: ByteArray): String {
        require(identityPublicKey.isNotEmpty()) { "Identity public key must not be empty" }
        require(identityPublicKey.size <= MAX_PUBLIC_KEY_BYTES) { "Identity public key is too large" }
        val digest = MessageDigest.getInstance("SHA-256").digest(identityPublicKey)
        return base64Url(digest)
    }

    fun signedPreKeyPayload(id: Int, publicKey: ByteArray): ByteArray {
        require(id > 0) { "Prekey id must be positive" }
        require(publicKey.isNotEmpty()) { "Prekey public key must not be empty" }
        require(publicKey.size <= MAX_PUBLIC_KEY_BYTES) { "Prekey public key is too large" }

        return ByteBuffer.allocate(signedPreKeyDomain.size + Int.SIZE_BYTES + Int.SIZE_BYTES + publicKey.size)
            .put(signedPreKeyDomain)
            .putInt(id)
            .putInt(publicKey.size)
            .put(publicKey)
            .array()
    }

    fun verifyP256Signature(
        publicKey: ByteArray,
        payload: ByteArray,
        signatureBytes: ByteArray,
    ): Boolean {
        if (
            publicKey.isEmpty() ||
            publicKey.size > MAX_PUBLIC_KEY_BYTES ||
            signatureBytes.isEmpty() ||
            signatureBytes.size > MAX_SIGNATURE_BYTES
        ) {
            return false
        }

        return try {
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKey))
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(payload)
                verify(signatureBytes)
            }
        } catch (_: Exception) {
            false
        }
    }
}
