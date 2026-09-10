package com.sl.kenato.identity

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest

internal enum class PreKeyKind(val code: Int) {
    SIGNED(1),
    ONE_TIME(2),
}

internal data class GeneratedPreKey(
    val publicKey: ByteArray,
    val encryptedPrivateKey: ByteArray,
)

internal data class StoredPreKey(
    val id: Int,
    val createdAtEpochSeconds: Long,
    val publicKey: ByteArray,
    val encryptedPrivateKey: ByteArray,
    val signature: ByteArray?,
)

internal data class LocalIdentityState(
    val identityPublicKey: ByteArray,
    val signedPreKey: StoredPreKey,
    val previousSignedPreKey: StoredPreKey?,
    val oneTimePreKeys: List<StoredPreKey>,
    val nextPreKeyId: Int,
)

internal object IdentityStateCodec {
    const val MAX_STATE_BYTES = 256 * 1024
    const val MAX_ONE_TIME_PREKEYS = 100
    const val MAX_ENCRYPTED_PRIVATE_KEY_BYTES = 8 * 1024

    private const val FORMAT_VERSION = 1
    private const val STATE_DIGEST = "SHA-256"
    private const val STATE_DIGEST_BYTES = 32
    private val magic = byteArrayOf('K'.code.toByte(), 'N'.code.toByte(), 'I'.code.toByte(), 'D'.code.toByte())

    fun encode(state: LocalIdentityState): ByteArray {
        validate(state)

        val payload = ByteArrayOutputStream()
        DataOutputStream(payload).use { output ->
            output.write(magic)
            output.writeInt(FORMAT_VERSION)
            output.writeBounded(state.identityPublicKey)
            output.writePreKey(state.signedPreKey)
            output.writeBoolean(state.previousSignedPreKey != null)
            state.previousSignedPreKey?.let { output.writePreKey(it) }
            output.writeInt(state.oneTimePreKeys.size)
            state.oneTimePreKeys.forEach { output.writePreKey(it) }
            output.writeInt(state.nextPreKeyId)
        }

        val payloadBytes = payload.toByteArray()
        if (payloadBytes.size > MAX_STATE_BYTES - STATE_DIGEST_BYTES) {
            throw IdentityStateException("Encoded identity state exceeds the maximum size")
        }

        val digest = MessageDigest.getInstance(STATE_DIGEST).digest(payloadBytes)
        return ByteArrayOutputStream(payloadBytes.size + digest.size).apply {
            write(payloadBytes)
            write(digest)
        }.toByteArray()
    }

    fun decode(bytes: ByteArray): LocalIdentityState {
        if (bytes.size <= STATE_DIGEST_BYTES || bytes.size > MAX_STATE_BYTES) {
            throw IdentityStateException("Identity state size is invalid")
        }

        val payloadLength = bytes.size - STATE_DIGEST_BYTES
        val actualDigest = MessageDigest.getInstance(STATE_DIGEST).run {
            update(bytes, 0, payloadLength)
            digest()
        }
        val expectedDigest = bytes.copyOfRange(payloadLength, bytes.size)
        if (!MessageDigest.isEqual(actualDigest, expectedDigest)) {
            throw IdentityStateException("Identity state checksum is invalid")
        }

        try {
            DataInputStream(ByteArrayInputStream(bytes, 0, payloadLength)).use { input ->
                val actualMagic = ByteArray(magic.size)
                input.readFully(actualMagic)
                if (!actualMagic.contentEquals(magic)) {
                    throw IdentityStateException("Identity state magic is invalid")
                }

                if (input.readInt() != FORMAT_VERSION) {
                    throw IdentityStateException("Identity state version is unsupported")
                }

                val identityPublicKey = input.readBounded(IdentityPrimitives.MAX_PUBLIC_KEY_BYTES)
                val signedPreKey = input.readPreKey()
                val previousSignedPreKey = if (input.readCanonicalBoolean()) input.readPreKey() else null

                val oneTimeCount = input.readInt()
                if (oneTimeCount !in 0..MAX_ONE_TIME_PREKEYS) {
                    throw IdentityStateException("One-time prekey count is invalid")
                }
                val oneTimePreKeys = List(oneTimeCount) { input.readPreKey() }
                val nextPreKeyId = input.readInt()

                if (input.available() != 0) {
                    throw IdentityStateException("Identity state contains trailing data")
                }

                return LocalIdentityState(
                    identityPublicKey = identityPublicKey,
                    signedPreKey = signedPreKey,
                    previousSignedPreKey = previousSignedPreKey,
                    oneTimePreKeys = oneTimePreKeys,
                    nextPreKeyId = nextPreKeyId,
                ).also(::validate)
            }
        } catch (error: IdentityStateException) {
            throw error
        } catch (error: Exception) {
            throw IdentityStateException("Identity state is corrupt", error)
        }
    }

    private fun validate(state: LocalIdentityState) {
        validateBytes(
            state.identityPublicKey,
            IdentityPrimitives.MAX_PUBLIC_KEY_BYTES,
            "identity public key",
        )
        if (state.oneTimePreKeys.size > MAX_ONE_TIME_PREKEYS) {
            throw IdentityStateException("Too many one-time prekeys")
        }

        validatePreKey(state.signedPreKey, requiresSignature = true)
        state.previousSignedPreKey?.let { validatePreKey(it, requiresSignature = true) }
        state.oneTimePreKeys.forEach { validatePreKey(it, requiresSignature = false) }

        val ids = buildList {
            add(state.signedPreKey.id)
            state.previousSignedPreKey?.let { add(it.id) }
            state.oneTimePreKeys.forEach { add(it.id) }
        }
        if (ids.size != ids.toSet().size) {
            throw IdentityStateException("Identity state contains duplicate prekey ids")
        }
        val highestId = ids.maxOrNull() ?: 0
        if (state.nextPreKeyId <= highestId || state.nextPreKeyId <= 0) {
            throw IdentityStateException("Next prekey id is invalid")
        }
    }

    private fun validatePreKey(preKey: StoredPreKey, requiresSignature: Boolean) {
        if (preKey.id <= 0) {
            throw IdentityStateException("Prekey id is invalid")
        }
        if (preKey.createdAtEpochSeconds < 0) {
            throw IdentityStateException("Prekey timestamp is invalid")
        }
        validateBytes(preKey.publicKey, IdentityPrimitives.MAX_PUBLIC_KEY_BYTES, "prekey public key")
        validateBytes(
            preKey.encryptedPrivateKey,
            MAX_ENCRYPTED_PRIVATE_KEY_BYTES,
            "encrypted prekey private key",
        )
        if (requiresSignature) {
            val signature = preKey.signature ?: throw IdentityStateException("Signed prekey signature is missing")
            validateBytes(signature, IdentityPrimitives.MAX_SIGNATURE_BYTES, "signed prekey signature")
        } else if (preKey.signature != null) {
            throw IdentityStateException("One-time prekey must not contain a signature")
        }
    }

    private fun validateBytes(value: ByteArray, maximum: Int, name: String) {
        if (value.isEmpty() || value.size > maximum) {
            throw IdentityStateException("$name size is invalid")
        }
    }

    private fun DataOutputStream.writePreKey(preKey: StoredPreKey) {
        writeInt(preKey.id)
        writeLong(preKey.createdAtEpochSeconds)
        writeBounded(preKey.publicKey)
        writeBounded(preKey.encryptedPrivateKey)
        val signature = preKey.signature
        writeBoolean(signature != null)
        signature?.let { writeBounded(it) }
    }

    private fun DataOutputStream.writeBounded(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }

    private fun DataInputStream.readPreKey(): StoredPreKey {
        val id = readInt()
        val createdAtEpochSeconds = readLong()
        val publicKey = readBounded(IdentityPrimitives.MAX_PUBLIC_KEY_BYTES)
        val encryptedPrivateKey = readBounded(MAX_ENCRYPTED_PRIVATE_KEY_BYTES)
        val signature = if (readCanonicalBoolean()) readBounded(IdentityPrimitives.MAX_SIGNATURE_BYTES) else null
        return StoredPreKey(id, createdAtEpochSeconds, publicKey, encryptedPrivateKey, signature)
    }

    private fun DataInputStream.readCanonicalBoolean(): Boolean = when (val value = readUnsignedByte()) {
        0 -> false
        1 -> true
        else -> throw IdentityStateException("Identity state boolean is invalid: $value")
    }

    private fun DataInputStream.readBounded(maximum: Int): ByteArray {
        val length = readInt()
        if (length !in 1..maximum) {
            throw IdentityStateException("Identity state field size is invalid")
        }
        return ByteArray(length).also { readFully(it) }
    }
}
