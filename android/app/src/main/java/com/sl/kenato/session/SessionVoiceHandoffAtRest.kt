package com.sl.kenato.session

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Seals ONLY M5 voice-v2 M3 handoff plaintext before an atomic state write.
 * The existing Android Keystore-backed pickle master wraps a fresh random
 * 256-bit data key with domain-separated AAD. Each voice payload is AES-256-GCM
 * encrypted under that data key and bound to the exact M3/M4 handoff identity.
 *
 * M4 text handoffs remain byte-for-byte compatible. This is not anti-rollback:
 * authenticated restoration of an older whole M3 state still requires #118.
 */
internal class SessionVoiceHandoffAtRest(
    private val wrapping: SessionPickleKeyBackend,
) {
    private val random = SecureRandom()

    fun protectForDisk(state: SessionState): SessionState = state.copy(
        messageHandoffs = state.messageHandoffs.map { handoff ->
            val bytes = handoff.encodedPlaintext
            if (isSealed(bytes)) {
                throw SessionStateException("Already-sealed voice handoff cannot be persisted again")
            }
            if (isVoice(bytes)) {
                handoff.copy(encodedPlaintext = seal(state.ownerIdentityId, handoff))
            } else handoff
        },
    )

    fun restoreFromDisk(state: SessionState): SessionState = state.copy(
        messageHandoffs = state.messageHandoffs.map { handoff ->
            val bytes = handoff.encodedPlaintext
            when {
                isSealed(bytes) -> handoff.copy(
                    encodedPlaintext = unseal(state.ownerIdentityId, handoff),
                )
                isVoice(bytes) -> throw SessionStateException(
                    "Unprotected M5 voice handoff on disk; explicit recovery is required",
                )
                else -> handoff
            }
        },
    )

    private fun seal(owner: ByteArray, handoff: SessionMessageHandoff): ByteArray {
        val plaintext = handoff.encodedPlaintext
        if (!isVoice(plaintext) || plaintext.size > MAX_VOICE_PLAINTEXT_BYTES) {
            throw SessionStateException("Invalid voice plaintext for encrypted M3 handoff")
        }
        val binding = aad(owner, handoff)
        val key = ByteArray(DATA_KEY_BYTES).also(random::nextBytes)
        return try {
            val wrapped = wrapping.wrap(key, KEY_DOMAIN + binding)
            if (wrapped.isEmpty() || wrapped.size > SessionStateCodec.MAX_WRAPPED_PICKLE_KEY_BYTES) {
                throw SessionStateException("Invalid wrapped voice handoff data key")
            }
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
            cipher.updateAAD(DATA_DOMAIN + binding)
            val encrypted = cipher.doFinal(plaintext)
            val iv = cipher.iv
            if (iv.size != IV_BYTES || encrypted.size > MAX_ENCRYPTED_BYTES) {
                throw SessionStateException("Invalid encrypted voice handoff size")
            }
            ByteArrayOutputStream().use { buffer ->
                DataOutputStream(buffer).use { out ->
                    out.write(MAGIC)
                    out.writeByte(VERSION)
                    out.writeShort(wrapped.size)
                    out.write(wrapped)
                    out.writeByte(iv.size)
                    out.write(iv)
                    out.writeInt(encrypted.size)
                    out.write(encrypted)
                }
                buffer.toByteArray().also {
                    if (it.size > SessionStateCodec.MAX_HANDOFF_PLAINTEXT_BYTES) {
                        throw SessionStateException("Sealed voice handoff exceeds M3 storage limit")
                    }
                }
            }
        } catch (e: SessionStateException) {
            throw e
        } catch (e: Exception) {
            throw SessionStateException("Unable to seal M5 handoff plaintext", e)
        } finally {
            key.fill(0)
        }
    }

    private fun unseal(owner: ByteArray, handoff: SessionMessageHandoff): ByteArray {
        val bytes = handoff.encodedPlaintext
        val binding = aad(owner, handoff)
        try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val magic = ByteArray(MAGIC.size).also(input::readFully)
                if (!magic.contentEquals(MAGIC) || input.readUnsignedByte() != VERSION) {
                    throw SessionStateException("Unknown sealed M5 handoff format")
                }
                val wrappedSize = input.readUnsignedShort()
                if (wrappedSize !in 1..SessionStateCodec.MAX_WRAPPED_PICKLE_KEY_BYTES) {
                    throw SessionStateException("Invalid sealed voice key length")
                }
                val wrapped = ByteArray(wrappedSize).also(input::readFully)
                val ivSize = input.readUnsignedByte()
                if (ivSize != IV_BYTES) {
                    throw SessionStateException("Invalid sealed voice IV size")
                }
                val iv = ByteArray(ivSize).also(input::readFully)
                val cipherLength = input.readInt()
                if (cipherLength !in GCM_TAG_BYTES + 1..MAX_ENCRYPTED_BYTES ||
                    input.available() != cipherLength
                ) {
                    throw SessionStateException("Invalid sealed voice ciphertext size")
                }
                val ciphertext = ByteArray(cipherLength).also(input::readFully)
                val key = wrapping.unwrap(wrapped, KEY_DOMAIN + binding)
                try {
                    if (key.size != DATA_KEY_BYTES) {
                        throw SessionStateException("Invalid unwrapped voice data key")
                    }
                    val plain = Cipher.getInstance(AES_GCM).run {
                        init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
                        updateAAD(DATA_DOMAIN + binding)
                        doFinal(ciphertext)
                    }
                    if (!isVoice(plain) || plain.size > MAX_VOICE_PLAINTEXT_BYTES) {
                        plain.fill(0)
                        throw SessionStateException("Authenticated voice handoff is not v2")
                    }
                    return plain
                } finally {
                    key.fill(0)
                }
            }
        } catch (e: SessionStateException) {
            throw e
        } catch (e: Exception) {
            throw SessionStateException("Unable to authenticate sealed M5 handoff", e)
        }
    }

    private fun aad(owner: ByteArray, h: SessionMessageHandoff): ByteArray {
        if (owner.size != 32 || h.localContactId.size != 16 ||
            h.peerIdentityId.size != 32 || h.messageId.size != 16 ||
            h.direction !in SessionStateCodec.HANDOFF_DIRECTION_OUTBOUND..SessionStateCodec.HANDOFF_DIRECTION_INBOUND ||
            h.encodedEnvelope.isEmpty() ||
            h.encodedEnvelope.size > SessionStateCodec.MAX_HANDOFF_ENVELOPE_BYTES
        ) {
            throw SessionStateException("Sealed M3 voice handoff binding is invalid")
        }
        return ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { out ->
                out.write(BINDING_DOMAIN)
                out.write(owner)
                out.write(h.localContactId)
                out.write(h.peerIdentityId)
                out.write(h.messageId)
                out.writeByte(h.direction)
                out.write(MessageDigest.getInstance("SHA-256").digest(h.encodedEnvelope))
            }
            buffer.toByteArray()
        }
    }

    private fun isVoice(data: ByteArray): Boolean =
        data.size >= 2 && data[0] == 0x08.toByte() && data[1] == 0x02.toByte()

    private fun isSealed(data: ByteArray): Boolean =
        data.size >= MAGIC.size && data.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)

    private companion object {
        val MAGIC = byteArrayOf('K'.code.toByte(), 'H'.code.toByte(), 'V'.code.toByte(), '2'.code.toByte())
        val BINDING_DOMAIN = "KENATO-M3-VOICE-HANDOFF-BINDING-V1\u0000".toByteArray(Charsets.UTF_8)
        val KEY_DOMAIN = "KENATO-M3-VOICE-HANDOFF-WRAPPED-KEY-V1\u0000".toByteArray(Charsets.UTF_8)
        val DATA_DOMAIN = "KENATO-M3-VOICE-HANDOFF-PLAINTEXT-V1\u0000".toByteArray(Charsets.UTF_8)
        const val VERSION = 1
        const val AES_GCM = "AES/GCM/NoPadding"
        const val DATA_KEY_BYTES = 32
        const val IV_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val GCM_TAG_BYTES = GCM_TAG_BITS / 8
        // The canonical voice record is at most 24 KiB, including SDP and wire fields.
        // Its sealed envelope fits inside M3's existing 32-KiB handoff field.
        const val MAX_VOICE_PLAINTEXT_BYTES = 24 * 1024
        const val MAX_ENCRYPTED_BYTES = MAX_VOICE_PLAINTEXT_BYTES + GCM_TAG_BYTES
    }
}
