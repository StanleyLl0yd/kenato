package com.sl.kenato.call

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64
import java.security.MessageDigest

internal class VoiceCapabilityQrException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Bounded, canonical out-of-band QR/text representation for the existing M5
 * one-time capability challenge and P-256 signed proof. This is NOT a trust
 * or approval boundary. The signer must first verify the pinned M2 identity
 * of the requesting contact and explicitly agree to sign. The verifier must
 * pass the returned proof to DurableVoiceCapabilityConsentRepository with
 * fresh stored challenge, pinned key and explicit user approval.
 *
 * No server, URI deep link, contact discovery or v2 network probe is involved.
 */
internal object VoiceCapabilityQrWire {
    private const val CHALLENGE_PREFIX = "kenato-voice-v2:challenge:"
    private const val PROOF_PREFIX = "kenato-voice-v2:proof:"
    private const val MAX_RECORD_CHARS = 512
    private const val ID_BYTES = 32
    private const val NONCE_BYTES = VoiceCapabilityProofWire.CHALLENGE_BYTES
    private const val VERSION = 2
    private const val CHALLENGE_RECORD_BYTES = 4 + 4 + ID_BYTES + ID_BYTES + NONCE_BYTES + 8
    private val challengeMagic = byteArrayOf(0x4b, 0x56, 0x51, 0x32)
    private val canonicalChars = Regex("^[A-Za-z0-9_-]+$")
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encodeChallenge(challenge: VoiceCapabilityChallenge): String {
        validateChallengeShape(challenge)
        val bytes = ByteArrayOutputStream(CHALLENGE_RECORD_BYTES).use { buffer ->
            DataOutputStream(buffer).use { out ->
                out.write(challengeMagic)
                out.writeInt(VERSION)
                out.write(challenge.ownerIdentityId)
                out.write(challenge.peerIdentityId)
                out.write(challenge.challenge)
                out.writeLong(challenge.expiresAtEpochSeconds)
            }
            buffer.toByteArray()
        }
        return CHALLENGE_PREFIX + encoder.encodeToString(bytes)
    }

    /**
     * Parse only for the intended signer and current verifier. The QR contents
     * are unauthenticated: displaying a pinned verifier contact and explicit
     * signer consent remain mandatory before calling VoiceCapabilityProofWire.sign.
     */
    fun decodeChallenge(
        record: String,
        expectedVerifierIdentityId: ByteArray,
        localSignerIdentityId: ByteArray,
        nowEpochSeconds: Long,
    ): VoiceCapabilityChallenge {
        val bytes = decodeRecord(record, CHALLENGE_PREFIX)
        if (bytes.size != CHALLENGE_RECORD_BYTES) {
            throw VoiceCapabilityQrException("Capability challenge QR size is invalid")
        }
        val value = try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val magic = ByteArray(4).also(input::readFully)
                val version = input.readInt()
                if (!magic.contentEquals(challengeMagic) || version != VERSION) {
                    throw VoiceCapabilityQrException("Unsupported capability QR challenge")
                }
                VoiceCapabilityChallenge(
                    ownerIdentityId = ByteArray(ID_BYTES).also(input::readFully),
                    peerIdentityId = ByteArray(ID_BYTES).also(input::readFully),
                    challenge = ByteArray(NONCE_BYTES).also(input::readFully),
                    expiresAtEpochSeconds = input.readLong(),
                )
            }
        } catch (error: VoiceCapabilityQrException) {
            throw error
        } catch (error: Exception) {
            throw VoiceCapabilityQrException("Malformed capability QR challenge", error)
        }
        validateChallengeShape(value)
        if (!MessageDigest.isEqual(value.ownerIdentityId, expectedVerifierIdentityId) ||
            !MessageDigest.isEqual(value.peerIdentityId, localSignerIdentityId) ||
            nowEpochSeconds <= 0 ||
            value.expiresAtEpochSeconds <= nowEpochSeconds ||
            value.expiresAtEpochSeconds - nowEpochSeconds > VoiceCapabilityProofWire.MAX_LIFETIME_SECONDS
        ) {
            throw VoiceCapabilityQrException("Capability QR challenge identity or expiry mismatch")
        }
        return value
    }

    fun encodeProof(proof: VoiceCapabilityProof): String =
        PROOF_PREFIX + encoder.encodeToString(VoiceCapabilityProofWire.encode(proof))

    /**
     * Structural import only. The encoded proof MUST be passed to the persisted
     * one-time challenge repository for pinned P-256 authentication and approval.
     */
    fun decodeProof(record: String): ByteArray {
        val bytes = decodeRecord(record, PROOF_PREFIX)
        val parsed = VoiceCapabilityProofWire.decode(bytes)
        if (!VoiceCapabilityProofWire.encode(parsed).contentEquals(bytes)) {
            throw VoiceCapabilityQrException("Noncanonical capability QR proof")
        }
        return bytes
    }

    private fun decodeRecord(record: String, prefix: String): ByteArray {
        if (record.length !in (prefix.length + 1)..MAX_RECORD_CHARS ||
            !record.startsWith(prefix)
        ) {
            throw VoiceCapabilityQrException("Invalid capability QR record type or length")
        }
        val value = record.substring(prefix.length)
        if (!canonicalChars.matches(value) || value.length > MAX_RECORD_CHARS - prefix.length) {
            throw VoiceCapabilityQrException("Invalid capability QR base64 alphabet")
        }
        val decoded = try {
            decoder.decode(value)
        } catch (error: IllegalArgumentException) {
            throw VoiceCapabilityQrException("Invalid capability QR base64", error)
        }
        if (encoder.encodeToString(decoded) != value) {
            throw VoiceCapabilityQrException("Noncanonical capability QR encoding")
        }
        return decoded
    }

    private fun validateChallengeShape(value: VoiceCapabilityChallenge) {
        if (value.ownerIdentityId.size != ID_BYTES ||
            value.peerIdentityId.size != ID_BYTES ||
            value.ownerIdentityId.all { it == 0.toByte() } ||
            value.peerIdentityId.all { it == 0.toByte() } ||
            MessageDigest.isEqual(value.ownerIdentityId, value.peerIdentityId) ||
            value.challenge.size != NONCE_BYTES ||
            value.challenge.all { it == 0.toByte() } ||
            value.expiresAtEpochSeconds <= 0
        ) {
            throw VoiceCapabilityQrException("Malformed capability QR challenge")
        }
    }
}
