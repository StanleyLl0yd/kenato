package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.Signature

internal class VoiceCapabilityProofException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Only a bound, authenticated, fresh positive attestation may authorize a voice-v2 offer.
 * This proof must be obtained out-of-band (for example by an explicit verified-contact QR
 * challenge/response flow). Never send it as M4 text to discover unknown peer support.
 *
 * The consuming application must own a CSPRNG-generated, never-reused 16-byte challenge
 * and atomically retire that challenge on successful verification before enabling v2.
 * The codec itself has no transport, storage, QR or application call-side effects.
 */
internal class VoiceCapabilityProof(
    val signerIdentityId: ByteArray,
    val verifierIdentityId: ByteArray,
    val verifierChallenge: ByteArray,
    val issuedAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val signature: ByteArray,
    val applicationProtocolVersion: Int = VOICE_CAPABILITY_APPLICATION_VERSION,
)

internal object VoiceCapabilityProofWire {
    const val CHALLENGE_BYTES = 16
    const val MAX_LIFETIME_SECONDS = 5 * 60L
    const val MAX_FUTURE_SKEW_SECONDS = 30L
    private const val ID_BYTES = 32
    private const val MAX_SIGNATURE_BYTES = 144
    private const val MAX_WIRE_BYTES = 4 + 4 + 32 + 32 + 16 + 8 + 8 + 2 + MAX_SIGNATURE_BYTES
    private val magic = byteArrayOf('K'.code.toByte(), 'C'.code.toByte(), 'V'.code.toByte(), '1'.code.toByte())
    private val signingDomain = "KENATO-M5-VOICE-CAPABILITY-PROOF-V1\u0000".toByteArray(Charsets.UTF_8)

    fun sign(
        signerIdentityId: ByteArray,
        verifierIdentityId: ByteArray,
        verifierChallenge: ByteArray,
        issuedAtEpochSeconds: Long,
        expiresAtEpochSeconds: Long,
        signPayload: (ByteArray) -> ByteArray,
    ): VoiceCapabilityProof {
        val provisional = VoiceCapabilityProof(
            signerIdentityId.copyOf(), verifierIdentityId.copyOf(), verifierChallenge.copyOf(),
            issuedAtEpochSeconds, expiresAtEpochSeconds, byteArrayOf(),
        )
        val signed = signedPayload(provisional)
        val signature = try {
            signPayload(signed)
        } catch (error: Exception) {
            throw VoiceCapabilityProofException("Unable to sign M5 capability attestation", error)
        }
        return VoiceCapabilityProof(
            provisional.signerIdentityId, provisional.verifierIdentityId,
            provisional.verifierChallenge, issuedAtEpochSeconds, expiresAtEpochSeconds,
            signature.copyOf(),
        ).also(::requireProofShape)
    }

    fun encode(value: VoiceCapabilityProof): ByteArray {
        requireProofShape(value)
        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.write(magic)
                out.writeInt(value.applicationProtocolVersion)
                out.write(value.signerIdentityId)
                out.write(value.verifierIdentityId)
                out.write(value.verifierChallenge)
                out.writeLong(value.issuedAtEpochSeconds)
                out.writeLong(value.expiresAtEpochSeconds)
                out.writeShort(value.signature.size)
                out.write(value.signature)
            }
            bytes.toByteArray()
        }
    }

    fun decode(encoded: ByteArray): VoiceCapabilityProof {
        if (encoded.size !in (MAX_WIRE_BYTES - MAX_SIGNATURE_BYTES + 1)..MAX_WIRE_BYTES) {
            throw VoiceCapabilityProofException("M5 capability proof size is invalid")
        }
        return try {
            DataInputStream(ByteArrayInputStream(encoded)).use { input ->
                val header = ByteArray(magic.size).also(input::readFully)
                if (!header.contentEquals(magic)) {
                    throw VoiceCapabilityProofException("M5 capability proof magic is invalid")
                }
                val version = input.readInt()
                val signer = ByteArray(ID_BYTES).also(input::readFully)
                val verifier = ByteArray(ID_BYTES).also(input::readFully)
                val challenge = ByteArray(CHALLENGE_BYTES).also(input::readFully)
                val issued = input.readLong()
                val expires = input.readLong()
                val signatureSize = input.readUnsignedShort()
                if (signatureSize !in 1..MAX_SIGNATURE_BYTES ||
                    signatureSize != input.available()
                ) {
                    throw VoiceCapabilityProofException("M5 capability signature size or trailing bytes invalid")
                }
                val signature = ByteArray(signatureSize).also(input::readFully)
                VoiceCapabilityProof(signer, verifier, challenge, issued, expires, signature, version)
                    .also(::requireProofShape)
            }
        } catch (error: VoiceCapabilityProofException) {
            throw error
        } catch (error: Exception) {
            throw VoiceCapabilityProofException("M5 capability proof is malformed", error)
        }
    }

    /**
     * Pinned M2 identity public key, not any key supplied by the attestation, is authoritative.
     * This method is admission proof only; caller must consume its own fresh challenge once.
     */
    fun verifyForPinnedContact(
        encoded: ByteArray,
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        pinnedPeerIdentityPublicKey: ByteArray,
        outstandingChallenge: ByteArray,
        nowEpochSeconds: Long,
    ): VoiceCapabilityProof {
        val value = decode(encoded)
        if (ownerIdentityId.size != ID_BYTES ||
            peerIdentityId.size != ID_BYTES ||
            outstandingChallenge.size != CHALLENGE_BYTES ||
            !MessageDigest.isEqual(value.verifierIdentityId, ownerIdentityId) ||
            !MessageDigest.isEqual(value.signerIdentityId, peerIdentityId) ||
            !MessageDigest.isEqual(value.verifierChallenge, outstandingChallenge)
        ) {
            throw VoiceCapabilityProofException("M5 capability proof does not match pinned owner, peer and challenge")
        }
        if (nowEpochSeconds <= 0L ||
            value.expiresAtEpochSeconds <= nowEpochSeconds ||
            (value.issuedAtEpochSeconds > nowEpochSeconds &&
                value.issuedAtEpochSeconds - nowEpochSeconds > MAX_FUTURE_SKEW_SECONDS)
        ) {
            throw VoiceCapabilityProofException("M5 capability proof is expired or has invalid time")
        }
        val publicKey = try {
            val key = ContactCrypto.canonicalP256PublicKey(pinnedPeerIdentityPublicKey)
            if (!MessageDigest.isEqual(
                    ContactCrypto.identityId(pinnedPeerIdentityPublicKey),
                    peerIdentityId,
                )
            ) {
                throw VoiceCapabilityProofException("Pinned M2 public key identity does not match peer")
            }
            key
        } catch (error: VoiceCapabilityProofException) {
            throw error
        } catch (error: Exception) {
            throw VoiceCapabilityProofException("Pinned M2 identity public key is invalid", error)
        }
        val authenticated = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(signedPayload(value))
                verify(value.signature)
            }
        } catch (_: Exception) {
            false
        }
        if (!authenticated) {
            throw VoiceCapabilityProofException("Peer capability attestation signature is invalid")
        }
        return value
    }

    private fun signedPayload(value: VoiceCapabilityProof): ByteArray {
        requireFields(value)
        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.write(signingDomain)
                out.writeInt(value.applicationProtocolVersion)
                out.write(value.signerIdentityId)
                out.write(value.verifierIdentityId)
                out.write(value.verifierChallenge)
                out.writeLong(value.issuedAtEpochSeconds)
                out.writeLong(value.expiresAtEpochSeconds)
            }
            bytes.toByteArray()
        }
    }

    private fun requireProofShape(value: VoiceCapabilityProof) {
        requireFields(value)
        if (value.signature.size !in 1..MAX_SIGNATURE_BYTES) {
            throw VoiceCapabilityProofException("Voice capability signature size invalid")
        }
    }

    private fun requireFields(value: VoiceCapabilityProof) {
        if (value.applicationProtocolVersion != VOICE_CAPABILITY_APPLICATION_VERSION ||
            value.signerIdentityId.size != ID_BYTES ||
            value.verifierIdentityId.size != ID_BYTES ||
            value.signerIdentityId.all { it == 0.toByte() } ||
            value.verifierIdentityId.all { it == 0.toByte() } ||
            value.signerIdentityId.contentEquals(value.verifierIdentityId) ||
            value.verifierChallenge.size != CHALLENGE_BYTES ||
            value.verifierChallenge.all { it == 0.toByte() }
        ) {
            throw VoiceCapabilityProofException("Voice capability identities, challenge or version invalid")
        }
        if (value.issuedAtEpochSeconds <= 0L ||
            value.expiresAtEpochSeconds <= value.issuedAtEpochSeconds ||
            value.expiresAtEpochSeconds - value.issuedAtEpochSeconds > MAX_LIFETIME_SECONDS
        ) {
            throw VoiceCapabilityProofException("Voice capability signed lifetime invalid")
        }
    }
}

private const val VOICE_CAPABILITY_APPLICATION_VERSION = 2
