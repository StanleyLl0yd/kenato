package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import com.sl.kenato.contact.PinnedContact
import com.sl.kenato.identity.LocalIdentityRepository
import com.sl.kenato.session.SessionStateCodec
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

internal class VoiceCapabilityExchangeException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal interface VoiceCapabilityLocalSigner {
    fun localIdentityId(): ByteArray
    fun signProtocolPayload(payload: ByteArray): ByteArray
}

/** Android Keystore-backed M1 identity signing; no private keys are exported. */
internal class LocalVoiceCapabilitySigner(
    private val identities: LocalIdentityRepository,
) : VoiceCapabilityLocalSigner {
    override fun localIdentityId(): ByteArray {
        val encoded = identities.current()?.identityId
            ?: throw VoiceCapabilityExchangeException("M5 capability local identity is not initialized")
        if (encoded.length != 43 || !encoded.matches(Regex("^[A-Za-z0-9_-]+$"))) {
            throw VoiceCapabilityExchangeException("M5 capability local identity encoding invalid")
        }
        val decoded = try {
            Base64.getUrlDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw VoiceCapabilityExchangeException("M5 capability local identity encoding invalid", error)
        }
        if (decoded.size != 32 ||
            decoded.all { it == 0.toByte() } ||
            Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != encoded
        ) {
            throw VoiceCapabilityExchangeException("M5 capability local identity invalid")
        }
        return decoded
    }

    override fun signProtocolPayload(payload: ByteArray): ByteArray =
        identities.signIdentityProtocolPayload(payload)
}

internal fun interface VoiceCapabilityExchangeClock {
    fun nowEpochSeconds(): Long
}

/**
 * Opt-in two-phone, offline and pinned-contact capability handshake.
 *
 * Callers must present the selected pinned contact to the local user, require
 * explicit approval to sign on the responder, and explicit approval to accept
 * proof on the verifier. Neither QR import nor signature generation starts
 * a voice call, probes M4, mutates the ratchet or sends data to a server.
 */
internal class VoiceCapabilityOutOfBandService(
    private val identity: VoiceCapabilityLocalSigner,
    private val pinned: VoicePinnedContactSource,
    private val consent: DurableVoiceCapabilityConsentRepository,
    private val clock: VoiceCapabilityExchangeClock =
        VoiceCapabilityExchangeClock { Instant.now().epochSecond },
) {
    /** Step 1: verifier prepares a fresh Keystore-authenticated durable challenge. */
    @Synchronized
    fun issueChallengeQr(peerIdentityId: ByteArray): String {
        val owner = requireLocalIdentity()
        val contact = requirePinned(owner, peerIdentityId)
        val challenge = consent.issueChallenge(
            owner.copyOf(), peerIdentityId.copyOf(), contact.identityPublicKey.copyOf(),
        )
        return VoiceCapabilityQrWire.encodeChallenge(challenge)
    }

    /**
     * Step 2: responder signs the selected verifier's fresh QR challenge.
     * A QR challenge is not itself signed: the user must independently verify
     * that the selected verifier is already a pinned M2 contact.
     */
    @Synchronized
    fun approveAndSignChallengeQr(
        verifierIdentityId: ByteArray,
        encodedChallengeQr: String,
        explicitUserApproval: Boolean,
    ): String {
        if (!explicitUserApproval) {
            throw VoiceCapabilityExchangeException("Explicit approval to sign voice-v2 proof required")
        }
        val local = requireLocalIdentity()
        requirePinned(local, verifierIdentityId)
        val now = requireNow()
        val challenge = VoiceCapabilityQrWire.decodeChallenge(
            encodedChallengeQr, verifierIdentityId, local, now,
        )
        if (now > Long.MAX_VALUE - VoiceCapabilityProofWire.MAX_LIFETIME_SECONDS) {
            throw VoiceCapabilityExchangeException("Invalid M5 proof issuance clock")
        }
        val expires = minOf(
            challenge.expiresAtEpochSeconds, now + VoiceCapabilityProofWire.MAX_LIFETIME_SECONDS,
        )
        val proof = VoiceCapabilityProofWire.sign(
            signerIdentityId = local,
            verifierIdentityId = verifierIdentityId,
            verifierChallenge = challenge.challenge,
            issuedAtEpochSeconds = now,
            expiresAtEpochSeconds = expires,
            signPayload = identity::signProtocolPayload,
        )
        return VoiceCapabilityQrWire.encodeProof(proof)
    }

    /** Step 3: verifier authenticates and durably consumes its one-time challenge. */
    @Synchronized
    fun approveAndImportProofQr(
        peerIdentityId: ByteArray,
        encodedProofQr: String,
        explicitUserApproval: Boolean,
    ) {
        if (!explicitUserApproval) {
            throw VoiceCapabilityExchangeException("Explicit approval to accept voice-v2 proof required")
        }
        val owner = requireLocalIdentity()
        val contact = requirePinned(owner, peerIdentityId)
        val proof = VoiceCapabilityQrWire.decodeProof(encodedProofQr)
        consent.confirmSignedProof(
            owner.copyOf(),
            peerIdentityId.copyOf(),
            contact.identityPublicKey.copyOf(),
            proof,
            true,
        )
    }

    private fun requireLocalIdentity(): ByteArray =
        identity.localIdentityId().also { id ->
            if (id.size != 32 || id.all { it == 0.toByte() }) {
                throw VoiceCapabilityExchangeException("Invalid M5 local identity")
            }
        }.copyOf()

    private fun requirePinned(owner: ByteArray, peer: ByteArray): PinnedContact {
        if (peer.size != 32 ||
            peer.all { it == 0.toByte() } ||
            MessageDigest.isEqual(owner, peer)
        ) {
            throw VoiceCapabilityExchangeException("Invalid M5 capability peer")
        }
        val contact = pinned.pinnedContact(owner.copyOf(), peer.copyOf())
            ?: throw VoiceCapabilityExchangeException("M5 capability peer is not a pinned contact")
        val derived = try {
            ContactCrypto.identityId(contact.identityPublicKey)
        } catch (error: Exception) {
            throw VoiceCapabilityExchangeException("M5 pinned peer identity key invalid", error)
        }
        if (!MessageDigest.isEqual(contact.identityId, peer) ||
            !MessageDigest.isEqual(derived, peer) ||
            contact.localId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES ||
            contact.localId.all { it == 0.toByte() }
        ) {
            throw VoiceCapabilityExchangeException("M5 capability peer binding changed")
        }
        return contact
    }

    private fun requireNow(): Long = clock.nowEpochSeconds().also {
        if (it <= 0) throw VoiceCapabilityExchangeException("Invalid M5 capability clock")
    }
}
