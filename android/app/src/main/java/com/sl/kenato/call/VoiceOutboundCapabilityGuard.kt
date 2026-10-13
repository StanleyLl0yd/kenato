package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import com.sl.kenato.contact.ContactLocalState
import com.sl.kenato.contact.PinnedContact
import com.sl.kenato.session.LocalSessionRepository
import com.sl.kenato.session.SessionStateCodec
import java.security.MessageDigest

internal class VoiceOutboundEligibilityException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal fun interface VoicePinnedContactSource {
    fun pinnedContact(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): PinnedContact?
}

internal class LocalVoicePinnedContactSource(
    private val state: ContactLocalState,
) : VoicePinnedContactSource {
    override fun pinnedContact(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): PinnedContact? =
        state.contacts(ownerIdentityId).singleOrNull {
            it.identityId.contentEquals(peerIdentityId)
        }
}

internal fun interface VoiceSessionContactSource {
    fun establishedLocalContactId(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray?
}

internal class LocalVoiceSessionContactSource(
    private val sessions: LocalSessionRepository,
) : VoiceSessionContactSource {
    override fun establishedLocalContactId(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): ByteArray? =
        sessions.currentState(ownerIdentityId)?.sessions?.singleOrNull {
            it.peerIdentityId.contentEquals(peerIdentityId) && it.pendingInit == null
        }?.localContactId?.copyOf()
}

/** Copied identity and contact binding, NOT a call permission or ratchet/send commitment. */
internal class VerifiedVoiceOutboundPeer(
    val ownerIdentityId: ByteArray,
    val peerIdentityId: ByteArray,
    val localContactId: ByteArray,
)

/**
 * Strict preflight for a FUTURE outbound E2EE voice stage. Never probe older
 * peers over M4 to infer support. Require one authenticated pinned M2 contact,
 * exactly the same M3 established contact binding, and a durably consumed
 * explicit signed v2 capability proof in the independent Keystore-backed store.
 *
 * This is read-only. The real outbound M3 ratchet stage must run under a
 * serialized lifecycle/admission boundary and revalidate the pinned contact,
 * established session, TTL and positive capability at the moment of staging.
 * It does not start calls, produce SDP, send to WSS or own a reducer.
 */
internal class VoiceOutboundCapabilityGuard(
    private val pinned: VoicePinnedContactSource,
    private val sessions: VoiceSessionContactSource,
    private val consent: DurableVoiceCapabilityConsentRepository,
) {
    @Synchronized
    fun requireEligiblePeer(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
    ): VerifiedVoiceOutboundPeer {
        if (ownerIdentityId.size != 32 || peerIdentityId.size != 32 ||
            ownerIdentityId.all { it == 0.toByte() } ||
            peerIdentityId.all { it == 0.toByte() } ||
            MessageDigest.isEqual(ownerIdentityId, peerIdentityId)
        ) {
            throw VoiceOutboundEligibilityException("Invalid outbound voice owner/peer")
        }
        val contact = pinned.pinnedContact(ownerIdentityId.copyOf(), peerIdentityId.copyOf())
            ?: throw VoiceOutboundEligibilityException("Peer has no pinned M2 contact")
        if (!MessageDigest.isEqual(contact.identityId, peerIdentityId) ||
            contact.localId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES ||
            contact.localId.all { it == 0.toByte() }
        ) {
            throw VoiceOutboundEligibilityException("Pinned M2 contact binding invalid")
        }
        val derived = try {
            ContactCrypto.identityId(contact.identityPublicKey)
        } catch (error: Exception) {
            throw VoiceOutboundEligibilityException("Pinned M2 contact key is invalid", error)
        }
        if (!MessageDigest.isEqual(derived, peerIdentityId)) {
            throw VoiceOutboundEligibilityException("Pinned M2 identity/public key mismatch")
        }
        val activeContactId = sessions.establishedLocalContactId(
            ownerIdentityId.copyOf(), peerIdentityId.copyOf(),
        ) ?: throw VoiceOutboundEligibilityException("Peer has no established M3 session")
        if (activeContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES ||
            !MessageDigest.isEqual(activeContactId, contact.localId)
        ) {
            throw VoiceOutboundEligibilityException("M3 session does not belong to the pinned M2 contact")
        }
        if (!consent.isVoiceVersion2Confirmed(
                ownerIdentityId.copyOf(), peerIdentityId.copyOf(), contact.identityPublicKey.copyOf(),
            )
        ) {
            throw VoiceOutboundEligibilityException("Peer has no approved signed voice-v2 capability")
        }
        return VerifiedVoiceOutboundPeer(
            ownerIdentityId.copyOf(), peerIdentityId.copyOf(), contact.localId.copyOf(),
        )
    }
}
