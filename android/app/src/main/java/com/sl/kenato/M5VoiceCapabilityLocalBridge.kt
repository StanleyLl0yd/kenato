package com.sl.kenato

import android.content.Context
import com.sl.kenato.call.AndroidKeystoreVoiceCapabilityCipher
import com.sl.kenato.call.AtomicFileVoiceCapabilityEncryptedStore
import com.sl.kenato.call.DurableVoiceCapabilityConsentRepository
import com.sl.kenato.call.LocalVoiceCapabilitySigner
import com.sl.kenato.call.LocalVoicePinnedContactSource
import com.sl.kenato.call.VoiceCapabilityOutOfBandService
import com.sl.kenato.contact.ContactLocalState
import com.sl.kenato.identity.LocalIdentityRepository

/**
 * Local-only opt-in test wiring for the manual M5 QR consent exchange.
 * Uses the same persisted M1 identity/M2 pins as M4. Never starts WebRTC,
 * emits a voice message, changes WSS, or sends QR payloads automatically.
 */
internal class M5VoiceCapabilityLocalBridge(
    context: Context,
    identities: LocalIdentityRepository,
    contacts: ContactLocalState,
) {
    private val pinned = LocalVoicePinnedContactSource(contacts)
    private val consent = DurableVoiceCapabilityConsentRepository(
        AtomicFileVoiceCapabilityEncryptedStore(context.applicationContext),
        AndroidKeystoreVoiceCapabilityCipher(),
    )
    private val service = VoiceCapabilityOutOfBandService(
        LocalVoiceCapabilitySigner(identities), pinned, consent,
    )

    fun issueChallengeQr(peerIdentityId: ByteArray): String =
        service.issueChallengeQr(peerIdentityId.copyOf())

    fun approveAndSignChallengeQr(peerIdentityId: ByteArray, challengeQr: String): String =
        service.approveAndSignChallengeQr(
            verifierIdentityId = peerIdentityId.copyOf(),
            encodedChallengeQr = challengeQr,
            explicitUserApproval = true,
        )

    fun approveAndImportProofQr(peerIdentityId: ByteArray, proofQr: String) {
        service.approveAndImportProofQr(
            peerIdentityId = peerIdentityId.copyOf(),
            encodedProofQr = proofQr,
            explicitUserApproval = true,
        )
    }

    fun isConfirmed(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): Boolean {
        val contact = pinned.pinnedContact(ownerIdentityId.copyOf(), peerIdentityId.copyOf())
            ?: return false
        return consent.isVoiceVersion2Confirmed(
            ownerIdentityId.copyOf(), peerIdentityId.copyOf(),
            contact.identityPublicKey.copyOf(),
        )
    }
}
