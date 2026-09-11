package com.sl.kenato.session

import com.sl.kenato.contact.ContactCrypto
import java.security.MessageDigest
import java.security.Signature

internal object SessionCrypto {
    fun verifyBootstrapBundle(
        bundle: SessionBootstrapBundle,
        expectedIdentityId: ByteArray,
        pinnedIdentityPublicKey: ByteArray,
    ) {
        SessionCanonical.validateBootstrap(bundle, requireSignature = true)
        requirePinnedIdentity(expectedIdentityId, pinnedIdentityPublicKey)
        if (!MessageDigest.isEqual(bundle.identityId, expectedIdentityId)) {
            throw SessionStateException("M3 bootstrap identity was substituted")
        }
        if (!verifySignature(
                pinnedIdentityPublicKey,
                SessionCanonical.bootstrapPayload(bundle),
                bundle.bindingSignature,
            )
        ) {
            throw SessionStateException("M3 session-account binding signature is invalid")
        }
    }

    fun verifyReserveProof(
        creatorIdentityId: ByteArray,
        redeemerIdentityId: ByteArray,
        inviteToken: ByteArray,
        signature: ByteArray,
        redeemerPinnedIdentityPublicKey: ByteArray,
    ) {
        requirePinnedIdentity(redeemerIdentityId, redeemerPinnedIdentityPublicKey)
        if (!verifySignature(
                redeemerPinnedIdentityPublicKey,
                SessionCanonical.reservePayload(creatorIdentityId, redeemerIdentityId, inviteToken),
                signature,
            )
        ) {
            throw SessionStateException("M3 session reservation signature is invalid")
        }
    }

    fun verifySubmitProof(
        request: SessionSubmitInit,
        redeemerPinnedIdentityPublicKey: ByteArray,
    ) {
        requirePinnedIdentity(request.redeemerIdentityId, redeemerPinnedIdentityPublicKey)
        SessionCanonical.validateSubmit(request, requireSignature = true)
        if (!verifySignature(
                redeemerPinnedIdentityPublicKey,
                SessionCanonical.submitPayload(request),
                request.submitSignature,
            )
        ) {
            throw SessionStateException("M3 session-init submit signature is invalid")
        }
    }

    fun verifyClaimProof(
        creatorIdentityId: ByteArray,
        inviteToken: ByteArray,
        signature: ByteArray,
        creatorPinnedIdentityPublicKey: ByteArray,
    ) {
        requirePinnedIdentity(creatorIdentityId, creatorPinnedIdentityPublicKey)
        if (!verifySignature(
                creatorPinnedIdentityPublicKey,
                SessionCanonical.claimPayload(creatorIdentityId, inviteToken),
                signature,
            )
        ) {
            throw SessionStateException("M3 session claim signature is invalid")
        }
    }

    private fun requirePinnedIdentity(identityId: ByteArray, publicKey: ByteArray) {
        if (identityId.size != SESSION_IDENTITY_BYTES) {
            throw SessionStateException("Pinned Kenato identity id size is invalid")
        }
        val derived = try {
            ContactCrypto.identityId(publicKey)
        } catch (error: Exception) {
            throw SessionStateException("Pinned Kenato identity public key is invalid", error)
        }
        if (!MessageDigest.isEqual(derived, identityId)) {
            throw SessionStateException("Pinned Kenato identity id does not match its public key")
        }
    }

    private fun verifySignature(publicKey: ByteArray, payload: ByteArray, signature: ByteArray): Boolean {
        if (signature.isEmpty() || signature.size > SESSION_MAX_SIGNATURE_BYTES) return false
        val key = try {
            ContactCrypto.canonicalP256PublicKey(publicKey)
        } catch (_: Exception) {
            return false
        }
        return try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(payload)
                verify(signature)
            }
        } catch (_: Exception) {
            false
        }
    }
}
