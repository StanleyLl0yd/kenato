package com.sl.kenato.contact

import android.content.Context
import com.sl.kenato.identity.LocalIdentityRepository
import java.security.SecureRandom
import java.time.Instant

internal data class ShareableInvite(
    val uri: String,
    val qrPayload: String,
    val expiresAtEpochSeconds: Long,
)

internal class ContactRepository(
    private val identity: ContactIdentityProvider,
    private val localState: ContactLocalState,
    private val transport: ContactTransport,
    private val random: SecureRandom,
    private val clock: ContactClock,
) {
    @Synchronized
    fun publishIdentity(): M2PublicIdentityBundle {
        val bundle = prepareLocalPublication()
        val acceptedRevision = transport.publishIdentity(bundle)
        if (acceptedRevision != bundle.publicationRevision) {
            throw ContactProtocolException("Server accepted an unexpected publication revision")
        }
        return bundle
    }

    @Synchronized
    fun createInvite(): ShareableInvite {
        val creator = publishIdentity()
        val token = ByteArray(INVITE_TOKEN_BYTES).also(random::nextBytes)
        val signature = identity.sign(ContactCanonical.invitePayload(creator.identityId, token))
        val descriptor = M2InviteDescriptor(creator.identityId.copyOf(), token, signature)
        validateInviteShape(descriptor)
        ContactCrypto.verifyInvite(descriptor, creator.identityPublicKey)

        val expiresAt = transport.createInvite(descriptor)
        val now = nowEpochSeconds()
        if (expiresAt <= now) {
            throw ContactProtocolException("Server returned an expired invite")
        }
        localState.addPendingInvite(
            PendingInvite(
                creatorIdentityId = creator.identityId,
                token = token,
                signature = signature,
                expiresAtEpochSeconds = expiresAt,
            ),
            now,
        )
        val uri = InviteUriCodec.encode(descriptor)
        return ShareableInvite(uri = uri, qrPayload = uri, expiresAtEpochSeconds = expiresAt)
    }

    @Synchronized
    fun redeemInvite(uri: String): PinnedContact {
        val invite = InviteUriCodec.decode(uri)
        val localBundle = prepareLocalPublication()
        if (invite.creatorIdentityId.contentEquals(localBundle.identityId)) {
            throw ContactIdentityConflictException("A local identity cannot redeem its own invite")
        }

        val redemptionSignature = identity.sign(
            ContactCanonical.redemptionPayload(
                invite.creatorIdentityId,
                localBundle.identityId,
                invite.token,
            ),
        )
        if (redemptionSignature.isEmpty() || redemptionSignature.size > MAX_CONTACT_SIGNATURE_BYTES) {
            throw ContactProtocolException("Local redemption signature size is invalid")
        }
        val response = transport.redeemInvite(invite, localBundle, redemptionSignature)
        ContactCrypto.verifyPublicIdentityBundle(response.creatorBundle)
        if (!response.creatorBundle.identityId.contentEquals(invite.creatorIdentityId)) {
            throw ContactIdentityConflictException("Invite creator identity was substituted")
        }
        ContactCrypto.verifyInvite(invite, response.creatorBundle.identityPublicKey)

        return localState.pinVerifiedIdentity(
            ownerIdentityId = localBundle.identityId,
            identityId = response.creatorBundle.identityId,
            identityPublicKey = response.creatorBundle.identityPublicKey,
            pinnedAtEpochSeconds = nowEpochSeconds(),
        )
    }

    @Synchronized
    fun claimInvite(uri: String): PinnedContact {
        val invite = InviteUriCodec.decode(uri)
        val localBundle = prepareLocalPublication()
        if (!invite.creatorIdentityId.contentEquals(localBundle.identityId)) {
            throw ContactIdentityConflictException("Invite does not belong to the local identity")
        }
        val now = nowEpochSeconds()
        val pending = localState.pendingInvites(localBundle.identityId, now).firstOrNull {
            it.token.contentEquals(invite.token)
        } ?: throw ContactStateException("Pending invite is unavailable or expired")
        if (!pending.signature.contentEquals(invite.signature)) {
            throw ContactIdentityConflictException("Pending invite signature changed")
        }

        val claimSignature = identity.sign(ContactCanonical.claimPayload(localBundle.identityId, invite.token))
        if (claimSignature.isEmpty() || claimSignature.size > MAX_CONTACT_SIGNATURE_BYTES) {
            throw ContactProtocolException("Local claim signature size is invalid")
        }
        val response = transport.claimInvite(localBundle.identityId, invite.token, claimSignature)
        if (response.redeemerBundle.identityId.contentEquals(localBundle.identityId)) {
            throw ContactIdentityConflictException("Invite redemption resolved to the local identity")
        }
        ContactCrypto.verifyRedemption(
            creatorIdentityId = localBundle.identityId,
            redeemer = response.redeemerBundle,
            token = invite.token,
            signature = response.redemptionSignature,
        )
        return localState.commitClaimedIdentity(
            ownerIdentityId = localBundle.identityId,
            token = invite.token,
            identityId = response.redeemerBundle.identityId,
            identityPublicKey = response.redeemerBundle.identityPublicKey,
            pinnedAtEpochSeconds = nowEpochSeconds(),
        )
    }

    @Synchronized
    fun pendingInvites(): List<ShareableInvite> {
        val owner = identity.currentIdentity().toUnsignedContactBundle(1).identityId
        return localState.pendingInvites(owner, nowEpochSeconds()).map { pending ->
            val descriptor = M2InviteDescriptor(
                pending.creatorIdentityId,
                pending.token,
                pending.signature,
            )
            val uri = InviteUriCodec.encode(descriptor)
            ShareableInvite(uri, uri, pending.expiresAtEpochSeconds)
        }
    }

    @Synchronized
    fun contacts(): List<PinnedContact> {
        val owner = identity.currentIdentity().toUnsignedContactBundle(1).identityId
        return localState.contacts(owner)
    }

    /** Must be invoked only together with an explicit destructive local identity recovery action. */
    @Synchronized
    fun clearContactStateForIdentityRecovery() = localState.clearForIdentityRecovery()

    private fun prepareLocalPublication(): M2PublicIdentityBundle {
        val snapshot = identity.currentIdentity()
        val provisional = snapshot.toUnsignedContactBundle(1)
        val materialHash = ContactCanonical.publicationMaterialHash(provisional)
        val reservation = localState.reservePublication(provisional.identityId, materialHash)
        val unsigned = snapshot.toUnsignedContactBundle(reservation.revision)
        return identity.signPublicBundle(unsigned)
    }

    private fun nowEpochSeconds(): Long = clock.nowEpochSeconds().also {
        if (it < 0) throw ContactStateException("Contact clock returned an invalid timestamp")
    }

    companion object {
        fun create(
            context: Context,
            serviceOrigin: java.net.URI,
        ): ContactRepository = ContactRepository(
            identity = LocalContactIdentityProvider(LocalIdentityRepository.create(context)),
            localState = ContactLocalState(SharedPreferencesContactStateStore(context)),
            transport = HttpContactTransport(serviceOrigin),
            random = SecureRandom(),
            clock = SystemContactClock,
        )
    }
}

internal fun interface ContactClock {
    fun nowEpochSeconds(): Long
}

private object SystemContactClock : ContactClock {
    override fun nowEpochSeconds(): Long = Instant.now().epochSecond
}
