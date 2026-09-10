package com.sl.kenato.contact

import android.content.Context
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

internal interface ContactStateStore {
    fun read(): ByteArray?

    fun write(value: ByteArray): Boolean

    fun clear(): Boolean
}

internal class SharedPreferencesContactStateStore(context: Context) : ContactStateStore {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    override fun read(): ByteArray? {
        val encoded = try {
            preferences.getString(STATE_KEY, null)
        } catch (error: ClassCastException) {
            throw ContactStateException("Persisted contact state has an invalid storage type", error)
        } ?: return null
        if (encoded.isEmpty() || encoded.length > MAX_ENCODED_STATE_CHARS) {
            throw ContactStateException("Persisted contact state size is invalid")
        }
        return try {
            decoder.decode(encoded).also {
                if (it.isEmpty() || it.size > ContactStateCodec.MAX_STATE_BYTES) {
                    throw ContactStateException("Persisted contact state size is invalid")
                }
            }
        } catch (error: ContactStateException) {
            throw error
        } catch (error: IllegalArgumentException) {
            throw ContactStateException("Persisted contact state encoding is invalid", error)
        }
    }

    override fun write(value: ByteArray): Boolean {
        if (value.isEmpty() || value.size > ContactStateCodec.MAX_STATE_BYTES) {
            throw ContactStateException("Contact state size is invalid")
        }
        return preferences.edit().putString(STATE_KEY, encoder.encodeToString(value)).commit()
    }

    override fun clear(): Boolean = preferences.edit().remove(STATE_KEY).commit()

    private companion object {
        const val PREFERENCES_NAME = "kenato_contact_v1"
        const val STATE_KEY = "state"
        const val MAX_ENCODED_STATE_CHARS = (ContactStateCodec.MAX_STATE_BYTES * 4 + 2) / 3
    }
}

internal class ContactLocalState(
    private val store: ContactStateStore,
    private val random: SecureRandom = SecureRandom(),
) {
    @Synchronized
    fun reservePublication(ownerIdentityId: ByteArray, materialHash: ByteArray): PublicationReservation {
        requireOwner(ownerIdentityId)
        if (materialHash.size != 32) {
            throw ContactStateException("Publication material hash is invalid")
        }
        val state = load(ownerIdentityId)
        val current = state.publication
        if (current != null && MessageDigest.isEqual(current.materialHash, materialHash)) {
            return current.copy(materialHash = current.materialHash.copyOf())
        }
        val nextRevision = when {
            current == null -> 1L
            current.revision == Long.MAX_VALUE -> throw ContactStateException("Publication revision space is exhausted")
            else -> current.revision + 1
        }
        val reservation = PublicationReservation(nextRevision, materialHash.copyOf())
        persist(state.copy(publication = reservation))
        return reservation.copy(materialHash = reservation.materialHash.copyOf())
    }

    @Synchronized
    fun addPendingInvite(invite: PendingInvite, nowEpochSeconds: Long) {
        if (nowEpochSeconds < 0 || invite.expiresAtEpochSeconds <= nowEpochSeconds) {
            throw ContactStateException("Pending invite expiry is invalid")
        }
        requireOwner(invite.creatorIdentityId)
        validateInviteShape(M2InviteDescriptor(invite.creatorIdentityId, invite.token, invite.signature))
        val state = pruneExpired(load(invite.creatorIdentityId), nowEpochSeconds)
        val existing = state.pendingInvites.firstOrNull { it.token.contentEquals(invite.token) }
        if (existing != null) {
            if (
                !existing.creatorIdentityId.contentEquals(invite.creatorIdentityId) ||
                !existing.signature.contentEquals(invite.signature) ||
                existing.expiresAtEpochSeconds != invite.expiresAtEpochSeconds
            ) {
                throw ContactStateException("Pending invite token conflicts with existing state")
            }
            if (state !== load(invite.creatorIdentityId)) {
                persist(state)
            }
            return
        }
        if (state.pendingInvites.size >= ContactStateCodec.MAX_PENDING_INVITES) {
            throw ContactStateException("Pending invite capacity reached")
        }
        persist(state.copy(pendingInvites = state.pendingInvites + invite.copyDeep()))
    }

    @Synchronized
    fun pendingInvites(ownerIdentityId: ByteArray, nowEpochSeconds: Long): List<PendingInvite> {
        if (nowEpochSeconds < 0) {
            throw ContactStateException("Contact clock is invalid")
        }
        val loaded = load(ownerIdentityId)
        val pruned = pruneExpired(loaded, nowEpochSeconds)
        if (pruned.pendingInvites.size != loaded.pendingInvites.size) {
            persist(pruned)
        }
        return pruned.pendingInvites.map(PendingInvite::copyDeep)
    }

    @Synchronized
    fun removePendingInvite(ownerIdentityId: ByteArray, token: ByteArray): Boolean {
        requireOwner(ownerIdentityId)
        if (token.size != INVITE_TOKEN_BYTES) {
            throw ContactStateException("Invite token size is invalid")
        }
        val state = load(ownerIdentityId)
        val retained = state.pendingInvites.filterNot { it.token.contentEquals(token) }
        if (retained.size == state.pendingInvites.size) {
            return false
        }
        persist(state.copy(pendingInvites = retained))
        return true
    }

    @Synchronized
    fun pinVerifiedIdentity(
        ownerIdentityId: ByteArray,
        identityId: ByteArray,
        identityPublicKey: ByteArray,
        pinnedAtEpochSeconds: Long,
    ): PinnedContact {
        requireOwner(ownerIdentityId)
        if (pinnedAtEpochSeconds < 0) {
            throw ContactStateException("Contact pin timestamp is invalid")
        }
        val derivedId = ContactCrypto.identityId(identityPublicKey)
        if (!MessageDigest.isEqual(derivedId, identityId)) {
            throw ContactIdentityConflictException("Peer identity id does not match its public key")
        }
        val state = load(ownerIdentityId)
        val existing = state.contacts.firstOrNull { it.identityId.contentEquals(identityId) }
        if (existing != null) {
            if (!existing.identityPublicKey.contentEquals(identityPublicKey)) {
                throw ContactIdentityConflictException("Pinned contact identity key changed")
            }
            return existing.copyDeep()
        }
        if (state.contacts.size >= ContactStateCodec.MAX_CONTACTS) {
            throw ContactStateException("Contact capacity reached")
        }
        val localId = allocateLocalId(state.contacts)
        val contact = PinnedContact(
            localId = localId,
            identityId = identityId.copyOf(),
            identityPublicKey = identityPublicKey.copyOf(),
            pinnedAtEpochSeconds = pinnedAtEpochSeconds,
        )
        persist(state.copy(contacts = state.contacts + contact))
        return contact.copyDeep()
    }

    @Synchronized
    fun requireMatchingPin(
        ownerIdentityId: ByteArray,
        localId: ByteArray,
        identityId: ByteArray,
        identityPublicKey: ByteArray,
    ): PinnedContact {
        requireOwner(ownerIdentityId)
        if (localId.size != ContactStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw ContactIdentityConflictException("Local contact binding is invalid")
        }
        val contact = load(ownerIdentityId).contacts.firstOrNull { it.localId.contentEquals(localId) }
            ?: throw ContactIdentityConflictException("Local contact binding does not exist")
        if (
            !contact.identityId.contentEquals(identityId) ||
            !contact.identityPublicKey.contentEquals(identityPublicKey)
        ) {
            throw ContactIdentityConflictException("Existing contact binding cannot be replaced silently")
        }
        return contact.copyDeep()
    }

    @Synchronized
    fun contacts(ownerIdentityId: ByteArray): List<PinnedContact> =
        load(ownerIdentityId).contacts.map(PinnedContact::copyDeep)

    /** Must be called only as part of an explicit destructive local-identity recovery flow. */
    @Synchronized
    fun clearForIdentityRecovery() {
        if (!store.clear()) {
            throw ContactStateException("Unable to clear persisted contact state")
        }
    }

    private fun load(ownerIdentityId: ByteArray): ContactState {
        requireOwner(ownerIdentityId)
        val encoded = store.read() ?: return ContactState(
            ownerIdentityId = ownerIdentityId.copyOf(),
            publication = null,
            pendingInvites = emptyList(),
            contacts = emptyList(),
        )
        val state = ContactStateCodec.decode(encoded)
        if (!state.ownerIdentityId.contentEquals(ownerIdentityId)) {
            throw ContactIdentityConflictException(
                "Contact state belongs to a different local identity; explicit recovery is required",
            )
        }
        return state
    }

    private fun persist(state: ContactState) {
        if (!store.write(ContactStateCodec.encode(state))) {
            throw ContactStateException("Unable to commit local contact state")
        }
    }

    private fun pruneExpired(state: ContactState, nowEpochSeconds: Long): ContactState = state.copy(
        pendingInvites = state.pendingInvites.filter { it.expiresAtEpochSeconds > nowEpochSeconds },
    )

    private fun allocateLocalId(existing: List<PinnedContact>): ByteArray {
        repeat(8) {
            val candidate = ByteArray(ContactStateCodec.LOCAL_CONTACT_ID_BYTES).also(random::nextBytes)
            if (existing.none { it.localId.contentEquals(candidate) }) {
                return candidate
            }
        }
        throw ContactStateException("Unable to allocate a unique local contact id")
    }

    private fun requireOwner(ownerIdentityId: ByteArray) {
        if (ownerIdentityId.size != CONTACT_ID_BYTES) {
            throw ContactStateException("Local owner identity id is invalid")
        }
    }
}

private fun PendingInvite.copyDeep() = copy(
    creatorIdentityId = creatorIdentityId.copyOf(),
    token = token.copyOf(),
    signature = signature.copyOf(),
)

private fun PinnedContact.copyDeep() = copy(
    localId = localId.copyOf(),
    identityId = identityId.copyOf(),
    identityPublicKey = identityPublicKey.copyOf(),
)
