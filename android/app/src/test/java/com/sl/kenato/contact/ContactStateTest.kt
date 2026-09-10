package com.sl.kenato.contact

import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ContactStateTest {
    @Test
    fun codecRoundTripPreservesBoundedState() {
        val peer = publicKey()
        val owner = ByteArray(CONTACT_ID_BYTES) { it.toByte() }
        val state = ContactState(
            ownerIdentityId = owner,
            publication = PublicationReservation(3, ByteArray(32) { 7 }),
            pendingInvites = listOf(
                PendingInvite(owner, ByteArray(INVITE_TOKEN_BYTES) { 9 }, byteArrayOf(1, 2, 3), 2_000),
            ),
            contacts = listOf(
                PinnedContact(
                    localId = ByteArray(ContactStateCodec.LOCAL_CONTACT_ID_BYTES) { 4 },
                    identityId = ContactCrypto.identityId(peer),
                    identityPublicKey = peer,
                    pinnedAtEpochSeconds = 1_000,
                ),
            ),
        )

        val decoded = ContactStateCodec.decode(ContactStateCodec.encode(state))

        assertArrayEquals(owner, decoded.ownerIdentityId)
        assertEquals(3L, decoded.publication?.revision)
        assertArrayEquals(state.publication?.materialHash, decoded.publication?.materialHash)
        assertArrayEquals(state.pendingInvites.single().token, decoded.pendingInvites.single().token)
        assertArrayEquals(state.contacts.single().identityId, decoded.contacts.single().identityId)
    }

    @Test
    fun codecRejectsInviteOwnedByAnotherIdentity() {
        val owner = ByteArray(CONTACT_ID_BYTES) { 1 }
        val otherOwner = ByteArray(CONTACT_ID_BYTES) { 2 }
        val state = ContactState(
            ownerIdentityId = owner,
            publication = null,
            pendingInvites = listOf(
                PendingInvite(otherOwner, ByteArray(INVITE_TOKEN_BYTES) { 3 }, byteArrayOf(4), 2_000),
            ),
            contacts = emptyList(),
        )

        assertThrows(ContactStateException::class.java) { ContactStateCodec.encode(state) }
    }

    @Test
    fun codecRejectsPinnedIdentityKeyMismatch() {
        val owner = ByteArray(CONTACT_ID_BYTES) { 1 }
        val peer = publicKey()
        val state = ContactState(
            ownerIdentityId = owner,
            publication = null,
            pendingInvites = emptyList(),
            contacts = listOf(
                PinnedContact(
                    localId = ByteArray(ContactStateCodec.LOCAL_CONTACT_ID_BYTES) { 4 },
                    identityId = ByteArray(CONTACT_ID_BYTES) { 9 },
                    identityPublicKey = peer,
                    pinnedAtEpochSeconds = 1_000,
                ),
            ),
        )

        assertThrows(ContactStateException::class.java) { ContactStateCodec.encode(state) }
    }

    @Test
    fun publicationReservationIsStableAndMonotonic() {
        val owner = ByteArray(CONTACT_ID_BYTES) { 1 }
        val local = ContactLocalState(MemoryContactStateStore(), deterministicRandom())

        val first = local.reservePublication(owner, ByteArray(32) { 2 })
        val retry = local.reservePublication(owner, ByteArray(32) { 2 })
        val changed = local.reservePublication(owner, ByteArray(32) { 3 })

        assertEquals(1L, first.revision)
        assertEquals(1L, retry.revision)
        assertEquals(2L, changed.revision)
    }

    @Test
    fun pendingInvitesAreBoundedAndExpireLocally() {
        val owner = ByteArray(CONTACT_ID_BYTES) { 1 }
        val local = ContactLocalState(MemoryContactStateStore(), deterministicRandom())
        repeat(ContactStateCodec.MAX_PENDING_INVITES) { index ->
            local.addPendingInvite(
                PendingInvite(
                    creatorIdentityId = owner,
                    token = ByteArray(INVITE_TOKEN_BYTES) { byte -> (index + byte).toByte() },
                    signature = byteArrayOf((index + 1).toByte()),
                    expiresAtEpochSeconds = 2_000,
                ),
                nowEpochSeconds = 1_000,
            )
        }
        assertEquals(ContactStateCodec.MAX_PENDING_INVITES, local.pendingInvites(owner, 1_000).size)

        assertThrows(ContactStateException::class.java) {
            local.addPendingInvite(
                PendingInvite(owner, ByteArray(INVITE_TOKEN_BYTES) { 99 }, byteArrayOf(99), 2_000),
                1_000,
            )
        }
        assertTrue(local.pendingInvites(owner, 2_000).isEmpty())
    }

    @Test
    fun pinIsIdempotentAndExistingBindingCannotBeReplaced() {
        val owner = ByteArray(CONTACT_ID_BYTES) { 1 }
        val local = ContactLocalState(MemoryContactStateStore(), deterministicRandom())
        val firstKey = publicKey()
        val firstId = ContactCrypto.identityId(firstKey)
        val first = local.pinVerifiedIdentity(owner, firstId, firstKey, 1_000)
        val replay = local.pinVerifiedIdentity(owner, firstId, firstKey, 2_000)

        assertArrayEquals(first.localId, replay.localId)
        assertEquals(1, local.contacts(owner).size)

        val otherKey = publicKey()
        val otherId = ContactCrypto.identityId(otherKey)
        assertThrows(ContactIdentityConflictException::class.java) {
            local.requireMatchingPin(owner, first.localId, otherId, otherKey)
        }
        assertArrayEquals(firstId, local.contacts(owner).single().identityId)
    }

    @Test
    fun claimedIdentityCommitPinsAndRetiresInviteTogether() {
        val owner = ByteArray(CONTACT_ID_BYTES) { 1 }
        val token = ByteArray(INVITE_TOKEN_BYTES) { 5 }
        val store = MemoryContactStateStore()
        val local = ContactLocalState(store, deterministicRandom())
        local.addPendingInvite(PendingInvite(owner, token, byteArrayOf(7), 2_000), 1_000)
        val peerKey = publicKey()
        val peerId = ContactCrypto.identityId(peerKey)

        val contact = local.commitClaimedIdentity(owner, token, peerId, peerKey, 1_100)

        assertArrayEquals(peerId, contact.identityId)
        assertTrue(local.pendingInvites(owner, 1_100).isEmpty())
        assertEquals(1, local.contacts(owner).size)
    }

    @Test
    fun failedClaimCommitLeavesPendingInviteAndPinsUnchanged() {
        val owner = ByteArray(CONTACT_ID_BYTES) { 1 }
        val token = ByteArray(INVITE_TOKEN_BYTES) { 5 }
        val store = MemoryContactStateStore()
        val local = ContactLocalState(store, deterministicRandom())
        local.addPendingInvite(PendingInvite(owner, token, byteArrayOf(7), 2_000), 1_000)
        val durableBefore = requireNotNull(store.value).copyOf()
        val peerKey = publicKey()
        val peerId = ContactCrypto.identityId(peerKey)
        store.failWrites = true

        assertThrows(ContactStateException::class.java) {
            local.commitClaimedIdentity(owner, token, peerId, peerKey, 1_100)
        }

        assertArrayEquals(durableBefore, requireNotNull(store.value))
        store.failWrites = false
        assertEquals(1, local.pendingInvites(owner, 1_100).size)
        assertTrue(local.contacts(owner).isEmpty())
    }

    @Test
    fun stateForDifferentLocalIdentityFailsClosed() {
        val store = MemoryContactStateStore()
        val firstOwner = ByteArray(CONTACT_ID_BYTES) { 1 }
        val secondOwner = ByteArray(CONTACT_ID_BYTES) { 2 }
        val local = ContactLocalState(store, deterministicRandom())
        local.reservePublication(firstOwner, ByteArray(32) { 3 })

        assertThrows(ContactIdentityConflictException::class.java) {
            local.contacts(secondOwner)
        }
    }

    @Test
    fun corruptStateFailsClosedAndFailedClearPreservesState() {
        val store = MemoryContactStateStore()
        val owner = ByteArray(CONTACT_ID_BYTES) { 1 }
        val local = ContactLocalState(store, deterministicRandom())
        local.reservePublication(owner, ByteArray(32) { 2 })
        store.value = requireNotNull(store.value).copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

        assertThrows(ContactStateException::class.java) { local.contacts(owner) }

        store.value = ContactStateCodec.encode(ContactState(owner, null, emptyList(), emptyList()))
        store.failClear = true
        assertThrows(ContactStateException::class.java) { local.clearForIdentityRecovery() }
        assertFalse(store.value == null)
    }

    private fun publicKey(): ByteArray = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair().public.encoded
    }

    private fun deterministicRandom(): SecureRandom = SecureRandom(byteArrayOf(1, 2, 3, 4))
}

private class MemoryContactStateStore : ContactStateStore {
    var value: ByteArray? = null
    var failClear = false
    var failWrites = false

    override fun read(): ByteArray? = value?.copyOf()

    override fun write(value: ByteArray): Boolean {
        if (failWrites) return false
        this.value = value.copyOf()
        return true
    }

    override fun clear(): Boolean {
        if (failClear) return false
        value = null
        return true
    }
}
