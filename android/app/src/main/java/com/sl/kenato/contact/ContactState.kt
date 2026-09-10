package com.sl.kenato.contact

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest

internal data class PublicationReservation(
    val revision: Long,
    val materialHash: ByteArray,
)

internal data class PendingInvite(
    val creatorIdentityId: ByteArray,
    val token: ByteArray,
    val signature: ByteArray,
    val expiresAtEpochSeconds: Long,
)

internal data class PinnedContact(
    val localId: ByteArray,
    val identityId: ByteArray,
    val identityPublicKey: ByteArray,
    val pinnedAtEpochSeconds: Long,
)

internal data class ContactState(
    val ownerIdentityId: ByteArray,
    val publication: PublicationReservation?,
    val pendingInvites: List<PendingInvite>,
    val contacts: List<PinnedContact>,
)

internal class ContactStateException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal class ContactIdentityConflictException(message: String) : IllegalStateException(message)

internal object ContactStateCodec {
    const val MAX_STATE_BYTES = 1 shl 20
    const val MAX_PENDING_INVITES = 16
    const val MAX_CONTACTS = 256
    const val LOCAL_CONTACT_ID_BYTES = 16

    private const val FORMAT_VERSION = 1
    private const val DIGEST_BYTES = 32
    private val magic = byteArrayOf('K'.code.toByte(), 'N'.code.toByte(), 'C'.code.toByte(), 'T'.code.toByte())

    fun encode(state: ContactState): ByteArray {
        validate(state)
        val payload = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(magic)
                output.writeInt(FORMAT_VERSION)
                output.write(state.ownerIdentityId)
                output.writeBoolean(state.publication != null)
                state.publication?.let { publication ->
                    output.writeLong(publication.revision)
                    output.write(publication.materialHash)
                }
                output.writeInt(state.pendingInvites.size)
                state.pendingInvites.forEach { invite ->
                    output.write(invite.creatorIdentityId)
                    output.write(invite.token)
                    output.writeSized(invite.signature)
                    output.writeLong(invite.expiresAtEpochSeconds)
                }
                output.writeInt(state.contacts.size)
                state.contacts.forEach { contact ->
                    output.write(contact.localId)
                    output.write(contact.identityId)
                    output.writeSized(contact.identityPublicKey)
                    output.writeLong(contact.pinnedAtEpochSeconds)
                }
            }
            bytes.toByteArray()
        }
        if (payload.size > MAX_STATE_BYTES - DIGEST_BYTES) {
            throw ContactStateException("Contact state exceeds the maximum size")
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(payload)
        return payload + digest
    }

    fun decode(encoded: ByteArray): ContactState {
        if (encoded.size <= DIGEST_BYTES || encoded.size > MAX_STATE_BYTES) {
            throw ContactStateException("Contact state size is invalid")
        }
        val payloadSize = encoded.size - DIGEST_BYTES
        val actualDigest = MessageDigest.getInstance("SHA-256").run {
            update(encoded, 0, payloadSize)
            digest()
        }
        val expectedDigest = encoded.copyOfRange(payloadSize, encoded.size)
        if (!MessageDigest.isEqual(actualDigest, expectedDigest)) {
            throw ContactStateException("Contact state checksum is invalid")
        }

        try {
            DataInputStream(ByteArrayInputStream(encoded, 0, payloadSize)).use { input ->
                val actualMagic = ByteArray(magic.size).also(input::readFully)
                if (!actualMagic.contentEquals(magic) || input.readInt() != FORMAT_VERSION) {
                    throw ContactStateException("Contact state format is unsupported")
                }
                val owner = ByteArray(CONTACT_ID_BYTES).also(input::readFully)
                val publication = if (input.readCanonicalBoolean()) {
                    PublicationReservation(
                        revision = input.readLong(),
                        materialHash = ByteArray(32).also(input::readFully),
                    )
                } else {
                    null
                }
                val pendingCount = input.readInt()
                if (pendingCount !in 0..MAX_PENDING_INVITES) {
                    throw ContactStateException("Pending invite count is invalid")
                }
                val pending = List(pendingCount) {
                    PendingInvite(
                        creatorIdentityId = ByteArray(CONTACT_ID_BYTES).also(input::readFully),
                        token = ByteArray(INVITE_TOKEN_BYTES).also(input::readFully),
                        signature = input.readSized(MAX_CONTACT_SIGNATURE_BYTES),
                        expiresAtEpochSeconds = input.readLong(),
                    )
                }
                val contactCount = input.readInt()
                if (contactCount !in 0..MAX_CONTACTS) {
                    throw ContactStateException("Contact count is invalid")
                }
                val contacts = List(contactCount) {
                    PinnedContact(
                        localId = ByteArray(LOCAL_CONTACT_ID_BYTES).also(input::readFully),
                        identityId = ByteArray(CONTACT_ID_BYTES).also(input::readFully),
                        identityPublicKey = input.readSized(MAX_CONTACT_PUBLIC_KEY_BYTES),
                        pinnedAtEpochSeconds = input.readLong(),
                    )
                }
                if (input.available() != 0) {
                    throw ContactStateException("Contact state contains trailing data")
                }
                return ContactState(owner, publication, pending, contacts).also(::validate)
            }
        } catch (error: ContactStateException) {
            throw error
        } catch (error: Exception) {
            throw ContactStateException("Contact state is corrupt", error)
        }
    }

    private fun validate(state: ContactState) {
        if (state.ownerIdentityId.size != CONTACT_ID_BYTES) {
            throw ContactStateException("Contact state owner identity id is invalid")
        }
        state.publication?.let {
            if (it.revision <= 0 || it.materialHash.size != 32) {
                throw ContactStateException("Publication reservation is invalid")
            }
        }
        if (state.pendingInvites.size > MAX_PENDING_INVITES) {
            throw ContactStateException("Too many pending invites")
        }
        state.pendingInvites.forEachIndexed { index, invite ->
            if (
                !invite.creatorIdentityId.contentEquals(state.ownerIdentityId) ||
                invite.token.size != INVITE_TOKEN_BYTES ||
                invite.signature.isEmpty() ||
                invite.signature.size > MAX_CONTACT_SIGNATURE_BYTES ||
                invite.expiresAtEpochSeconds <= 0
            ) {
                throw ContactStateException("Pending invite is invalid")
            }
            if (state.pendingInvites.take(index).any { it.token.contentEquals(invite.token) }) {
                throw ContactStateException("Duplicate pending invite token")
            }
        }
        if (state.contacts.size > MAX_CONTACTS) {
            throw ContactStateException("Too many contacts")
        }
        state.contacts.forEachIndexed { index, contact ->
            if (
                contact.localId.size != LOCAL_CONTACT_ID_BYTES ||
                contact.identityId.size != CONTACT_ID_BYTES ||
                contact.identityPublicKey.isEmpty() ||
                contact.identityPublicKey.size > MAX_CONTACT_PUBLIC_KEY_BYTES ||
                contact.pinnedAtEpochSeconds < 0 ||
                contact.identityId.contentEquals(state.ownerIdentityId)
            ) {
                throw ContactStateException("Pinned contact is invalid")
            }
            val derivedIdentityId = try {
                ContactCrypto.identityId(contact.identityPublicKey)
            } catch (error: ContactProtocolException) {
                throw ContactStateException("Pinned contact public key is invalid", error)
            }
            if (!MessageDigest.isEqual(derivedIdentityId, contact.identityId)) {
                throw ContactStateException("Pinned contact identity id does not match its public key")
            }
            val previous = state.contacts.take(index)
            if (
                previous.any { it.localId.contentEquals(contact.localId) } ||
                previous.any { it.identityId.contentEquals(contact.identityId) }
            ) {
                throw ContactStateException("Contact state contains duplicate pins")
            }
        }
    }

    private fun DataOutputStream.writeSized(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }

    private fun DataInputStream.readSized(maximum: Int): ByteArray {
        val size = readInt()
        if (size !in 1..maximum) {
            throw ContactStateException("Contact state field size is invalid")
        }
        return ByteArray(size).also(::readFully)
    }

    private fun DataInputStream.readCanonicalBoolean(): Boolean = when (readUnsignedByte()) {
        0 -> false
        1 -> true
        else -> throw ContactStateException("Contact state boolean is invalid")
    }
}
