package com.sl.kenato.session

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal data class WrappedSessionSnapshot(
    val ciphertext: ByteArray,
    val wrappedPickleKey: ByteArray,
)

internal data class TrackedSessionOneTimeKey(
    val id: Long,
    val publicKey: ByteArray,
)

internal data class SessionAccountState(
    val accountGeneration: Long,
    val publicationRevision: Long,
    val nextOneTimeKeyId: Long,
    val olmEd25519IdentityKey: ByteArray,
    val olmCurve25519IdentityKey: ByteArray,
    val oneTimeKeys: List<TrackedSessionOneTimeKey>,
    val snapshot: WrappedSessionSnapshot,
)

internal data class PendingSessionInit(
    val inviteTokenHash: ByteArray,
    val creatorAccountGeneration: Long,
    val creatorOneTimePreKeyId: Long,
    val redeemerAccountGeneration: Long,
    val messageType: Int,
    val olmMessage: ByteArray,
)

internal data class PersistedSession(
    val localContactId: ByteArray,
    val peerIdentityId: ByteArray,
    val peerAccountGeneration: Long,
    val peerOlmEd25519IdentityKey: ByteArray,
    val peerOlmCurve25519IdentityKey: ByteArray,
    val sessionId: String,
    val initiator: Boolean,
    val snapshot: WrappedSessionSnapshot,
    val pendingInit: PendingSessionInit? = null,
)

internal data class SessionState(
    val ownerIdentityId: ByteArray,
    val account: SessionAccountState,
    val sessions: List<PersistedSession>,
)

internal class SessionStateException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

internal object SessionStateCodec {
    const val MAX_STATE_BYTES = 16 * 1024 * 1024
    const val MAX_SESSIONS = 256
    const val MAX_TRACKED_ONE_TIME_KEYS = 100
    const val IDENTITY_ID_BYTES = 32
    const val LOCAL_CONTACT_ID_BYTES = 16
    const val OLM_PUBLIC_KEY_BYTES = 32
    const val INVITE_TOKEN_HASH_BYTES = 32
    const val MAX_ACCOUNT_SNAPSHOT_BYTES = 256 * 1024
    const val MAX_SESSION_SNAPSHOT_BYTES = 256 * 1024
    const val MAX_WRAPPED_PICKLE_KEY_BYTES = 256
    const val MAX_SESSION_ID_BYTES = 128
    const val MAX_OLM_MESSAGE_BYTES = 96 * 1024

    private const val FORMAT_VERSION = 1
    private const val DIGEST_BYTES = 32
    private val magic = byteArrayOf('K'.code.toByte(), 'N'.code.toByte(), 'S'.code.toByte(), '3'.code.toByte())

    fun encode(state: SessionState): ByteArray {
        validate(state)
        val payload = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(magic)
                output.writeInt(FORMAT_VERSION)
                output.write(state.ownerIdentityId)
                output.writeAccount(state.account)
                output.writeInt(state.sessions.size)
                state.sessions.forEach { output.writeSession(it) }
            }
            bytes.toByteArray()
        }
        if (payload.size > MAX_STATE_BYTES - DIGEST_BYTES) {
            throw SessionStateException("Session state exceeds the maximum size")
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(payload)
        return payload + digest
    }

    fun decode(encoded: ByteArray): SessionState {
        if (encoded.size <= DIGEST_BYTES || encoded.size > MAX_STATE_BYTES) {
            throw SessionStateException("Session state size is invalid")
        }
        val payloadSize = encoded.size - DIGEST_BYTES
        val actualDigest = MessageDigest.getInstance("SHA-256").run {
            update(encoded, 0, payloadSize)
            digest()
        }
        val expectedDigest = encoded.copyOfRange(payloadSize, encoded.size)
        if (!MessageDigest.isEqual(actualDigest, expectedDigest)) {
            throw SessionStateException("Session state checksum is invalid")
        }

        try {
            DataInputStream(ByteArrayInputStream(encoded, 0, payloadSize)).use { input ->
                val actualMagic = ByteArray(magic.size).also(input::readFully)
                if (!actualMagic.contentEquals(magic) || input.readInt() != FORMAT_VERSION) {
                    throw SessionStateException("Session state format is unsupported")
                }
                val owner = ByteArray(IDENTITY_ID_BYTES).also(input::readFully)
                val account = input.readAccount()
                val sessionCount = input.readInt()
                if (sessionCount !in 0..MAX_SESSIONS) {
                    throw SessionStateException("Session count is invalid")
                }
                val sessions = List(sessionCount) { input.readSession() }
                if (input.available() != 0) {
                    throw SessionStateException("Session state contains trailing data")
                }
                return SessionState(owner, account, sessions).also(::validate)
            }
        } catch (error: SessionStateException) {
            throw error
        } catch (error: Exception) {
            throw SessionStateException("Session state is corrupt", error)
        }
    }

    private fun validate(state: SessionState) {
        requireSize(state.ownerIdentityId, IDENTITY_ID_BYTES, "owner identity id")
        validateAccount(state.account)
        if (state.sessions.size > MAX_SESSIONS) {
            throw SessionStateException("Too many persisted sessions")
        }
        state.sessions.forEachIndexed { index, session ->
            validateSession(state, session)
            val previous = state.sessions.take(index)
            if (
                previous.any { it.localContactId.contentEquals(session.localContactId) } ||
                previous.any { it.peerIdentityId.contentEquals(session.peerIdentityId) } ||
                previous.any { it.sessionId == session.sessionId }
            ) {
                throw SessionStateException("Session state contains duplicate active sessions")
            }
        }
    }

    private fun validateAccount(account: SessionAccountState) {
        if (account.accountGeneration <= 0) {
            throw SessionStateException("Session account generation is invalid")
        }
        if (account.publicationRevision < 0) {
            throw SessionStateException("Session publication revision is invalid")
        }
        if (account.nextOneTimeKeyId <= 0) {
            throw SessionStateException("Next session one-time-key id is invalid")
        }
        requireSize(account.olmEd25519IdentityKey, OLM_PUBLIC_KEY_BYTES, "Olm Ed25519 identity key")
        requireSize(account.olmCurve25519IdentityKey, OLM_PUBLIC_KEY_BYTES, "Olm Curve25519 identity key")
        if (account.oneTimeKeys.size > MAX_TRACKED_ONE_TIME_KEYS) {
            throw SessionStateException("Too many tracked session one-time keys")
        }
        var previousId = 0L
        account.oneTimeKeys.forEachIndexed { index, key ->
            if (key.id <= previousId || key.id >= account.nextOneTimeKeyId) {
                throw SessionStateException("Tracked session one-time-key ids are invalid")
            }
            requireSize(key.publicKey, OLM_PUBLIC_KEY_BYTES, "Olm one-time key")
            if (
                key.publicKey.contentEquals(account.olmEd25519IdentityKey) ||
                key.publicKey.contentEquals(account.olmCurve25519IdentityKey) ||
                account.oneTimeKeys.take(index).any { it.publicKey.contentEquals(key.publicKey) }
            ) {
                throw SessionStateException("Tracked session one-time-key material is not unique")
            }
            previousId = key.id
        }
        validateSnapshot(account.snapshot, MAX_ACCOUNT_SNAPSHOT_BYTES, "account")
    }

    private fun validateSession(state: SessionState, session: PersistedSession) {
        requireSize(session.localContactId, LOCAL_CONTACT_ID_BYTES, "local contact id")
        requireSize(session.peerIdentityId, IDENTITY_ID_BYTES, "peer identity id")
        if (session.peerIdentityId.contentEquals(state.ownerIdentityId)) {
            throw SessionStateException("Session peer cannot be the local identity")
        }
        if (session.peerAccountGeneration <= 0) {
            throw SessionStateException("Peer session account generation is invalid")
        }
        requireSize(session.peerOlmEd25519IdentityKey, OLM_PUBLIC_KEY_BYTES, "peer Olm Ed25519 identity key")
        requireSize(session.peerOlmCurve25519IdentityKey, OLM_PUBLIC_KEY_BYTES, "peer Olm Curve25519 identity key")
        val sessionIdBytes = session.sessionId.toByteArray(StandardCharsets.UTF_8)
        if (
            sessionIdBytes.isEmpty() ||
            sessionIdBytes.size > MAX_SESSION_ID_BYTES ||
            !String(sessionIdBytes, StandardCharsets.UTF_8).toByteArray(StandardCharsets.UTF_8).contentEquals(sessionIdBytes)
        ) {
            throw SessionStateException("Session id is invalid")
        }
        validateSnapshot(session.snapshot, MAX_SESSION_SNAPSHOT_BYTES, "session")
        session.pendingInit?.let { pending ->
            if (!session.initiator) {
                throw SessionStateException("Only an initiator session may retain a pending M3 init frame")
            }
            requireSize(pending.inviteTokenHash, INVITE_TOKEN_HASH_BYTES, "pending invite token hash")
            if (
                pending.creatorAccountGeneration != session.peerAccountGeneration ||
                pending.creatorOneTimePreKeyId <= 0 ||
                pending.redeemerAccountGeneration != state.account.accountGeneration ||
                pending.messageType != SESSION_OLM_MESSAGE_PRE_KEY ||
                pending.olmMessage.isEmpty() ||
                pending.olmMessage.size > MAX_OLM_MESSAGE_BYTES
            ) {
                throw SessionStateException("Pending M3 session init metadata is invalid")
            }
        }
    }

    private fun validateSnapshot(snapshot: WrappedSessionSnapshot, maximumCiphertextBytes: Int, name: String) {
        if (snapshot.ciphertext.isEmpty() || snapshot.ciphertext.size > maximumCiphertextBytes) {
            throw SessionStateException("Encrypted $name snapshot size is invalid")
        }
        if (
            snapshot.wrappedPickleKey.isEmpty() ||
            snapshot.wrappedPickleKey.size > MAX_WRAPPED_PICKLE_KEY_BYTES
        ) {
            throw SessionStateException("Wrapped $name pickle key size is invalid")
        }
    }

    private fun requireSize(value: ByteArray, expected: Int, name: String) {
        if (value.size != expected) {
            throw SessionStateException("$name size is invalid")
        }
    }

    private fun DataOutputStream.writeAccount(account: SessionAccountState) {
        writeLong(account.accountGeneration)
        writeLong(account.publicationRevision)
        writeLong(account.nextOneTimeKeyId)
        write(account.olmEd25519IdentityKey)
        write(account.olmCurve25519IdentityKey)
        writeInt(account.oneTimeKeys.size)
        account.oneTimeKeys.forEach { key ->
            writeLong(key.id)
            write(key.publicKey)
        }
        writeSized(account.snapshot.ciphertext)
        writeSized(account.snapshot.wrappedPickleKey)
    }

    private fun DataInputStream.readAccount(): SessionAccountState {
        val generation = readLong()
        val revision = readLong()
        val nextOneTimeKeyId = readLong()
        val ed25519 = ByteArray(OLM_PUBLIC_KEY_BYTES).also(::readFully)
        val curve25519 = ByteArray(OLM_PUBLIC_KEY_BYTES).also(::readFully)
        val oneTimeKeyCount = readInt()
        if (oneTimeKeyCount !in 0..MAX_TRACKED_ONE_TIME_KEYS) {
            throw SessionStateException("Tracked session one-time-key count is invalid")
        }
        val oneTimeKeys = List(oneTimeKeyCount) {
            TrackedSessionOneTimeKey(
                id = readLong(),
                publicKey = ByteArray(OLM_PUBLIC_KEY_BYTES).also(::readFully),
            )
        }
        val snapshot = WrappedSessionSnapshot(
            ciphertext = readSized(MAX_ACCOUNT_SNAPSHOT_BYTES),
            wrappedPickleKey = readSized(MAX_WRAPPED_PICKLE_KEY_BYTES),
        )
        return SessionAccountState(
            generation,
            revision,
            nextOneTimeKeyId,
            ed25519,
            curve25519,
            oneTimeKeys,
            snapshot,
        )
    }

    private fun DataOutputStream.writeSession(session: PersistedSession) {
        write(session.localContactId)
        write(session.peerIdentityId)
        writeLong(session.peerAccountGeneration)
        write(session.peerOlmEd25519IdentityKey)
        write(session.peerOlmCurve25519IdentityKey)
        writeString(session.sessionId)
        writeByte(if (session.initiator) 1 else 0)
        writeSized(session.snapshot.ciphertext)
        writeSized(session.snapshot.wrappedPickleKey)
        val pending = session.pendingInit
        writeByte(if (pending != null) 1 else 0)
        if (pending != null) {
            write(pending.inviteTokenHash)
            writeLong(pending.creatorAccountGeneration)
            writeLong(pending.creatorOneTimePreKeyId)
            writeLong(pending.redeemerAccountGeneration)
            writeInt(pending.messageType)
            writeSized(pending.olmMessage)
        }
    }

    private fun DataInputStream.readSession(): PersistedSession {
        val localContactId = ByteArray(LOCAL_CONTACT_ID_BYTES).also(::readFully)
        val peerIdentityId = ByteArray(IDENTITY_ID_BYTES).also(::readFully)
        val peerAccountGeneration = readLong()
        val peerEd25519 = ByteArray(OLM_PUBLIC_KEY_BYTES).also(::readFully)
        val peerCurve25519 = ByteArray(OLM_PUBLIC_KEY_BYTES).also(::readFully)
        val sessionId = readString(MAX_SESSION_ID_BYTES)
        val initiator = readCanonicalBoolean()
        val snapshot = WrappedSessionSnapshot(
            ciphertext = readSized(MAX_SESSION_SNAPSHOT_BYTES),
            wrappedPickleKey = readSized(MAX_WRAPPED_PICKLE_KEY_BYTES),
        )
        val pending = if (readCanonicalBoolean()) {
            PendingSessionInit(
                inviteTokenHash = ByteArray(INVITE_TOKEN_HASH_BYTES).also(::readFully),
                creatorAccountGeneration = readLong(),
                creatorOneTimePreKeyId = readLong(),
                redeemerAccountGeneration = readLong(),
                messageType = readInt(),
                olmMessage = readSized(MAX_OLM_MESSAGE_BYTES),
            )
        } else {
            null
        }
        return PersistedSession(
            localContactId,
            peerIdentityId,
            peerAccountGeneration,
            peerEd25519,
            peerCurve25519,
            sessionId,
            initiator,
            snapshot,
            pending,
        )
    }

    private fun DataOutputStream.writeSized(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }

    private fun DataInputStream.readSized(maximum: Int): ByteArray {
        val size = readInt()
        if (size !in 1..maximum) {
            throw SessionStateException("Session state field size is invalid")
        }
        return ByteArray(size).also(::readFully)
    }

    private fun DataOutputStream.writeString(value: String) {
        val encoded = value.toByteArray(StandardCharsets.UTF_8)
        writeSized(encoded)
    }

    private fun DataInputStream.readString(maximum: Int): String {
        val encoded = readSized(maximum)
        val decoded = String(encoded, StandardCharsets.UTF_8)
        if (!decoded.toByteArray(StandardCharsets.UTF_8).contentEquals(encoded)) {
            throw SessionStateException("Session state string encoding is invalid")
        }
        return decoded
    }

    private fun DataInputStream.readCanonicalBoolean(): Boolean = when (readUnsignedByte()) {
        0 -> false
        1 -> true
        else -> throw SessionStateException("Session state boolean is invalid")
    }
}

internal object SessionKeyAad {
    private val accountDomain = "KENATO-M3-ACCOUNT-PICKLE-V1\u0000".toByteArray(StandardCharsets.UTF_8)
    private val sessionDomain = "KENATO-M3-SESSION-PICKLE-V1\u0000".toByteArray(StandardCharsets.UTF_8)

    fun account(ownerIdentityId: ByteArray, accountGeneration: Long): ByteArray {
        requireIdentity(ownerIdentityId)
        if (accountGeneration <= 0) {
            throw SessionStateException("Session account generation is invalid")
        }
        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(accountDomain)
                output.write(ownerIdentityId)
                output.writeLong(accountGeneration)
            }
            bytes.toByteArray()
        }
    }

    fun session(
        ownerIdentityId: ByteArray,
        localAccountGeneration: Long,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
        peerAccountGeneration: Long,
        sessionId: String,
    ): ByteArray {
        requireIdentity(ownerIdentityId)
        requireIdentity(peerIdentityId)
        if (localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw SessionStateException("Local contact id size is invalid")
        }
        if (localAccountGeneration <= 0 || peerAccountGeneration <= 0) {
            throw SessionStateException("Session account generation is invalid")
        }
        val sessionIdBytes = sessionId.toByteArray(StandardCharsets.UTF_8)
        if (sessionIdBytes.isEmpty() || sessionIdBytes.size > SessionStateCodec.MAX_SESSION_ID_BYTES) {
            throw SessionStateException("Session id is invalid")
        }
        return ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(sessionDomain)
                output.write(ownerIdentityId)
                output.writeLong(localAccountGeneration)
                output.write(localContactId)
                output.write(peerIdentityId)
                output.writeLong(peerAccountGeneration)
                output.writeInt(sessionIdBytes.size)
                output.write(sessionIdBytes)
            }
            bytes.toByteArray()
        }
    }

    private fun requireIdentity(identityId: ByteArray) {
        if (identityId.size != SessionStateCodec.IDENTITY_ID_BYTES) {
            throw SessionStateException("Identity id size is invalid")
        }
    }
}
