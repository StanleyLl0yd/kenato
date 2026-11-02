package com.sl.kenato.call

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest

/** Raw AtomicFile-like boundary for an isolated KDL1 research ledger, not the v1 replay file. */
internal interface VoiceDispatchLedgerRawStore {
    fun read(): ByteArray?
    fun write(bytes: ByteArray): Boolean
}

/** A dedicated *independent* Keystore namespace; decrypt MUST NOT create keys. */
internal interface VoiceDispatchLedgerEpochKeys {
    fun epochIds(): Set<String>
    fun createEpoch(): String
    fun encrypt(epoch: String, plaintext: ByteArray, aad: ByteArray): ByteArray
    fun decrypt(epoch: String, ciphertext: ByteArray, aad: ByteArray): ByteArray
    fun retireEpoch(epoch: String)
}

/**
 * Isolated proposal for a durable single-use dispatch claim, with a Keystore
 * epoch retired at every completed commit. It does NOT perform an effect,
 * authenticate inbound signaling, or implement the shared M2/M3/WSS owner.
 *
 * The caller must already have authenticated the exact semantic event under
 * the same serialized owner and must revalidate pinned consent before acting.
 * The global monitor only serializes instances in this ONE process.
 *
 * No production factory or Android Keystore backend uses this research class.
 * Failed/uncertain commits are terminal for the instance. No implicit
 * migration, key recreation, journal reset or destructive recovery.
 */
internal class VoiceDispatchContinuityLedger(
    private val raw: VoiceDispatchLedgerRawStore,
    private val keys: VoiceDispatchLedgerEpochKeys,
) {
    private var uncertain = false

    /**
     * True only after a newly consumed permit is durably committed, read back,
     * and the previous Keystore epoch is retired. False is a known duplicate.
     * Any ambiguous state is an exception and MUST NEVER dispatch an effect.
     */
    @Synchronized
    fun claim(
        ownerIdentityId: ByteArray,
        permit: VoiceSignalReplayDispatchPermit,
    ): Boolean = synchronized(WRITE_LOCK) {
        requireHealthy()
        requireOwner(ownerIdentityId)
        val keyDigest = messageKeyDigest(ownerIdentityId, permit)
        val binding = permitDigest(ownerIdentityId, permit)
        val current = readAuthenticated()
        if (current != null && !MessageDigest.isEqual(current.second.owner, ownerIdentityId)) {
            throw VoiceSignalReplayException("Durable dispatch ledger belongs to a different identity")
        }
        val prior = current?.second?.claims?.singleOrNull {
            MessageDigest.isEqual(it.messageKey, keyDigest)
        }
        if (prior != null) {
            if (!MessageDigest.isEqual(prior.permitBinding, binding)) {
                throw VoiceSignalReplayException(
                    "Conflicting authenticated metadata for already claimed voice message id"
                )
            }
            return@synchronized false
        }
        val oldClaims = current?.second?.claims.orEmpty()
        if (oldClaims.size >= MAX_CLAIMS) {
            throw VoiceSignalReplayException("Durable dispatch ledger is full; refuse further effects")
        }
        val next = State(ownerIdentityId.copyOf(), oldClaims + ClaimRecord(keyDigest, binding))
        val plaintext = encode(next)
        val previousEpoch = current?.first
        // Even a throwing createEpoch() can have left a new durable key behind.
        // Never retry automatically from the same process after this point.
        uncertain = true
        try {
            val fresh = keys.createEpoch()
            if (!EPOCH_ID.matches(fresh) || fresh == previousEpoch) {
                throw VoiceSignalReplayException("Dispatch epoch key is invalid or reused")
            }
            requireEpochs(if (previousEpoch == null) setOf(fresh) else setOf(previousEpoch, fresh))
            val sealed = keys.encrypt(fresh, plaintext, aad(fresh))
            if (sealed.isEmpty() || sealed.size + HEADER_BYTES > MAX_FILE_BYTES) {
                throw VoiceSignalReplayException("Protected dispatch ledger exceeds size bound")
            }
            val expected = MAGIC + byteArrayOf(VERSION) + fresh.toByteArray(Charsets.US_ASCII) + sealed
            if (!raw.write(expected)) {
                throw VoiceSignalReplayException("Dispatch claim atomic commit was refused")
            }
            if (raw.read()?.contentEquals(expected) != true) {
                throw VoiceSignalReplayException("Dispatch claim commit readback mismatch")
            }
            if (previousEpoch != null) keys.retireEpoch(previousEpoch)
            requireEpochs(setOf(fresh))
            val verified = readAuthenticated()
                ?: throw VoiceSignalReplayException("Committed dispatch ledger disappeared")
            if (verified.first != fresh ||
                !MessageDigest.isEqual(verified.second.owner, ownerIdentityId) ||
                verified.second.claims.size != next.claims.size ||
                verified.second.claims.zip(next.claims).any { (a, b) ->
                    !MessageDigest.isEqual(a.messageKey, b.messageKey) ||
                        !MessageDigest.isEqual(a.permitBinding, b.permitBinding)
                }
            ) {
                throw VoiceSignalReplayException("Dispatch ledger final verification failed")
            }
            uncertain = false
            true
        } finally {
            plaintext.fill(0)
            // On a failed commit, uncertain stays true. Never allow an effect.
        }
    }

    @Synchronized
    fun hasClaim(ownerIdentityId: ByteArray, permit: VoiceSignalReplayDispatchPermit): Boolean =
        synchronized(WRITE_LOCK) {
            requireHealthy()
            requireOwner(ownerIdentityId)
            val keyDigest = messageKeyDigest(ownerIdentityId, permit)
            val binding = permitDigest(ownerIdentityId, permit)
            val state = readAuthenticated()?.second ?: return@synchronized false
            if (!MessageDigest.isEqual(state.owner, ownerIdentityId)) {
                throw VoiceSignalReplayException("Durable dispatch ledger owner mismatch")
            }
            val prior = state.claims.singleOrNull {
                MessageDigest.isEqual(it.messageKey, keyDigest)
            } ?: return@synchronized false
            if (!MessageDigest.isEqual(prior.permitBinding, binding)) {
                throw VoiceSignalReplayException(
                    "Conflicting authenticated metadata for already claimed voice message id"
                )
            }
            true
        }

    @Synchronized
    fun clearForIdentityRecovery(): Nothing =
        throw VoiceSignalReplayException("Durable dispatch recovery requires explicit reviewed key deletion")

    private fun readAuthenticated(): Pair<String, State>? {
        val stored = raw.read()
        if (stored == null) {
            requireEpochs(emptySet())
            return null
        }
        if (stored.size !in (HEADER_BYTES + MIN_CIPHERTEXT_BYTES)..MAX_FILE_BYTES ||
            !stored.copyOfRange(0, 4).contentEquals(MAGIC) ||
            stored[4] != VERSION
        ) {
            throw VoiceSignalReplayException("Unknown or malformed protected dispatch ledger")
        }
        val epoch = stored.copyOfRange(5, HEADER_BYTES).toString(Charsets.US_ASCII)
        if (!EPOCH_ID.matches(epoch)) {
            throw VoiceSignalReplayException("Dispatch ledger epoch id invalid")
        }
        requireEpochs(setOf(epoch))
        val plaintext = try {
            keys.decrypt(epoch, stored.copyOfRange(HEADER_BYTES, stored.size), aad(epoch))
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Cannot authenticate durable dispatch ledger", error)
        }
        try {
            val decoded = decode(plaintext)
            requireEpochs(setOf(epoch))
            return epoch to decoded
        } finally {
            plaintext.fill(0)
        }
    }

    private fun requireHealthy() {
        if (uncertain) throw VoiceSignalReplayException(
            "Uncertain dispatch claim; no effects permitted until explicit recovery"
        )
    }

    private fun requireEpochs(expected: Set<String>) {
        val actual = try {
            keys.epochIds()
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Cannot inspect dispatch Keystore namespace", error)
        }
        if (actual != expected) {
            throw VoiceSignalReplayException("Dispatch key namespace inconsistent or rolled back")
        }
    }

    private fun requireOwner(owner: ByteArray) {
        if (owner.size != OWNER_BYTES || owner.all { it == 0.toByte() }) {
            throw VoiceSignalReplayException("Dispatch ledger owner is invalid")
        }
    }

    private fun messageKeyDigest(owner: ByteArray, permit: VoiceSignalReplayDispatchPermit): ByteArray {
        validatePermit(owner, permit)
        return MessageDigest.getInstance("SHA-256").digest(
            MESSAGE_KEY_DOMAIN + owner + permit.peerIdentityId + permit.messageId
        )
    }

    private fun validatePermit(owner: ByteArray, permit: VoiceSignalReplayDispatchPermit) {
        if (permit.peerIdentityId.size != OWNER_BYTES ||
            permit.peerIdentityId.all { it == 0.toByte() } ||
            MessageDigest.isEqual(owner, permit.peerIdentityId) ||
            permit.messageId.size != MESSAGE_BYTES ||
            permit.callId.size != MESSAGE_BYTES ||
            permit.envelopeDigest.size != DIGEST_BYTES ||
            permit.kind.number !in 1..255
        ) {
            throw VoiceSignalReplayException("Dispatch ledger permit key is invalid")
        }
    }

    private fun permitDigest(owner: ByteArray, permit: VoiceSignalReplayDispatchPermit): ByteArray {
        validatePermit(owner, permit)
        val buffer = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.write(PERMIT_DOMAIN)
                out.write(owner)
                out.write(permit.peerIdentityId)
                out.write(permit.messageId)
                out.write(permit.callId)
                out.writeInt(permit.kind.number)
                out.write(permit.envelopeDigest)
            }
            bytes.toByteArray()
        }
        return try {
            MessageDigest.getInstance("SHA-256").digest(buffer)
        } finally {
            buffer.fill(0)
        }
    }

    /** One message key is claimable once, independent of its forged call/digest fields. */
    private data class ClaimRecord(val messageKey: ByteArray, val permitBinding: ByteArray)
    private data class State(val owner: ByteArray, val claims: List<ClaimRecord>)

    private fun encode(state: State): ByteArray = ByteArrayOutputStream().use { bytes ->
        DataOutputStream(bytes).use { output ->
            output.write(STATE_MAGIC)
            output.write(state.owner)
            output.writeInt(state.claims.size)
            state.claims.forEach {
                output.write(it.messageKey)
                output.write(it.permitBinding)
            }
        }
        bytes.toByteArray()
    }

    private fun decode(bytes: ByteArray): State {
        if (bytes.size !in STATE_HEADER_BYTES..MAX_STATE_BYTES) {
            throw VoiceSignalReplayException("Protected dispatch state size invalid")
        }
        return try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val magic = ByteArray(4).also(input::readFully)
                if (!magic.contentEquals(STATE_MAGIC)) {
                    throw VoiceSignalReplayException("Protected dispatch state version invalid")
                }
                val owner = ByteArray(OWNER_BYTES).also(input::readFully)
                requireOwner(owner)
                val count = input.readInt()
                if (count !in 1..MAX_CLAIMS || input.available() != count * CLAIM_RECORD_BYTES) {
                    throw VoiceSignalReplayException("Protected dispatch claim count invalid")
                }
                val seen = HashSet<List<Byte>>()
                val claims = List(count) {
                    val key = ByteArray(DIGEST_BYTES).also(input::readFully)
                    val binding = ByteArray(DIGEST_BYTES).also(input::readFully)
                    if (!seen.add(key.toList())) {
                        throw VoiceSignalReplayException("Duplicate message key in protected ledger")
                    }
                    ClaimRecord(key, binding)
                }
                State(owner, claims)
            }
        } catch (error: VoiceSignalReplayException) {
            throw error
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Cannot parse protected dispatch claim state", error)
        }
    }

    private fun aad(epoch: String): ByteArray = AAD_DOMAIN + epoch.toByteArray(Charsets.US_ASCII)

    private companion object {
        val WRITE_LOCK = Any()
        val MAGIC = "KDL1".toByteArray(Charsets.US_ASCII)
        val STATE_MAGIC = "KDC2".toByteArray(Charsets.US_ASCII)
        val PERMIT_DOMAIN = "KENATO-M5-DISPATCH-PERMIT-V1\u0000".toByteArray(Charsets.UTF_8)
        val MESSAGE_KEY_DOMAIN = "KENATO-M5-DISPATCH-MESSAGE-V1\u0000".toByteArray(Charsets.UTF_8)
        val AAD_DOMAIN = "KENATO-M5-DISPATCH-EPOCH-V1\u0000".toByteArray(Charsets.UTF_8)
        val EPOCH_ID = Regex("[0-9a-f]{32}")
        const val VERSION: Byte = 1
        const val OWNER_BYTES = 32
        const val MESSAGE_BYTES = 16
        const val DIGEST_BYTES = 32
        const val MAX_CLAIMS = 1024
        const val STATE_HEADER_BYTES = 4 + OWNER_BYTES + 4
        const val CLAIM_RECORD_BYTES = 2 * DIGEST_BYTES
        const val MAX_STATE_BYTES = STATE_HEADER_BYTES + MAX_CLAIMS * CLAIM_RECORD_BYTES
        const val HEADER_BYTES = 4 + 1 + 32
        const val MIN_CIPHERTEXT_BYTES = 12 + 16 + STATE_HEADER_BYTES + CLAIM_RECORD_BYTES
        const val MAX_FILE_BYTES = HEADER_BYTES + MAX_STATE_BYTES + 128
    }
}
