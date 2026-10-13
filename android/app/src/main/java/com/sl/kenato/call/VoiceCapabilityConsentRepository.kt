package com.sl.kenato.call

import com.sl.kenato.contact.ContactCrypto
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant

internal class VoiceCapabilityConsentException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

/** A separate encrypted, no-backup AtomicFile, NEVER the semantic SDP/ICE store file. */
internal interface VoiceCapabilityEncryptedStore {
    fun read(): ByteArray?
    fun write(bytes: ByteArray): Boolean
    fun clear(): Boolean
}

/** Hardware-key invalidation on explicit destructive local identity recovery. */
internal interface VoiceCapabilityKeyLifecycle {
    fun deleteCapabilityKeyForIdentityRecovery()
}

/** Required independent cipher type; never reuse the semantic SDP/ICE encryption key. */
internal interface VoiceCapabilityPayloadCipher :
    VoiceSemanticPayloadCipher, VoiceCapabilityKeyLifecycle

internal fun interface VoiceCapabilityConsentClock {
    fun nowEpochSeconds(): Long
}

private object SystemVoiceCapabilityConsentClock : VoiceCapabilityConsentClock {
    override fun nowEpochSeconds(): Long = Instant.now().epochSecond
}

internal class VoiceCapabilityChallenge(
    val ownerIdentityId: ByteArray,
    val peerIdentityId: ByteArray,
    val challenge: ByteArray,
    val expiresAtEpochSeconds: Long,
)

/**
 * Exactly one state per peer: either a pending one-time challenge or confirmed
 * user-approved capability. A confirmation has no challenge nonce to replay.
 */
internal class VoiceCapabilityConsentEntry(
    val peerIdentityId: ByteArray,
    val peerPublicKeyDigest: ByteArray,
    val challenge: ByteArray,
    val challengeIssuedAt: Long,
    val challengeExpiresAt: Long,
    val approvedAt: Long,
)

internal class VoiceCapabilityConsentState(
    val ownerIdentityId: ByteArray,
    val entries: List<VoiceCapabilityConsentEntry>,
)

internal object VoiceCapabilityConsentStateCodec {
    const val MAX_CONTACTS = 128
    const val MAX_BYTES = 16 * 1024
    const val MAX_ENCRYPTED_BYTES = MAX_BYTES + 64
    private const val VERSION = 1
    private const val ID_BYTES = 32
    private const val NONCE_BYTES = VoiceCapabilityProofWire.CHALLENGE_BYTES
    private const val DIGEST_BYTES = 32
    private const val RECORD_BYTES = ID_BYTES + DIGEST_BYTES + NONCE_BYTES + 8 + 8 + 8
    private const val HEADER_BYTES = 4 + 4 + ID_BYTES + 4
    private val magic = byteArrayOf('K'.code.toByte(), 'C'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte())

    fun encode(state: VoiceCapabilityConsentState): ByteArray {
        validate(state)
        val content = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.write(magic)
                out.writeInt(VERSION)
                out.write(state.ownerIdentityId)
                out.writeInt(state.entries.size)
                for (r in state.entries) {
                    out.write(r.peerIdentityId)
                    out.write(r.peerPublicKeyDigest)
                    out.write(r.challenge)
                    out.writeLong(r.challengeIssuedAt)
                    out.writeLong(r.challengeExpiresAt)
                    out.writeLong(r.approvedAt)
                }
            }
            bytes.toByteArray()
        }
        if (content.size + DIGEST_BYTES > MAX_BYTES) {
            throw VoiceCapabilityConsentException("Capability state exceeds maximum size")
        }
        return content + MessageDigest.getInstance("SHA-256").digest(content)
    }

    fun decode(bytes: ByteArray): VoiceCapabilityConsentState {
        if (bytes.size !in (HEADER_BYTES + DIGEST_BYTES)..MAX_BYTES) {
            throw VoiceCapabilityConsentException("Capability state size invalid")
        }
        val payloadLength = bytes.size - DIGEST_BYTES
        val digest = MessageDigest.getInstance("SHA-256").run {
            update(bytes, 0, payloadLength)
            digest()
        }
        if (!MessageDigest.isEqual(digest, bytes.copyOfRange(payloadLength, bytes.size))) {
            throw VoiceCapabilityConsentException("Capability state checksum mismatch")
        }
        return try {
            DataInputStream(ByteArrayInputStream(bytes, 0, payloadLength)).use { input ->
                val header = ByteArray(4).also(input::readFully)
                if (!header.contentEquals(magic) || input.readInt() != VERSION) {
                    throw VoiceCapabilityConsentException("Capability state format unsupported")
                }
                val owner = ByteArray(ID_BYTES).also(input::readFully)
                val count = input.readInt()
                if (count !in 0..MAX_CONTACTS || input.available() != count * RECORD_BYTES) {
                    throw VoiceCapabilityConsentException("Capability state record count invalid")
                }
                val entries = List(count) {
                    VoiceCapabilityConsentEntry(
                        peerIdentityId = ByteArray(ID_BYTES).also(input::readFully),
                        peerPublicKeyDigest = ByteArray(DIGEST_BYTES).also(input::readFully),
                        challenge = ByteArray(NONCE_BYTES).also(input::readFully),
                        challengeIssuedAt = input.readLong(),
                        challengeExpiresAt = input.readLong(),
                        approvedAt = input.readLong(),
                    )
                }
                if (input.available() != 0) {
                    throw VoiceCapabilityConsentException("Capability state has trailing bytes")
                }
                VoiceCapabilityConsentState(owner, entries).also(::validate)
            }
        } catch (error: VoiceCapabilityConsentException) {
            throw error
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Capability state corrupted", error)
        }
    }

    private fun validate(state: VoiceCapabilityConsentState) {
        if (state.ownerIdentityId.size != ID_BYTES ||
            state.ownerIdentityId.all { it == 0.toByte() } ||
            state.entries.size > MAX_CONTACTS
        ) {
            throw VoiceCapabilityConsentException("Capability owner/count invalid")
        }
        val seen = HashSet<List<Byte>>()
        for (r in state.entries) {
            if (r.peerIdentityId.size != ID_BYTES ||
                r.peerIdentityId.all { it == 0.toByte() } ||
                r.peerIdentityId.contentEquals(state.ownerIdentityId) ||
                r.peerPublicKeyDigest.size != DIGEST_BYTES ||
                !MessageDigest.isEqual(r.peerPublicKeyDigest, r.peerIdentityId) ||
                r.challenge.size != NONCE_BYTES ||
                !seen.add(r.peerIdentityId.toList())
            ) {
                throw VoiceCapabilityConsentException("Capability contact record invalid")
            }
            if (r.approvedAt == 0L) {
                if (r.challenge.all { it == 0.toByte() } ||
                    r.challengeIssuedAt <= 0L ||
                    r.challengeExpiresAt <= r.challengeIssuedAt ||
                    r.challengeExpiresAt - r.challengeIssuedAt > VoiceCapabilityProofWire.MAX_LIFETIME_SECONDS
                ) {
                    throw VoiceCapabilityConsentException("Pending capability challenge invalid")
                }
            } else if (r.approvedAt < 0L ||
                r.challenge.any { it != 0.toByte() } ||
                r.challengeIssuedAt != 0L ||
                r.challengeExpiresAt != 0L
            ) {
                throw VoiceCapabilityConsentException("Approved capability cannot retain a challenge")
            }
        }
    }
}

/**
 * Client-only opt-in verified-peer capability handshake state. No v2 capability
 * is inferred from an unknown client; do not send in-band probes to M4 peers.
 * UI/QR exchange and outbound voice use are deliberately NOT connected.
 *
 * The outer Android caller must supply the contact's currently pinned M2 key,
 * display the intended contact and request explicit user approval for each proof.
 * Only an authenticated P-256 signature tied to the stored one-time challenge
 * permits a durable, positive v2 capability. No call effects are granted here.
 */
internal class DurableVoiceCapabilityConsentRepository(
    private val store: VoiceCapabilityEncryptedStore,
    private val cipher: VoiceCapabilityPayloadCipher,
    private val random: SecureRandom = SecureRandom(),
    private val clock: VoiceCapabilityConsentClock = SystemVoiceCapabilityConsentClock,
) {
    @Synchronized
    fun issueChallenge(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        pinnedPeerPublicKey: ByteArray,
    ): VoiceCapabilityChallenge {
        validateOwnerPeer(ownerIdentityId, peerIdentityId, pinnedPeerPublicKey)
        val now = now()
        if (now > Long.MAX_VALUE - VoiceCapabilityProofWire.MAX_LIFETIME_SECONDS) {
            throw VoiceCapabilityConsentException("Capability challenge expiry overflow")
        }
        val state = load(ownerIdentityId)
        val retained = state?.entries.orEmpty().filter {
            it.approvedAt > 0L || it.challengeExpiresAt > now
        }
        if (retained.any { it.peerIdentityId.contentEquals(peerIdentityId) && it.approvedAt > 0L }) {
            throw VoiceCapabilityConsentException("Capability already approved; revoke first")
        }
        val remaining = retained.filterNot { it.peerIdentityId.contentEquals(peerIdentityId) }
        if (remaining.size >= VoiceCapabilityConsentStateCodec.MAX_CONTACTS) {
            throw VoiceCapabilityConsentException("Capability store full")
        }
        // Include the challenge being rotated: never deliberately reuse the old nonce.
        val challenge = generateUniqueChallenge(retained)
        val entry = VoiceCapabilityConsentEntry(
            peerIdentityId.copyOf(),
            peerIdentityId.copyOf(),
            challenge.copyOf(),
            now,
            now + VoiceCapabilityProofWire.MAX_LIFETIME_SECONDS,
            approvedAt = 0L,
        )
        persist(ownerIdentityId, remaining + entry)
        return VoiceCapabilityChallenge(
            ownerIdentityId.copyOf(),
            peerIdentityId.copyOf(),
            challenge.copyOf(),
            entry.challengeExpiresAt,
        )
    }

    @Synchronized
    fun confirmSignedProof(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        pinnedPeerPublicKey: ByteArray,
        encodedProof: ByteArray,
        explicitUserApproval: Boolean,
    ) {
        validateOwnerPeer(ownerIdentityId, peerIdentityId, pinnedPeerPublicKey)
        if (!explicitUserApproval) {
            throw VoiceCapabilityConsentException("Explicit user approval is required")
        }
        val now = now()
        val entries = load(ownerIdentityId)?.entries.orEmpty()
        val pending = entries.singleOrNull {
            it.peerIdentityId.contentEquals(peerIdentityId) && it.approvedAt == 0L
        } ?: throw VoiceCapabilityConsentException("No outstanding capability challenge")
        if (pending.challengeExpiresAt <= now) {
            throw VoiceCapabilityConsentException("Pending capability challenge expired")
        }
        val proof = VoiceCapabilityProofWire.verifyForPinnedContact(
            encodedProof,
            ownerIdentityId,
            peerIdentityId,
            pinnedPeerPublicKey,
            pending.challenge,
            now,
        )
        if (proof.issuedAtEpochSeconds < pending.challengeIssuedAt - VoiceCapabilityProofWire.MAX_FUTURE_SKEW_SECONDS ||
            proof.expiresAtEpochSeconds > pending.challengeExpiresAt
        ) {
            throw VoiceCapabilityConsentException("Signed proof is not bound to this challenge lifetime")
        }
        val confirmed = VoiceCapabilityConsentEntry(
            pending.peerIdentityId.copyOf(),
            pending.peerPublicKeyDigest.copyOf(),
            ByteArray(VoiceCapabilityProofWire.CHALLENGE_BYTES),
            challengeIssuedAt = 0L,
            challengeExpiresAt = 0L,
            approvedAt = now,
        )
        persist(ownerIdentityId, entries.map {
            if (it.peerIdentityId.contentEquals(peerIdentityId)) confirmed else it
        })
    }

    /** Verified only for this currently pinned public key; never consult relay hints. */
    @Synchronized
    fun isVoiceVersion2Confirmed(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        pinnedPeerPublicKey: ByteArray,
    ): Boolean {
        validateOwnerPeer(ownerIdentityId, peerIdentityId, pinnedPeerPublicKey)
        return load(ownerIdentityId)?.entries?.any {
            it.approvedAt > 0L &&
                it.peerIdentityId.contentEquals(peerIdentityId) &&
                MessageDigest.isEqual(it.peerPublicKeyDigest, peerIdentityId)
        } == true
    }

    @Synchronized
    fun revoke(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
    ) {
        validateIdentityPair(ownerIdentityId, peerIdentityId)
        val state = load(ownerIdentityId) ?: return
        persist(ownerIdentityId, state.entries.filterNot {
            it.peerIdentityId.contentEquals(peerIdentityId)
        })
    }

    /** Must be called together with explicit destructive local identity recovery. */
    @Synchronized
    fun clearForIdentityRecovery() {
        // Deleting the key first makes an old encrypted blob undecryptable even
        // if a destructive file clear fails or a stale file is restored later.
        cipher.deleteCapabilityKeyForIdentityRecovery()
        if (!store.clear()) {
            throw VoiceCapabilityConsentException("Unable to clear capability recovery state")
        }
    }

    private fun persist(owner: ByteArray, entries: List<VoiceCapabilityConsentEntry>) {
        val plaintext = VoiceCapabilityConsentStateCodec.encode(
            VoiceCapabilityConsentState(owner.copyOf(), entries),
        )
        val encrypted = try {
            cipher.encrypt(plaintext, aad(owner))
        } finally {
            plaintext.fill(0)
        }
        if (encrypted.isEmpty() ||
            encrypted.size > VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES ||
            !store.write(encrypted)
        ) {
            throw VoiceCapabilityConsentException("Capability consent state not durably stored")
        }
    }

    private fun load(owner: ByteArray): VoiceCapabilityConsentState? {
        val encrypted = store.read() ?: return null
        if (encrypted.isEmpty() ||
            encrypted.size > VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES
        ) {
            throw VoiceCapabilityConsentException("Encrypted capability state oversized")
        }
        val plaintext = try {
            cipher.decrypt(encrypted, aad(owner))
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Cannot authenticate capability state", error)
        }
        return try {
            VoiceCapabilityConsentStateCodec.decode(plaintext).also {
                if (!MessageDigest.isEqual(it.ownerIdentityId, owner)) {
                    throw VoiceCapabilityConsentException("Capability state owner mismatch")
                }
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun generateUniqueChallenge(existing: List<VoiceCapabilityConsentEntry>): ByteArray {
        repeat(8) {
            val candidate = ByteArray(VoiceCapabilityProofWire.CHALLENGE_BYTES).also(random::nextBytes)
            if (candidate.any { it != 0.toByte() } &&
                existing.none { MessageDigest.isEqual(it.challenge, candidate) }
            ) {
                return candidate
            }
        }
        throw VoiceCapabilityConsentException("Cannot generate a fresh unique capability challenge")
    }

    private fun validateOwnerPeer(owner: ByteArray, peer: ByteArray, pinnedPublicKey: ByteArray) {
        validateIdentityPair(owner, peer)
        try {
            val derived = ContactCrypto.identityId(pinnedPublicKey)
            if (!MessageDigest.isEqual(derived, peer)) {
                throw VoiceCapabilityConsentException("Pinned M2 identity key mismatch")
            }
        } catch (error: VoiceCapabilityConsentException) {
            throw error
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Invalid pinned M2 identity key", error)
        }
    }

    private fun validateIdentityPair(owner: ByteArray, peer: ByteArray) {
        if (owner.size != 32 || peer.size != 32 ||
            owner.all { it == 0.toByte() } ||
            peer.all { it == 0.toByte() } ||
            MessageDigest.isEqual(owner, peer)
        ) {
            throw VoiceCapabilityConsentException("Voice capability identity pair invalid")
        }
    }

    private fun now(): Long = clock.nowEpochSeconds().also {
        if (it <= 0L) throw VoiceCapabilityConsentException("Invalid voice capability clock")
    }

    private fun aad(owner: ByteArray): ByteArray =
        "KENATO-M5-VOICE-CAPABILITY-CONSENT-V1\u0000".toByteArray(Charsets.UTF_8) + owner
}
