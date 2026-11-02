package com.sl.kenato.call

/**
 * Raw storage for the *isolated* KCE2 continuity envelope. The existing v1
 * AtomicFile has a smaller size limit and is NOT a compatible backing.
 */
internal interface VoiceConsentEpochRawStore {
    fun read(): ByteArray?
    fun write(bytes: ByteArray): Boolean
}

/**
 * Own dedicated Keystore namespace, independent from M3 KAE2, M5 semantic events
 * and the existing fixed-alias M5 consent cipher. Never silently generate a key
 * during decrypt or reuse an epoch after deletion.
 */
internal interface VoiceConsentEpochKeys {
    fun epochIds(): Set<String>
    fun createEpoch(): String
    fun seal(epoch: String, ciphertext: ByteArray, aad: ByteArray): ByteArray
    fun open(epoch: String, envelope: ByteArray, aad: ByteArray): ByteArray
    fun retire(epoch: String)
}

/**
 * JVM-only, unwired KCE2 proof: a file-only rollback adversary cannot restore
 * an older *authentic* consent snapshot after the older Keystore key is retired.
 *
 * NOT a production migration. No Android key backend, storage factory or UI
 * calls this class. This protocol fails closed on uncertain commits; a recovery
 * protocol, interprocess lock and real-device evidence are still missing.
 */
internal class EpochBoundVoiceConsentStore(
    private val backing: VoiceConsentEpochRawStore,
    private val keys: VoiceConsentEpochKeys,
) {
    private var uncertainCommit = false

    @Synchronized
    fun readEncryptedConsent(): ByteArray? {
        requireUnpoisoned()
        return authenticated()?.second
    }

    @Synchronized
    fun commitEncryptedConsent(ciphertext: ByteArray): Boolean {
        requireUnpoisoned()
        if (ciphertext.isEmpty() ||
            ciphertext.size > VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES
        ) {
            throw VoiceCapabilityConsentException("KCE2 consent ciphertext size invalid")
        }
        val previous = authenticated()
        val old = previous?.first
        previous?.second?.fill(0)

        // A key can be created even when createEpoch throws after touching the
        // Keystore. Do not automatically recover from ANY ambiguous mutation.
        uncertainCommit = true
        val fresh = keys.createEpoch()
        if (!EPOCH_PATTERN.matches(fresh) || fresh == old) {
            throw VoiceCapabilityConsentException("KCE2 epoch invalid or reused")
        }
        requireEpochs(if (old == null) setOf(fresh) else setOf(old, fresh))
        val envelope = keys.seal(fresh, ciphertext, aad(fresh))
        if (envelope.isEmpty() || envelope.size + HEADER_BYTES > MAX_PERSISTED_BYTES) {
            throw VoiceCapabilityConsentException("KCE2 envelope exceeds bound")
        }
        val encoded = MAGIC + byteArrayOf(VERSION) + fresh.toByteArray(Charsets.US_ASCII) + envelope
        if (!backing.write(encoded)) {
            throw VoiceCapabilityConsentException("KCE2 commit uncertain; explicit recovery required")
        }
        if (backing.read()?.contentEquals(encoded) != true) {
            throw VoiceCapabilityConsentException("KCE2 written bytes differ from committed state")
        }
        if (old != null) keys.retire(old)
        requireEpochs(setOf(fresh))
        val check = authenticated()
            ?: throw VoiceCapabilityConsentException("KCE2 committed state disappeared")
        try {
            if (check.first != fresh || !check.second.contentEquals(ciphertext)) {
                throw VoiceCapabilityConsentException("KCE2 commit verification failed")
            }
        } finally {
            check.second.fill(0)
        }
        uncertainCommit = false
        return true
    }

    /** No implicit deletion/recreation of keys or loss of explicit revocations. */
    @Synchronized
    fun clearForIdentityRecovery(): Nothing =
        throw VoiceCapabilityConsentException("KCE2 recovery requires a separately reviewed protocol")

    private fun authenticated(): Pair<String, ByteArray>? {
        val stored = backing.read()
        if (stored == null) {
            requireEpochs(emptySet())
            return null
        }
        if (stored.size !in (HEADER_BYTES + 1)..MAX_PERSISTED_BYTES ||
            !stored.copyOfRange(0, 4).contentEquals(MAGIC) ||
            stored[4] != VERSION
        ) {
            throw VoiceCapabilityConsentException("Unsupported KCE2 consent storage; no legacy fallback")
        }
        val epoch = stored.copyOfRange(5, HEADER_BYTES).toString(Charsets.US_ASCII)
        if (!EPOCH_PATTERN.matches(epoch)) {
            throw VoiceCapabilityConsentException("KCE2 epoch identifier invalid")
        }
        requireEpochs(setOf(epoch))
        val result = try {
            keys.open(epoch, stored.copyOfRange(HEADER_BYTES, stored.size), aad(epoch))
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("KCE2 consent epoch authentication failed", error)
        }
        if (result.isEmpty() || result.size > VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES) {
            result.fill(0)
            throw VoiceCapabilityConsentException("KCE2 decrypted consent ciphertext invalid")
        }
        try {
            requireEpochs(setOf(epoch))
        } catch (error: Exception) {
            result.fill(0)
            throw error
        }
        return epoch to result
    }

    private fun requireEpochs(expected: Set<String>) {
        val actual = try {
            keys.epochIds()
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Unable to enumerate KCE2 epochs", error)
        }
        if (actual != expected) {
            throw VoiceCapabilityConsentException("Ambiguous or rolled-back KCE2 consent namespace")
        }
    }

    private fun requireUnpoisoned() {
        if (uncertainCommit) {
            throw VoiceCapabilityConsentException("KCE2 uncertain commit; refuse further consent access")
        }
    }

    private fun aad(epoch: String) = AAD_PREFIX + epoch.toByteArray(Charsets.US_ASCII)

    private companion object {
        val MAGIC = byteArrayOf('K'.code.toByte(), 'C'.code.toByte(), 'E'.code.toByte(), '2'.code.toByte())
        const val VERSION: Byte = 1
        const val HEADER_BYTES = 4 + 1 + 32
        const val MAX_PERSISTED_BYTES = VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES + 128
        val EPOCH_PATTERN = Regex("[0-9a-f]{32}")
        val AAD_PREFIX = "KENATO-M5-VOICE-CONSENT-EPOCH-V1\u005c\u00750000"
            .toByteArray(Charsets.UTF_8)
    }
}
