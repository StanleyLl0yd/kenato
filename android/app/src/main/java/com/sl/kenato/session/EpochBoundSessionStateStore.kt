package com.sl.kenato.session

/**
 * Experimental M5 anti-rollback continuity backend. The caller must provide an isolated,
 * complete and trustworthy Keystore namespace: aliases are not stored in app-private files.
 * No production factory uses this protocol. It does not protect against compromised app UID,
 * a Keystore/OS rollback, or concurrent repository instances/processes.
 */
internal interface SessionEpochKeyBackend {
    /** Enumerate all keys in this protocol's dedicated Keystore namespace. */
    fun epochIds(): Set<String>

    /** Generate a fresh independent, nonexportable AES-GCM key and its random epoch id. */
    fun createEpoch(): String

    /** Encrypt with the named epoch key and the provided authenticated context. */
    fun encrypt(epochId: String, plaintext: ByteArray, aad: ByteArray): ByteArray

    /** Decrypt only using the named existing key; MUST NOT create one. */
    fun decrypt(epochId: String, envelope: ByteArray, aad: ByteArray): ByteArray

    /** Irreversibly delete the named epoch key. Failure must be reported. */
    fun retireEpoch(epochId: String)
}

/**
 * Fail-closed epoch-per-commit proof of concept for the file-rollback-only adversary.
 *
 * Commit protocol: authenticate the current snapshot and assert exactly one matching
 * Keystore epoch; create a fresh epoch; atomically write new ciphertext; retire the old
 * epoch; verify the final file and key namespace. Once the new key exists, every failure
 * is deliberately terminal for this store until separately approved identity recovery.
 *
 * This is NOT an AndroidKeyStore implementation, release migration, or production M3
 * session store. Device performance/durability, legacy migration and multi-process
 * transactions have NOT been demonstrated.
 */
internal class EpochBoundSessionStateStore(
    private val backing: SessionStateStore,
    private val keys: SessionEpochKeyBackend,
) : SessionStateStore {
    companion object {
        private val MAGIC = byteArrayOf('K'.code.toByte(), 'A'.code.toByte(), 'E'.code.toByte(), '2'.code.toByte())
        private const val VERSION: Byte = 1
        private const val EPOCH_ID_BYTES = 32
        private const val HEADER_BYTES = 4 + 1 + EPOCH_ID_BYTES
        const val MAX_PERSISTED_BYTES = SessionStateCodec.MAX_STATE_BYTES + 128
        private val AAD_PREFIX = "KENATO-M3-EPOCH-CONTINUITY-V1\u0000".toByteArray(Charsets.UTF_8)
        private val EPOCH_PATTERN = Regex("[0-9a-f]{32}")
    }

    @Synchronized
    override fun read(): ByteArray? {
        val current = readAuthenticated() ?: return null
        return current.second
    }

    @Synchronized
    override fun write(value: ByteArray): Boolean {
        if (value.isEmpty() || value.size > SessionStateCodec.MAX_STATE_BYTES) {
            throw SessionStateException("Epoch M3 plaintext state length invalid")
        }
        SessionStateCodec.decode(value)
        val previous = readAuthenticated()
        val oldEpoch = previous?.first
        previous?.second?.fill(0)

        // Nothing after createEpoch is recoverable automatically: an interrupted write
        // can leave one or two aliases and an uncertain AtomicFile result.
        val fresh = keys.createEpoch()
        if (!EPOCH_PATTERN.matches(fresh) || fresh == oldEpoch) {
            throw SessionStateException("Keystore returned an invalid or reused M3 epoch")
        }
        val expectedBefore = if (oldEpoch == null) setOf(fresh) else setOf(oldEpoch, fresh)
        requireEpochs(expectedBefore)
        val envelope = keys.encrypt(fresh, value, aad(fresh))
        if (envelope.isEmpty() || envelope.size + HEADER_BYTES > MAX_PERSISTED_BYTES) {
            throw SessionStateException("Epoch M3 protected envelope length invalid")
        }
        val encoded = MAGIC + byteArrayOf(VERSION) + fresh.toByteArray(Charsets.US_ASCII) + envelope
        if (!backing.write(encoded)) {
            throw SessionStateException("Epoch M3 atomic write did not commit; recovery required")
        }
        // Post-commit verification cannot turn an uncertain write into a successful ACK.
        if (!(backing.read()?.contentEquals(encoded) ?: false)) {
            throw SessionStateException("Epoch M3 committed file verification failed")
        }
        if (oldEpoch != null) keys.retireEpoch(oldEpoch)
        requireEpochs(setOf(fresh))
        val check = readAuthenticated()
            ?: throw SessionStateException("Epoch M3 state disappeared after commit")
        try {
            if (check.first != fresh || !check.second.contentEquals(value)) {
                throw SessionStateException("Epoch M3 committed state verification failed")
            }
        } finally {
            check.second.fill(0)
        }
        return true
    }

    /** No implicit destructive recovery from an uncertain commit. */
    @Synchronized
    override fun clear(): Boolean =
        throw SessionStateException("Epoch M3 identity recovery requires a separate explicit reviewed protocol")

    private fun readAuthenticated(): Pair<String, ByteArray>? {
        val stored = backing.read()
        if (stored == null) {
            requireEpochs(emptySet())
            return null
        }
        if (stored.size !in (HEADER_BYTES + 1)..MAX_PERSISTED_BYTES ||
            !stored.copyOfRange(0, 4).contentEquals(MAGIC) ||
            stored[4] != VERSION
        ) {
            throw SessionStateException("Unknown or invalid epoch M3 envelope; no legacy fallback")
        }
        val epoch = stored.copyOfRange(5, HEADER_BYTES).toString(Charsets.US_ASCII)
        if (!EPOCH_PATTERN.matches(epoch)) {
            throw SessionStateException("Invalid epoch M3 key identifier")
        }
        requireEpochs(setOf(epoch))
        val plaintext = try {
            keys.decrypt(epoch, stored.copyOfRange(HEADER_BYTES, stored.size), aad(epoch))
        } catch (error: Exception) {
            throw SessionStateException("Unable to authenticate epoch M3 state", error)
        }
        try {
            SessionStateCodec.decode(plaintext)
        } catch (error: Exception) {
            plaintext.fill(0)
            throw SessionStateException("Authenticated epoch M3 state is not canonical", error)
        }
        requireEpochs(setOf(epoch))
        return epoch to plaintext
    }

    private fun requireEpochs(expected: Set<String>) {
        val actual = try {
            keys.epochIds()
        } catch (error: Exception) {
            throw SessionStateException("Unable to inspect M3 Keystore epoch namespace", error)
        }
        if (actual != expected) {
            throw SessionStateException("Ambiguous or rolled-back M3 Keystore epoch namespace")
        }
    }

    private fun aad(epoch: String) = AAD_PREFIX + epoch.toByteArray(Charsets.US_ASCII)
}
