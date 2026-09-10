package com.sl.kenato.identity

import android.content.Context

/**
 * Owns the device-local identity lifecycle. All methods are synchronous and must be called off the UI thread.
 */
class LocalIdentityRepository internal constructor(
    private val keyBackend: IdentityKeyBackend,
    private val stateStore: IdentityStateStore,
    private val clock: IdentityClock,
) {
    @Synchronized
    fun loadOrCreate(): IdentityBundle {
        val existing = loadValidatedStateOrNull()
        return if (existing != null) existing.toBundle() else createNewIdentity().toBundle()
    }

    @Synchronized
    fun current(): IdentityBundle? = loadValidatedStateOrNull()?.toBundle()

    @Synchronized
    fun rotateSignedPreKey(): IdentityBundle {
        val state = requireInitializedState()
        val newId = state.nextPreKeyId.requireAllocatable()
        val replacement = generateStoredPreKey(newId, PreKeyKind.SIGNED)
        val updated = state.copy(
            signedPreKey = replacement,
            previousSignedPreKey = state.signedPreKey,
            nextPreKeyId = newId + 1,
        )
        persist(updated)
        return updated.toBundle()
    }

    @Synchronized
    fun retirePreviousSignedPreKey(): IdentityBundle {
        val state = requireInitializedState()
        if (state.previousSignedPreKey == null) {
            return state.toBundle()
        }
        val updated = state.copy(previousSignedPreKey = null)
        persist(updated)
        return updated.toBundle()
    }

    @Synchronized
    fun consumeOneTimePreKey(id: Int): Boolean {
        require(id > 0) { "Prekey id must be positive" }
        val state = requireInitializedState()
        val retained = state.oneTimePreKeys.filterNot { it.id == id }
        if (retained.size == state.oneTimePreKeys.size) {
            return false
        }
        persist(state.copy(oneTimePreKeys = retained))
        return true
    }

    @Synchronized
    fun replenishOneTimePreKeys(targetCount: Int = DEFAULT_ONE_TIME_PREKEYS): IdentityBundle {
        require(targetCount in 0..IdentityStateCodec.MAX_ONE_TIME_PREKEYS) {
            "One-time prekey target is out of bounds"
        }

        val state = requireInitializedState()
        if (state.oneTimePreKeys.size >= targetCount) {
            return state.toBundle()
        }

        var nextId = state.nextPreKeyId
        val replenished = state.oneTimePreKeys.toMutableList()
        while (replenished.size < targetCount) {
            val allocated = nextId.requireAllocatable()
            replenished += generateStoredPreKey(allocated, PreKeyKind.ONE_TIME)
            nextId = allocated + 1
        }

        val updated = state.copy(
            oneTimePreKeys = replenished,
            nextPreKeyId = nextId,
        )
        persist(updated)
        return updated.toBundle()
    }

    /**
     * Destructive recovery primitive. A caller must require an explicit user decision before invoking it.
     */
    @Synchronized
    fun resetLocalIdentityForRecovery() {
        if (!stateStore.clear()) {
            throw IdentityPersistenceException("Unable to clear persisted local identity state")
        }
        keyBackend.deleteManagedKeys()
    }

    private fun createNewIdentity(): LocalIdentityState {
        if (keyBackend.hasAnyManagedKey()) {
            throw IdentityStateException(
                "Android Keystore identity material exists without persisted state; explicit recovery is required",
            )
        }

        try {
            val identityPublicKey = keyBackend.createManagedKeys()
            var nextId = FIRST_PREKEY_ID

            val signedId = nextId.requireAllocatable()
            val signedPreKey = generateStoredPreKey(signedId, PreKeyKind.SIGNED)
            nextId = signedId + 1

            val oneTimePreKeys = ArrayList<StoredPreKey>(DEFAULT_ONE_TIME_PREKEYS)
            repeat(DEFAULT_ONE_TIME_PREKEYS) {
                val allocated = nextId.requireAllocatable()
                oneTimePreKeys += generateStoredPreKey(allocated, PreKeyKind.ONE_TIME)
                nextId = allocated + 1
            }

            val state = LocalIdentityState(
                identityPublicKey = identityPublicKey,
                signedPreKey = signedPreKey,
                previousSignedPreKey = null,
                oneTimePreKeys = oneTimePreKeys,
                nextPreKeyId = nextId,
            )
            validateCryptographicState(state)
            persist(state)
            return state
        } catch (error: Throwable) {
            try {
                keyBackend.deleteManagedKeys()
            } catch (cleanupError: Throwable) {
                error.addSuppressed(cleanupError)
            }
            throw error
        }
    }

    private fun requireInitializedState(): LocalIdentityState =
        loadValidatedStateOrNull()
            ?: throw IdentityStateException("Local identity has not been initialized")

    private fun loadValidatedStateOrNull(): LocalIdentityState? {
        val encoded = stateStore.read()
        if (encoded == null) {
            if (keyBackend.hasAnyManagedKey()) {
                throw IdentityStateException(
                    "Android Keystore identity material exists without persisted state; explicit recovery is required",
                )
            }
            return null
        }

        if (!keyBackend.hasAllManagedKeys()) {
            throw IdentityStateException(
                "Persisted identity state exists but Android Keystore material is missing; refusing silent regeneration",
            )
        }

        val state = IdentityStateCodec.decode(encoded)
        val keystorePublicKey = keyBackend.identityPublicKey()
        if (!keystorePublicKey.contentEquals(state.identityPublicKey)) {
            throw IdentityStateException(
                "Persisted identity public key does not match Android Keystore material",
            )
        }

        validateCryptographicState(state)
        return state
    }

    private fun validateCryptographicState(state: LocalIdentityState) {
        validateSignedPreKey(state.identityPublicKey, state.signedPreKey)
        state.previousSignedPreKey?.let { validateSignedPreKey(state.identityPublicKey, it) }

        if (!keyBackend.validateEncryptedPreKey(state.signedPreKey, PreKeyKind.SIGNED)) {
            throw IdentityStateException("Signed prekey private material is invalid")
        }
        state.previousSignedPreKey?.let {
            if (!keyBackend.validateEncryptedPreKey(it, PreKeyKind.SIGNED)) {
                throw IdentityStateException("Previous signed prekey private material is invalid")
            }
        }
        for (preKey in state.oneTimePreKeys) {
            if (!keyBackend.validateEncryptedPreKey(preKey, PreKeyKind.ONE_TIME)) {
                throw IdentityStateException("One-time prekey private material is invalid")
            }
        }
    }

    private fun validateSignedPreKey(identityPublicKey: ByteArray, preKey: StoredPreKey) {
        val signature = preKey.signature
            ?: throw IdentityStateException("Signed prekey signature is missing")
        val payload = IdentityPrimitives.signedPreKeyPayload(preKey.id, preKey.publicKey)
        if (!IdentityPrimitives.verifyP256Signature(identityPublicKey, payload, signature)) {
            throw IdentityStateException("Signed prekey signature is invalid")
        }
    }

    private fun generateStoredPreKey(id: Int, kind: PreKeyKind): StoredPreKey {
        val generated = keyBackend.generatePreKey(id, kind)
        val signature = if (kind == PreKeyKind.SIGNED) {
            keyBackend.signIdentity(IdentityPrimitives.signedPreKeyPayload(id, generated.publicKey))
        } else {
            null
        }

        return StoredPreKey(
            id = id,
            createdAtEpochSeconds = clock.nowEpochSeconds().also {
                if (it < 0) {
                    throw IdentityStateException("Identity clock returned an invalid timestamp")
                }
            },
            publicKey = generated.publicKey,
            encryptedPrivateKey = generated.encryptedPrivateKey,
            signature = signature,
        )
    }

    private fun persist(state: LocalIdentityState) {
        val encoded = IdentityStateCodec.encode(state)
        if (!stateStore.write(encoded)) {
            throw IdentityPersistenceException("Unable to commit local identity state")
        }
    }

    private fun LocalIdentityState.toBundle(): IdentityBundle = IdentityBundle(
        identityId = IdentityPrimitives.identityId(identityPublicKey),
        identityPublicKey = IdentityPrimitives.base64Url(identityPublicKey),
        signedPreKey = SignedPreKey(
            id = signedPreKey.id,
            publicKey = IdentityPrimitives.base64Url(signedPreKey.publicKey),
            signature = IdentityPrimitives.base64Url(
                signedPreKey.signature ?: throw IdentityStateException("Signed prekey signature is missing"),
            ),
            createdAtEpochSeconds = signedPreKey.createdAtEpochSeconds,
        ),
        oneTimePreKeys = oneTimePreKeys.map {
            OneTimePreKey(
                id = it.id,
                publicKey = IdentityPrimitives.base64Url(it.publicKey),
                createdAtEpochSeconds = it.createdAtEpochSeconds,
            )
        },
    )

    private fun Int.requireAllocatable(): Int {
        if (this <= 0 || this == Int.MAX_VALUE) {
            throw IdentityStateException("Prekey id space is exhausted")
        }
        return this
    }

    companion object {
        const val DEFAULT_ONE_TIME_PREKEYS = 32
        private const val FIRST_PREKEY_ID = 1

        fun create(context: Context): LocalIdentityRepository = LocalIdentityRepository(
            keyBackend = AndroidIdentityKeyBackend(),
            stateStore = SharedPreferencesIdentityStateStore(context),
            clock = SystemIdentityClock,
        )
    }
}

internal fun interface IdentityClock {
    fun nowEpochSeconds(): Long
}

private object SystemIdentityClock : IdentityClock {
    override fun nowEpochSeconds(): Long = System.currentTimeMillis() / 1_000L
}
