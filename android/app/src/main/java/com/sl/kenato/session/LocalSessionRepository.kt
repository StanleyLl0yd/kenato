package com.sl.kenato.session

import android.content.Context

/**
 * Owns the M3 local Olm account/session lifecycle. All methods are synchronous and must be
 * invoked off the UI thread. Native state transitions are not externally visible until the
 * corresponding advanced snapshot is durably committed.
 */
internal class LocalSessionRepository(
    private val engine: SessionEngine,
    private val keyBackend: SessionPickleKeyBackend,
    private val stateStore: SessionStateStore,
) {
    @Synchronized
    fun loadOrCreateAccount(ownerIdentityId: ByteArray): SessionAccountState {
        requireIdentityId(ownerIdentityId, "owner identity id")
        val existing = loadValidatedStateOrNull(ownerIdentityId)
        return if (existing != null) {
            existing.account.copyForCaller()
        } else {
            createAccount(ownerIdentityId).account.copyForCaller()
        }
    }

    @Synchronized
    fun currentState(ownerIdentityId: ByteArray): SessionState? {
        requireIdentityId(ownerIdentityId, "owner identity id")
        return loadValidatedStateOrNull(ownerIdentityId)?.copyForCaller()
    }

    @Synchronized
    fun createOutboundSession(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
        peerAccountGeneration: Long,
        peerOlmEd25519IdentityKey: ByteArray,
        peerOlmCurve25519IdentityKey: ByteArray,
        peerOneTimeKey: ByteArray,
        initialPlaintext: ByteArray,
    ): NativeSessionMessage {
        validatePeerContext(
            ownerIdentityId,
            localContactId,
            peerIdentityId,
            peerAccountGeneration,
            peerOlmEd25519IdentityKey,
            peerOlmCurve25519IdentityKey,
        )
        requireOlmKey(peerOneTimeKey, "peer one-time key")
        val state = requireState(ownerIdentityId)
        requireNoActiveSession(state, localContactId, peerIdentityId)

        val account = unwrapAccount(state)
        val result = try {
            engine.createOutboundSession(
                account,
                peerOlmCurve25519IdentityKey,
                peerOneTimeKey,
                initialPlaintext,
            )
        } finally {
            account.pickleKey.zeroize()
        }

        val wrappedSession = wrapSessionSnapshot(
            ownerIdentityId = state.ownerIdentityId,
            localAccountGeneration = state.account.accountGeneration,
            localContactId = localContactId,
            peerIdentityId = peerIdentityId,
            peerAccountGeneration = peerAccountGeneration,
            sessionId = result.sessionId,
            snapshot = result.snapshot,
        )
        val persisted = PersistedSession(
            localContactId = localContactId.copyOf(),
            peerIdentityId = peerIdentityId.copyOf(),
            peerAccountGeneration = peerAccountGeneration,
            peerOlmEd25519IdentityKey = peerOlmEd25519IdentityKey.copyOf(),
            peerOlmCurve25519IdentityKey = peerOlmCurve25519IdentityKey.copyOf(),
            sessionId = result.sessionId,
            initiator = true,
            snapshot = wrappedSession,
        )
        persist(state.copy(sessions = state.sessions + persisted))
        return result.initialMessage.copyForCaller()
    }

    @Synchronized
    fun createInboundSession(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
        peerAccountGeneration: Long,
        peerOlmEd25519IdentityKey: ByteArray,
        peerOlmCurve25519IdentityKey: ByteArray,
        consumedOneTimeKeyId: Long,
        expectedInitialPlaintext: ByteArray,
        messageType: Int,
        olmMessage: ByteArray,
    ): ByteArray {
        validatePeerContext(
            ownerIdentityId,
            localContactId,
            peerIdentityId,
            peerAccountGeneration,
            peerOlmEd25519IdentityKey,
            peerOlmCurve25519IdentityKey,
        )
        if (consumedOneTimeKeyId <= 0) {
            throw SessionStateException("Consumed session one-time-key id is invalid")
        }
        val state = requireState(ownerIdentityId)
        requireNoActiveSession(state, localContactId, peerIdentityId)
        val consumed = state.account.oneTimeKeys.singleOrNull { it.id == consumedOneTimeKeyId }
            ?: throw SessionStateException("Expected local session one-time key is unavailable")

        val account = unwrapAccount(state)
        val result = try {
            engine.createInboundSession(
                account,
                peerOlmCurve25519IdentityKey,
                messageType,
                olmMessage,
            )
        } finally {
            account.pickleKey.zeroize()
        }
        if (!result.plaintext.contentEquals(expectedInitialPlaintext)) {
            result.accountSnapshot.pickleKey.zeroize()
            result.sessionSnapshot.pickleKey.zeroize()
            result.plaintext.zeroize()
            throw SessionStateException("Authenticated M3 session-init control plaintext does not match the expected context")
        }

        val wrappedAccount = wrapAccountSnapshot(
            state.ownerIdentityId,
            state.account.accountGeneration,
            result.accountSnapshot,
        )
        val wrappedSession = wrapSessionSnapshot(
            ownerIdentityId = state.ownerIdentityId,
            localAccountGeneration = state.account.accountGeneration,
            localContactId = localContactId,
            peerIdentityId = peerIdentityId,
            peerAccountGeneration = peerAccountGeneration,
            sessionId = result.sessionId,
            snapshot = result.sessionSnapshot,
        )
        val updatedAccount = state.account.copy(
            oneTimeKeys = state.account.oneTimeKeys.filterNot { it.id == consumed.id },
            snapshot = wrappedAccount,
        )
        val persisted = PersistedSession(
            localContactId = localContactId.copyOf(),
            peerIdentityId = peerIdentityId.copyOf(),
            peerAccountGeneration = peerAccountGeneration,
            peerOlmEd25519IdentityKey = peerOlmEd25519IdentityKey.copyOf(),
            peerOlmCurve25519IdentityKey = peerOlmCurve25519IdentityKey.copyOf(),
            sessionId = result.sessionId,
            initiator = false,
            snapshot = wrappedSession,
        )
        persist(state.copy(account = updatedAccount, sessions = state.sessions + persisted))
        return result.plaintext.copyOf().also { result.plaintext.zeroize() }
    }

    @Synchronized
    fun encrypt(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        plaintext: ByteArray,
    ): NativeSessionMessage {
        val state = requireState(ownerIdentityId)
        val index = requireSessionIndex(state, localContactId)
        val persisted = state.sessions[index]
        val native = unwrapSession(state, persisted)
        val result = try {
            engine.encryptSession(native, plaintext)
        } finally {
            native.pickleKey.zeroize()
        }
        val wrapped = wrapSessionSnapshot(
            ownerIdentityId = state.ownerIdentityId,
            localAccountGeneration = state.account.accountGeneration,
            localContactId = persisted.localContactId,
            peerIdentityId = persisted.peerIdentityId,
            peerAccountGeneration = persisted.peerAccountGeneration,
            sessionId = persisted.sessionId,
            snapshot = result.snapshot,
        )
        val sessions = state.sessions.toMutableList().also {
            it[index] = persisted.copy(snapshot = wrapped)
        }
        persist(state.copy(sessions = sessions))
        return result.message.copyForCaller()
    }

    @Synchronized
    fun decrypt(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        messageType: Int,
        olmMessage: ByteArray,
    ): ByteArray {
        val state = requireState(ownerIdentityId)
        val index = requireSessionIndex(state, localContactId)
        val persisted = state.sessions[index]
        val native = unwrapSession(state, persisted)
        val result = try {
            engine.decryptSession(native, messageType, olmMessage)
        } finally {
            native.pickleKey.zeroize()
        }
        val wrapped = wrapSessionSnapshot(
            ownerIdentityId = state.ownerIdentityId,
            localAccountGeneration = state.account.accountGeneration,
            localContactId = persisted.localContactId,
            peerIdentityId = persisted.peerIdentityId,
            peerAccountGeneration = persisted.peerAccountGeneration,
            sessionId = persisted.sessionId,
            snapshot = result.snapshot,
        )
        val sessions = state.sessions.toMutableList().also {
            it[index] = persisted.copy(snapshot = wrapped)
        }
        persist(state.copy(sessions = sessions))
        return result.plaintext.copyOf().also { result.plaintext.zeroize() }
    }

    @Synchronized
    fun clearForExplicitRecovery() {
        if (!stateStore.clear()) {
            throw SessionStateException("Unable to clear persisted M3 session state")
        }
        keyBackend.deleteWrappingKey()
    }

    private fun createAccount(ownerIdentityId: ByteArray): SessionState {
        if (keyBackend.hasWrappingKey()) {
            throw SessionStateException(
                "Android Keystore M3 wrapping material exists without persisted state; explicit recovery is required",
            )
        }
        keyBackend.ensureWrappingKey()
        try {
            val mutation = engine.createAccount()
            val keys = mutation.publicState.unpublishedOneTimeKeys.mapIndexed { index, key ->
                TrackedSessionOneTimeKey(index.toLong() + FIRST_ONE_TIME_KEY_ID, key.copyOf())
            }
            val nextId = FIRST_ONE_TIME_KEY_ID + keys.size
            val state = SessionState(
                ownerIdentityId = ownerIdentityId.copyOf(),
                account = SessionAccountState(
                    accountGeneration = FIRST_ACCOUNT_GENERATION,
                    publicationRevision = 0,
                    nextOneTimeKeyId = nextId,
                    olmEd25519IdentityKey = mutation.publicState.olmEd25519IdentityKey.copyOf(),
                    olmCurve25519IdentityKey = mutation.publicState.olmCurve25519IdentityKey.copyOf(),
                    oneTimeKeys = keys,
                    snapshot = wrapAccountSnapshot(ownerIdentityId, FIRST_ACCOUNT_GENERATION, mutation.snapshot),
                ),
                sessions = emptyList(),
            )
            if (mutation.publicState.storedOneTimeKeyCount != keys.size) {
                throw SessionStateException("Fresh native account retained an unexpected one-time-key count")
            }
            persist(state)
            return state
        } catch (error: Exception) {
            runCatching { keyBackend.deleteWrappingKey() }.onFailure(error::addSuppressed)
            throw error
        }
    }

    private fun loadValidatedStateOrNull(ownerIdentityId: ByteArray): SessionState? {
        val encoded = stateStore.read()
        if (encoded == null) {
            if (keyBackend.hasWrappingKey()) {
                throw SessionStateException(
                    "Android Keystore M3 wrapping material exists without persisted state; explicit recovery is required",
                )
            }
            return null
        }
        if (!keyBackend.hasWrappingKey()) {
            throw SessionStateException(
                "Persisted M3 state exists but Android Keystore wrapping material is missing; refusing silent regeneration",
            )
        }
        val state = SessionStateCodec.decode(encoded)
        if (!state.ownerIdentityId.contentEquals(ownerIdentityId)) {
            throw SessionStateException("Persisted M3 state belongs to a different local identity")
        }
        validateNativeAccount(state)
        return state
    }

    private fun validateNativeAccount(state: SessionState) {
        val native = unwrapAccount(state)
        val public = try {
            engine.inspectAccount(native)
        } finally {
            native.pickleKey.zeroize()
        }
        if (
            !public.olmEd25519IdentityKey.contentEquals(state.account.olmEd25519IdentityKey) ||
            !public.olmCurve25519IdentityKey.contentEquals(state.account.olmCurve25519IdentityKey)
        ) {
            throw SessionStateException("Persisted M3 account identity keys do not match native state")
        }
        if (public.storedOneTimeKeyCount != state.account.oneTimeKeys.size) {
            throw SessionStateException("Persisted M3 one-time-key bookkeeping does not match native state")
        }
        for (unpublished in public.unpublishedOneTimeKeys) {
            if (state.account.oneTimeKeys.none { it.publicKey.contentEquals(unpublished) }) {
                throw SessionStateException("Native M3 account contains an untracked unpublished one-time key")
            }
        }
    }

    private fun requireState(ownerIdentityId: ByteArray): SessionState {
        requireIdentityId(ownerIdentityId, "owner identity id")
        return loadValidatedStateOrNull(ownerIdentityId)
            ?: throw SessionStateException("M3 session account has not been initialized")
    }

    private fun unwrapAccount(state: SessionState): NativeSessionSnapshot {
        val key = keyBackend.unwrap(
            state.account.snapshot.wrappedPickleKey,
            SessionKeyAad.account(state.ownerIdentityId, state.account.accountGeneration),
        )
        return NativeSessionSnapshot(state.account.snapshot.ciphertext.copyOf(), key)
    }

    private fun unwrapSession(state: SessionState, session: PersistedSession): NativeSessionSnapshot {
        val key = keyBackend.unwrap(
            session.snapshot.wrappedPickleKey,
            SessionKeyAad.session(
                state.ownerIdentityId,
                state.account.accountGeneration,
                session.localContactId,
                session.peerIdentityId,
                session.peerAccountGeneration,
                session.sessionId,
            ),
        )
        return NativeSessionSnapshot(session.snapshot.ciphertext.copyOf(), key)
    }

    private fun wrapAccountSnapshot(
        ownerIdentityId: ByteArray,
        accountGeneration: Long,
        snapshot: NativeSessionSnapshot,
    ): WrappedSessionSnapshot = try {
        WrappedSessionSnapshot(
            ciphertext = snapshot.ciphertext.copyOf(),
            wrappedPickleKey = keyBackend.wrap(
                snapshot.pickleKey,
                SessionKeyAad.account(ownerIdentityId, accountGeneration),
            ),
        )
    } finally {
        snapshot.pickleKey.zeroize()
    }

    private fun wrapSessionSnapshot(
        ownerIdentityId: ByteArray,
        localAccountGeneration: Long,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
        peerAccountGeneration: Long,
        sessionId: String,
        snapshot: NativeSessionSnapshot,
    ): WrappedSessionSnapshot = try {
        WrappedSessionSnapshot(
            ciphertext = snapshot.ciphertext.copyOf(),
            wrappedPickleKey = keyBackend.wrap(
                snapshot.pickleKey,
                SessionKeyAad.session(
                    ownerIdentityId,
                    localAccountGeneration,
                    localContactId,
                    peerIdentityId,
                    peerAccountGeneration,
                    sessionId,
                ),
            ),
        )
    } finally {
        snapshot.pickleKey.zeroize()
    }

    private fun persist(state: SessionState) {
        val encoded = SessionStateCodec.encode(state)
        if (!stateStore.write(encoded)) {
            throw SessionStateException("Unable to durably commit M3 session state")
        }
    }

    private fun requireNoActiveSession(
        state: SessionState,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
    ) {
        if (
            state.sessions.any {
                it.localContactId.contentEquals(localContactId) || it.peerIdentityId.contentEquals(peerIdentityId)
            }
        ) {
            throw SessionStateException("An active M3 session already exists for this pinned contact")
        }
    }

    private fun requireSessionIndex(state: SessionState, localContactId: ByteArray): Int {
        if (localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw SessionStateException("Local contact id size is invalid")
        }
        val matches = state.sessions.withIndex().filter { it.value.localContactId.contentEquals(localContactId) }
        if (matches.size != 1) {
            throw SessionStateException("Exactly one active M3 session is required for the pinned contact")
        }
        return matches.single().index
    }

    private fun validatePeerContext(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
        peerAccountGeneration: Long,
        peerOlmEd25519IdentityKey: ByteArray,
        peerOlmCurve25519IdentityKey: ByteArray,
    ) {
        requireIdentityId(ownerIdentityId, "owner identity id")
        requireIdentityId(peerIdentityId, "peer identity id")
        if (ownerIdentityId.contentEquals(peerIdentityId)) {
            throw SessionStateException("M3 peer cannot be the local identity")
        }
        if (localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw SessionStateException("Local contact id size is invalid")
        }
        if (peerAccountGeneration <= 0) {
            throw SessionStateException("Peer M3 account generation is invalid")
        }
        requireOlmKey(peerOlmEd25519IdentityKey, "peer Olm Ed25519 identity key")
        requireOlmKey(peerOlmCurve25519IdentityKey, "peer Olm Curve25519 identity key")
        if (peerOlmEd25519IdentityKey.contentEquals(peerOlmCurve25519IdentityKey)) {
            throw SessionStateException("Peer M3 identity keys must be distinct")
        }
    }

    private fun requireIdentityId(value: ByteArray, name: String) {
        if (value.size != SessionStateCodec.IDENTITY_ID_BYTES) {
            throw SessionStateException("$name size is invalid")
        }
    }

    private fun requireOlmKey(value: ByteArray, name: String) {
        if (value.size != SessionStateCodec.OLM_PUBLIC_KEY_BYTES) {
            throw SessionStateException("$name size is invalid")
        }
    }

    private fun SessionAccountState.copyForCaller(): SessionAccountState = copy(
        olmEd25519IdentityKey = olmEd25519IdentityKey.copyOf(),
        olmCurve25519IdentityKey = olmCurve25519IdentityKey.copyOf(),
        oneTimeKeys = oneTimeKeys.map { it.copy(publicKey = it.publicKey.copyOf()) },
        snapshot = snapshot.copy(
            ciphertext = snapshot.ciphertext.copyOf(),
            wrappedPickleKey = snapshot.wrappedPickleKey.copyOf(),
        ),
    )

    private fun SessionState.copyForCaller(): SessionState = copy(
        ownerIdentityId = ownerIdentityId.copyOf(),
        account = account.copyForCaller(),
        sessions = sessions.map { session ->
            session.copy(
                localContactId = session.localContactId.copyOf(),
                peerIdentityId = session.peerIdentityId.copyOf(),
                peerOlmEd25519IdentityKey = session.peerOlmEd25519IdentityKey.copyOf(),
                peerOlmCurve25519IdentityKey = session.peerOlmCurve25519IdentityKey.copyOf(),
                snapshot = session.snapshot.copy(
                    ciphertext = session.snapshot.ciphertext.copyOf(),
                    wrappedPickleKey = session.snapshot.wrappedPickleKey.copyOf(),
                ),
            )
        },
    )

    private fun NativeSessionMessage.copyForCaller(): NativeSessionMessage = copy(ciphertext = ciphertext.copyOf())

    companion object {
        private const val FIRST_ACCOUNT_GENERATION = 1L
        private const val FIRST_ONE_TIME_KEY_ID = 1L

        fun create(context: Context): LocalSessionRepository = LocalSessionRepository(
            engine = JniSessionEngine(),
            keyBackend = AndroidSessionPickleKeyBackend(),
            stateStore = AtomicFileSessionStateStore(context),
        )
    }
}
