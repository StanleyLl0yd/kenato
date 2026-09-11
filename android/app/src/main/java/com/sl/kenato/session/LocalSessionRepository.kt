package com.sl.kenato.session

import android.content.Context
import java.security.MessageDigest

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

    /**
     * Reserves the next monotonic publication revision before exposing a signed payload candidate.
     * A crash after this commit can skip a revision on retry, but can never reuse a committed
     * revision for different account material. Returns null when native state has no unpublished
     * one-time keys, so callers never need to classify repository state by exception text.
     */
    @Synchronized
    fun prepareBootstrapPublicationOrNull(ownerIdentityId: ByteArray): SessionBootstrapBundle? {
        val state = requireState(ownerIdentityId)
        val native = inspectNativeAccount(state)
        if (native.unpublishedOneTimeKeys.isEmpty()) {
            return null
        }
        if (state.account.oneTimeKeys.size !in 1..SESSION_MAX_ONE_TIME_KEYS) {
            throw SessionStateException("Tracked M3 one-time-key count cannot be published")
        }
        for (unpublished in native.unpublishedOneTimeKeys) {
            if (state.account.oneTimeKeys.none { it.publicKey.contentEquals(unpublished) }) {
                throw SessionStateException("Native unpublished M3 key is missing from local bookkeeping")
            }
        }
        if (state.account.publicationRevision == Long.MAX_VALUE) {
            throw SessionStateException("M3 publication revision space is exhausted")
        }
        val revision = state.account.publicationRevision + 1
        val bundle = SessionBootstrapBundle(
            identityId = state.ownerIdentityId.copyOf(),
            accountGeneration = state.account.accountGeneration,
            publicationRevision = revision,
            olmEd25519IdentityKey = state.account.olmEd25519IdentityKey.copyOf(),
            olmCurve25519IdentityKey = state.account.olmCurve25519IdentityKey.copyOf(),
            oneTimePreKeys = state.account.oneTimeKeys
                .sortedBy { it.id }
                .map { SessionOneTimePreKey(it.id, it.publicKey.copyOf()) },
            bindingSignature = ByteArray(0),
        )
        SessionCanonical.validateBootstrap(bundle, requireSignature = false)
        persist(state.copy(account = state.account.copy(publicationRevision = revision)))
        return bundle
    }

    /**
     * Completes a server-accepted publication by advancing the local account snapshot. The
     * advanced snapshot is persisted before the caller may treat the publication as complete.
     */
    @Synchronized
    fun completeBootstrapPublication(
        ownerIdentityId: ByteArray,
        acceptedAccountGeneration: Long,
        acceptedPublicationRevision: Long,
    ) {
        val state = requireState(ownerIdentityId)
        if (
            acceptedAccountGeneration != state.account.accountGeneration ||
            acceptedPublicationRevision != state.account.publicationRevision
        ) {
            throw SessionStateException("Server accepted unexpected M3 publication provenance")
        }
        val account = unwrapAccount(state)
        val advanced = try {
            engine.markAccountKeysPublished(account)
        } finally {
            account.pickleKey.zeroize()
        }
        val wrapped = wrapAccountSnapshot(
            state.ownerIdentityId,
            state.account.accountGeneration,
            advanced,
        )
        persist(state.copy(account = state.account.copy(snapshot = wrapped)))
    }

    /**
     * Replenishes the locally retained OTK set up to [targetCount]. A new batch is generated only
     * after the previous native unpublished batch has been committed as published.
     */
    @Synchronized
    fun replenishOneTimeKeys(
        ownerIdentityId: ByteArray,
        targetCount: Int = TARGET_ONE_TIME_KEYS,
    ): SessionAccountState {
        if (targetCount !in 1..SESSION_MAX_ONE_TIME_KEYS) {
            throw SessionStateException("M3 one-time-key replenishment target is invalid")
        }
        val state = requireState(ownerIdentityId)
        val inspected = inspectNativeAccount(state)
        if (inspected.unpublishedOneTimeKeys.isNotEmpty()) {
            throw SessionStateException("Existing M3 one-time keys must be published before replenishment")
        }
        val needed = targetCount - state.account.oneTimeKeys.size
        if (needed <= 0) return state.account.copyForCaller()
        if (state.account.oneTimeKeys.size + needed > SESSION_MAX_ONE_TIME_KEYS) {
            throw SessionStateException("M3 one-time-key publication bound would be exceeded")
        }
        if (state.account.nextOneTimeKeyId > Long.MAX_VALUE - needed.toLong()) {
            throw SessionStateException("M3 one-time-key id space is exhausted")
        }

        val account = unwrapAccount(state)
        val mutation = try {
            engine.generateAccountOneTimeKeys(account, needed)
        } finally {
            account.pickleKey.zeroize()
        }
        if (mutation.publicState.unpublishedOneTimeKeys.size != needed) {
            mutation.snapshot.pickleKey.zeroize()
            throw SessionStateException("Native M3 replenishment returned an unexpected key count")
        }
        val fresh = mutation.publicState.unpublishedOneTimeKeys.mapIndexed { index, key ->
            TrackedSessionOneTimeKey(
                state.account.nextOneTimeKeyId + index.toLong(),
                key.copyOf(),
            )
        }
        val allKeys = state.account.oneTimeKeys + fresh
        if (mutation.publicState.storedOneTimeKeyCount != allKeys.size) {
            mutation.snapshot.pickleKey.zeroize()
            throw SessionStateException("Native M3 retained key count does not match replenished bookkeeping")
        }
        val wrapped = wrapAccountSnapshot(
            state.ownerIdentityId,
            state.account.accountGeneration,
            mutation.snapshot,
        )
        val updated = state.account.copy(
            nextOneTimeKeyId = state.account.nextOneTimeKeyId + needed.toLong(),
            oneTimeKeys = allKeys,
            snapshot = wrapped,
        )
        persist(state.copy(account = updated))
        return updated.copyForCaller()
    }

    @Synchronized
    fun createOutboundSession(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        peerIdentityId: ByteArray,
        peerAccountGeneration: Long,
        peerOlmEd25519IdentityKey: ByteArray,
        peerOlmCurve25519IdentityKey: ByteArray,
        creatorOneTimePreKeyId: Long,
        peerOneTimeKey: ByteArray,
        inviteToken: ByteArray,
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
        if (creatorOneTimePreKeyId <= 0) {
            throw SessionStateException("Creator session one-time-key id is invalid")
        }
        if (inviteToken.size != SESSION_INVITE_TOKEN_BYTES) {
            throw SessionStateException("M3 invite token size is invalid")
        }
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
            pendingInit = PendingSessionInit(
                inviteTokenHash = MessageDigest.getInstance("SHA-256").digest(inviteToken),
                creatorAccountGeneration = peerAccountGeneration,
                creatorOneTimePreKeyId = creatorOneTimePreKeyId,
                redeemerAccountGeneration = state.account.accountGeneration,
                messageType = result.initialMessage.messageType,
                olmMessage = result.initialMessage.ciphertext.copyOf(),
            ),
        )
        persist(state.copy(sessions = state.sessions + persisted))
        return result.initialMessage.copyForCaller()
    }

    @Synchronized
    fun pendingOutboundInit(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        inviteToken: ByteArray,
        creatorAccountGeneration: Long,
        creatorOneTimePreKeyId: Long,
    ): NativeSessionMessage? {
        if (inviteToken.size != SESSION_INVITE_TOKEN_BYTES) {
            throw SessionStateException("M3 invite token size is invalid")
        }
        val state = requireState(ownerIdentityId)
        val session = state.sessions[requireSessionIndex(state, localContactId)]
        if (!session.initiator) {
            throw SessionStateException("Existing M3 session is not the deterministic invite initiator")
        }
        val pending = session.pendingInit ?: return null
        requirePendingInitContext(
            pending,
            inviteToken,
            creatorAccountGeneration,
            creatorOneTimePreKeyId,
            state.account.accountGeneration,
        )
        return NativeSessionMessage(pending.messageType, pending.olmMessage.copyOf())
    }

    @Synchronized
    fun markOutboundInitSubmitted(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        inviteToken: ByteArray,
        creatorAccountGeneration: Long,
        creatorOneTimePreKeyId: Long,
    ) {
        if (inviteToken.size != SESSION_INVITE_TOKEN_BYTES) {
            throw SessionStateException("M3 invite token size is invalid")
        }
        val state = requireState(ownerIdentityId)
        val index = requireSessionIndex(state, localContactId)
        val session = state.sessions[index]
        if (!session.initiator || session.peerAccountGeneration != creatorAccountGeneration) {
            throw SessionStateException("M3 submitted-init session provenance is invalid")
        }
        val pending = session.pendingInit ?: return
        requirePendingInitContext(
            pending,
            inviteToken,
            creatorAccountGeneration,
            creatorOneTimePreKeyId,
            state.account.accountGeneration,
        )
        val sessions = state.sessions.toMutableList().also {
            it[index] = session.copy(pendingInit = null)
        }
        persist(state.copy(sessions = sessions))
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
        if (persisted.pendingInit != null) {
            throw SessionStateException("M3 application encryption is unavailable until session init submission completes")
        }
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
        if (persisted.pendingInit != null) {
            throw SessionStateException("M3 application decryption is unavailable until session init submission completes")
        }
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
            val nextId = FIRST_ONE_TIME_KEY_ID + keys.size.toLong()
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
        val public = inspectNativeAccount(state)
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

    private fun inspectNativeAccount(state: SessionState): NativeAccountPublicState {
        val native = unwrapAccount(state)
        return try {
            engine.inspectAccount(native)
        } finally {
            native.pickleKey.zeroize()
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

    private fun requirePendingInitContext(
        pending: PendingSessionInit,
        inviteToken: ByteArray,
        creatorAccountGeneration: Long,
        creatorOneTimePreKeyId: Long,
        redeemerAccountGeneration: Long,
    ) {
        val tokenHash = MessageDigest.getInstance("SHA-256").digest(inviteToken)
        if (
            !MessageDigest.isEqual(pending.inviteTokenHash, tokenHash) ||
            pending.creatorAccountGeneration != creatorAccountGeneration ||
            pending.creatorOneTimePreKeyId != creatorOneTimePreKeyId ||
            pending.redeemerAccountGeneration != redeemerAccountGeneration
        ) {
            throw SessionStateException("Pending M3 init does not match the authenticated invite reservation")
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
                pendingInit = session.pendingInit?.copy(
                    inviteTokenHash = session.pendingInit.inviteTokenHash.copyOf(),
                    olmMessage = session.pendingInit.olmMessage.copyOf(),
                ),
            )
        },
    )

    private fun NativeSessionMessage.copyForCaller(): NativeSessionMessage = copy(ciphertext = ciphertext.copyOf())

    companion object {
        private const val FIRST_ACCOUNT_GENERATION = 1L
        private const val FIRST_ONE_TIME_KEY_ID = 1L
        private const val TARGET_ONE_TIME_KEYS = 32

        fun create(context: Context): LocalSessionRepository = LocalSessionRepository(
            engine = JniSessionEngine(),
            keyBackend = AndroidSessionPickleKeyBackend(),
            stateStore = AtomicFileSessionStateStore(context),
        )
    }
}
