package com.sl.kenato.session

import android.content.Context
import android.os.Looper
import com.sl.kenato.contact.ContactCrypto
import com.sl.kenato.contact.ContactIdentityConflictException
import com.sl.kenato.contact.ContactIdentityProvider
import com.sl.kenato.contact.ContactLocalState
import com.sl.kenato.contact.HttpContactTransport
import com.sl.kenato.contact.InviteUriCodec
import com.sl.kenato.contact.LocalContactIdentityProvider
import com.sl.kenato.contact.M2InviteDescriptor
import com.sl.kenato.contact.PinnedContact
import com.sl.kenato.contact.SharedPreferencesContactStateStore
import com.sl.kenato.contact.toUnsignedContactBundle
import com.sl.kenato.identity.LocalIdentityRepository
import java.net.URI
import java.time.Instant

internal data class SessionIdentityMaterial(
    val identityId: ByteArray,
    val identityPublicKey: ByteArray,
)

internal data class SessionPinnedContact(
    val localId: ByteArray,
    val identityId: ByteArray,
    val identityPublicKey: ByteArray,
)

internal enum class SessionBootstrapRole {
    INITIATOR,
    RESPONDER,
}

internal data class EstablishedSession(
    val localContactId: ByteArray,
    val peerIdentityId: ByteArray,
    val localAccountGeneration: Long,
    val peerAccountGeneration: Long,
    val role: SessionBootstrapRole,
)

internal class SessionOperationCancelledException : IllegalStateException("M3 session operation was cancelled")

internal fun interface SessionCancellation {
    fun isCancelled(): Boolean
}

internal fun interface SessionThreadGuard {
    fun requireWorkerThread()
}

internal fun interface SessionClock {
    fun nowEpochSeconds(): Long
}

internal interface SessionIdentityBoundary {
    fun current(): SessionIdentityMaterial

    fun sign(payload: ByteArray): ByteArray
}

internal interface SessionContactBoundary {
    fun requirePinnedContact(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        expectedPeerIdentityId: ByteArray,
    ): SessionPinnedContact

    fun requirePendingInvite(
        ownerIdentityId: ByteArray,
        invite: M2InviteDescriptor,
        nowEpochSeconds: Long,
    )

    fun commitClaimedContact(
        ownerIdentityId: ByteArray,
        inviteToken: ByteArray,
        peerIdentityId: ByteArray,
        peerIdentityPublicKey: ByteArray,
        pinnedAtEpochSeconds: Long,
    ): SessionPinnedContact
}

internal interface SessionLocalBoundary {
    fun loadOrCreateAccount(ownerIdentityId: ByteArray): SessionAccountState

    fun currentState(ownerIdentityId: ByteArray): SessionState?

    fun prepareBootstrapPublicationOrNull(ownerIdentityId: ByteArray): SessionBootstrapBundle?

    fun completeBootstrapPublication(
        ownerIdentityId: ByteArray,
        acceptedAccountGeneration: Long,
        acceptedPublicationRevision: Long,
    )

    fun replenishOneTimeKeys(ownerIdentityId: ByteArray): SessionAccountState

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
    ): NativeSessionMessage

    fun pendingOutboundInit(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        inviteToken: ByteArray,
        creatorAccountGeneration: Long,
        creatorOneTimePreKeyId: Long,
    ): NativeSessionMessage?

    fun markOutboundInitSubmitted(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        inviteToken: ByteArray,
        creatorAccountGeneration: Long,
        creatorOneTimePreKeyId: Long,
    )

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
    ): ByteArray
}

/**
 * Executes the M3 invite-bound bootstrap synchronously. The caller must use a worker thread.
 * Cancellation is honored only at recovery-safe boundaries: after a destructive creator claim
 * returns, the verified M2 pin and inbound Olm state are committed without another cancellation
 * checkpoint.
 */
internal class SessionCoordinator(
    private val identity: SessionIdentityBoundary,
    private val contacts: SessionContactBoundary,
    private val sessions: SessionLocalBoundary,
    private val transport: SessionTransport,
    private val threadGuard: SessionThreadGuard,
    private val clock: SessionClock,
) {
    @Synchronized
    fun maintainBootstrap(
        cancellation: SessionCancellation = NEVER_CANCELLED,
    ): SessionAccountState {
        requireExecution(cancellation)
        val local = currentIdentity()
        return ensureLocalBootstrap(local, cancellation)
    }

    /**
     * Runs the deterministic M3 redeemer/initiator flow for an invite already redeemed and pinned
     * by M2. A persisted pending pre-key frame is always reused verbatim after cancellation or
     * process restart; native outbound-session creation is never repeated for that pending frame.
     */
    @Synchronized
    fun establishOutbound(
        inviteUri: String,
        localContactId: ByteArray,
        cancellation: SessionCancellation = NEVER_CANCELLED,
    ): EstablishedSession {
        requireExecution(cancellation)
        val invite = InviteUriCodec.decode(inviteUri)
        val local = currentIdentity()
        if (invite.creatorIdentityId.contentEquals(local.identityId)) {
            throw SessionStateException("M3 redeemer cannot establish a session with the local identity")
        }
        val pin = contacts.requirePinnedContact(local.identityId, localContactId, invite.creatorIdentityId)
        ContactCrypto.verifyInvite(invite, pin.identityPublicKey)

        sessions.loadOrCreateAccount(local.identityId)
        val existingState = requireLocalState(local.identityId)
        val existing = findSession(existingState, localContactId)
        if (existing != null) {
            requireSessionMatchesPin(existing, pin, initiator = true)
            if (existing.pendingInit == null) {
                return established(existingState, existing, SessionBootstrapRole.INITIATOR)
            }
            checkCancelled(cancellation)
            return resumeOutbound(local, pin, invite, existingState, existing, cancellation)
        }

        val localAccount = ensureLocalBootstrap(local, cancellation)
        checkCancelled(cancellation)
        val reserveSignature = signBounded(
            SessionCanonical.reservePayload(invite.creatorIdentityId, local.identityId, invite.token),
            "M3 session reservation",
        )
        SessionCrypto.verifyReserveProof(
            creatorIdentityId = invite.creatorIdentityId,
            redeemerIdentityId = local.identityId,
            inviteToken = invite.token,
            signature = reserveSignature,
            redeemerPinnedIdentityPublicKey = local.identityPublicKey,
        )
        checkCancelled(cancellation)
        val reserved = transport.reserveBootstrap(
            creatorIdentityId = invite.creatorIdentityId,
            redeemerIdentityId = local.identityId,
            inviteToken = invite.token,
            reserveSignature = reserveSignature,
        )
        SessionCrypto.verifyBootstrapBundle(
            bundle = reserved.creatorBundle,
            expectedIdentityId = pin.identityId,
            pinnedIdentityPublicKey = pin.identityPublicKey,
        )
        requireReservedKey(reserved)

        val current = requireLocalState(local.identityId)
        if (current.account.accountGeneration != localAccount.accountGeneration) {
            throw SessionStateException("Local M3 account generation changed during reservation")
        }
        val control = SessionCanonical.initControlPayload(
            creatorIdentityId = pin.identityId,
            redeemerIdentityId = local.identityId,
            inviteToken = invite.token,
            creatorAccountGeneration = reserved.creatorBundle.accountGeneration,
            creatorOneTimePreKeyId = reserved.creatorOneTimePreKey.id,
            redeemerAccountGeneration = current.account.accountGeneration,
        )
        val frame = sessions.createOutboundSession(
            ownerIdentityId = local.identityId,
            localContactId = pin.localId,
            peerIdentityId = pin.identityId,
            peerAccountGeneration = reserved.creatorBundle.accountGeneration,
            peerOlmEd25519IdentityKey = reserved.creatorBundle.olmEd25519IdentityKey,
            peerOlmCurve25519IdentityKey = reserved.creatorBundle.olmCurve25519IdentityKey,
            creatorOneTimePreKeyId = reserved.creatorOneTimePreKey.id,
            peerOneTimeKey = reserved.creatorOneTimePreKey.publicKey,
            inviteToken = invite.token,
            initialPlaintext = control,
        )
        checkCancelled(cancellation)
        submitAndCommitOutbound(
            local = local,
            pin = pin,
            invite = invite,
            creatorAccountGeneration = reserved.creatorBundle.accountGeneration,
            creatorOneTimePreKeyId = reserved.creatorOneTimePreKey.id,
            redeemerAccountGeneration = current.account.accountGeneration,
            frame = frame,
            cancellation = cancellation,
        )
        val committed = requireLocalState(local.identityId)
        val session = requireSession(committed, pin.localId)
        requireSessionMatchesPin(session, pin, initiator = true)
        if (session.pendingInit != null) {
            throw SessionStateException("M3 outbound init remained pending after successful submission")
        }
        return established(committed, session, SessionBootstrapRole.INITIATOR)
    }

    /**
     * Runs the deterministic invite-creator/responder flow. M3 claim is destructive on the server,
     * matching ADR 0010, so cancellation is checked immediately before claim and then deferred
     * until the verified M2 contact pin and inbound Olm state have been durably committed.
     */
    @Synchronized
    fun claimInbound(
        inviteUri: String,
        cancellation: SessionCancellation = NEVER_CANCELLED,
    ): EstablishedSession {
        requireExecution(cancellation)
        val invite = InviteUriCodec.decode(inviteUri)
        val local = currentIdentity()
        if (!invite.creatorIdentityId.contentEquals(local.identityId)) {
            throw ContactIdentityConflictException("M3 claim invite does not belong to the local identity")
        }
        ContactCrypto.verifyInvite(invite, local.identityPublicKey)
        val now = nowEpochSeconds()
        contacts.requirePendingInvite(local.identityId, invite, now)
        val localAccount = ensureLocalBootstrap(local, cancellation)

        val claimSignature = signBounded(
            SessionCanonical.claimPayload(local.identityId, invite.token),
            "M3 session claim",
        )
        SessionCrypto.verifyClaimProof(
            creatorIdentityId = local.identityId,
            inviteToken = invite.token,
            signature = claimSignature,
            creatorPinnedIdentityPublicKey = local.identityPublicKey,
        )
        checkCancelled(cancellation)
        val claimed = transport.claimInit(local.identityId, invite.token, claimSignature)

        val redeemer = claimed.redeemerIdentityBundle
        if (redeemer.identityId.contentEquals(local.identityId)) {
            throw SessionStateException("M3 claim resolved to the local identity")
        }
        ContactCrypto.verifyRedemption(
            creatorIdentityId = local.identityId,
            redeemer = redeemer,
            token = invite.token,
            signature = claimed.redemptionSignature,
        )
        SessionCrypto.verifyBootstrapBundle(
            bundle = claimed.redeemerSessionBundle,
            expectedIdentityId = redeemer.identityId,
            pinnedIdentityPublicKey = redeemer.identityPublicKey,
        )
        if (claimed.redeemerSessionBundle.accountGeneration <= 0) {
            throw SessionStateException("Claimed redeemer M3 generation is invalid")
        }
        val submit = SessionSubmitInit(
            creatorIdentityId = local.identityId.copyOf(),
            redeemerIdentityId = redeemer.identityId.copyOf(),
            inviteToken = invite.token.copyOf(),
            creatorAccountGeneration = claimed.creatorAccountGeneration,
            creatorOneTimePreKeyId = claimed.creatorOneTimePreKey.id,
            redeemerAccountGeneration = claimed.redeemerSessionBundle.accountGeneration,
            olmMessageType = claimed.olmMessageType,
            olmMessage = claimed.olmMessage.copyOf(),
            submitSignature = claimed.submitSignature.copyOf(),
        )
        SessionCrypto.verifySubmitProof(submit, redeemer.identityPublicKey)

        val current = requireLocalState(local.identityId)
        if (
            current.account.accountGeneration != localAccount.accountGeneration ||
            current.account.accountGeneration != claimed.creatorAccountGeneration
        ) {
            throw SessionStateException("Claimed creator M3 generation does not match local state")
        }
        val localOneTimeKey = current.account.oneTimeKeys.singleOrNull {
            it.id == claimed.creatorOneTimePreKey.id
        } ?: throw SessionStateException("Claimed creator M3 one-time key is unavailable locally")
        if (!localOneTimeKey.publicKey.contentEquals(claimed.creatorOneTimePreKey.publicKey)) {
            throw SessionStateException("Claimed creator M3 one-time key was substituted")
        }
        val expectedControl = SessionCanonical.initControlPayload(
            creatorIdentityId = local.identityId,
            redeemerIdentityId = redeemer.identityId,
            inviteToken = invite.token,
            creatorAccountGeneration = claimed.creatorAccountGeneration,
            creatorOneTimePreKeyId = claimed.creatorOneTimePreKey.id,
            redeemerAccountGeneration = claimed.redeemerSessionBundle.accountGeneration,
        )

        var committedPlaintext: ByteArray? = null
        try {
            // These stores cannot be committed transactionally. Commit the authenticated M2 pin
            // first: if that write fails, M3 remains untouched. If the following M3 atomic write
            // fails, the valid pin remains but the local OTK/session snapshot stays unchanged; the
            // destructive server claim cannot be replayed and recovery requires a fresh invite.
            // Reversing this order could leave an M3 session without its durable M2 trust anchor.
            val pin = contacts.commitClaimedContact(
                ownerIdentityId = local.identityId,
                inviteToken = invite.token,
                peerIdentityId = redeemer.identityId,
                peerIdentityPublicKey = redeemer.identityPublicKey,
                pinnedAtEpochSeconds = nowEpochSeconds(),
            )
            val plaintext = sessions.createInboundSession(
                ownerIdentityId = local.identityId,
                localContactId = pin.localId,
                peerIdentityId = pin.identityId,
                peerAccountGeneration = claimed.redeemerSessionBundle.accountGeneration,
                peerOlmEd25519IdentityKey = claimed.redeemerSessionBundle.olmEd25519IdentityKey,
                peerOlmCurve25519IdentityKey = claimed.redeemerSessionBundle.olmCurve25519IdentityKey,
                consumedOneTimeKeyId = claimed.creatorOneTimePreKey.id,
                expectedInitialPlaintext = expectedControl,
                messageType = claimed.olmMessageType,
                olmMessage = claimed.olmMessage,
            )
            committedPlaintext = plaintext
            if (!plaintext.contentEquals(expectedControl)) {
                throw SessionStateException("Committed M3 inbound control plaintext changed unexpectedly")
            }

            val committed = requireLocalState(local.identityId)
            val session = requireSession(committed, pin.localId)
            requireSessionMatchesPin(session, pin, initiator = false)
            return established(committed, session, SessionBootstrapRole.RESPONDER)
        } finally {
            committedPlaintext?.zeroize()
            expectedControl.zeroize()
        }
    }

    private fun resumeOutbound(
        local: SessionIdentityMaterial,
        pin: SessionPinnedContact,
        invite: M2InviteDescriptor,
        state: SessionState,
        session: PersistedSession,
        cancellation: SessionCancellation,
    ): EstablishedSession {
        val pending = session.pendingInit
            ?: return established(state, session, SessionBootstrapRole.INITIATOR)
        if (pending.redeemerAccountGeneration != state.account.accountGeneration) {
            throw SessionStateException("Pending M3 outbound init belongs to a different local account generation")
        }
        val frame = sessions.pendingOutboundInit(
            ownerIdentityId = local.identityId,
            localContactId = pin.localId,
            inviteToken = invite.token,
            creatorAccountGeneration = pending.creatorAccountGeneration,
            creatorOneTimePreKeyId = pending.creatorOneTimePreKeyId,
        ) ?: throw SessionStateException("Persisted M3 outbound init disappeared during recovery")
        submitAndCommitOutbound(
            local = local,
            pin = pin,
            invite = invite,
            creatorAccountGeneration = pending.creatorAccountGeneration,
            creatorOneTimePreKeyId = pending.creatorOneTimePreKeyId,
            redeemerAccountGeneration = pending.redeemerAccountGeneration,
            frame = frame,
            cancellation = cancellation,
        )
        val committed = requireLocalState(local.identityId)
        val recovered = requireSession(committed, pin.localId)
        requireSessionMatchesPin(recovered, pin, initiator = true)
        if (recovered.pendingInit != null) {
            throw SessionStateException("Recovered M3 outbound init remained pending after submission")
        }
        return established(committed, recovered, SessionBootstrapRole.INITIATOR)
    }

    private fun submitAndCommitOutbound(
        local: SessionIdentityMaterial,
        pin: SessionPinnedContact,
        invite: M2InviteDescriptor,
        creatorAccountGeneration: Long,
        creatorOneTimePreKeyId: Long,
        redeemerAccountGeneration: Long,
        frame: NativeSessionMessage,
        cancellation: SessionCancellation,
    ) {
        val unsigned = SessionSubmitInit(
            creatorIdentityId = pin.identityId.copyOf(),
            redeemerIdentityId = local.identityId.copyOf(),
            inviteToken = invite.token.copyOf(),
            creatorAccountGeneration = creatorAccountGeneration,
            creatorOneTimePreKeyId = creatorOneTimePreKeyId,
            redeemerAccountGeneration = redeemerAccountGeneration,
            olmMessageType = frame.messageType,
            olmMessage = frame.ciphertext.copyOf(),
            submitSignature = ByteArray(0),
        )
        SessionCanonical.validateSubmit(unsigned, requireSignature = false)
        val signed = unsigned.copy(
            submitSignature = signBounded(
                SessionCanonical.submitPayload(unsigned),
                "M3 session init submission",
            ),
        )
        SessionCrypto.verifySubmitProof(signed, local.identityPublicKey)
        checkCancelled(cancellation)
        transport.submitInit(signed)
        // Do not honor cancellation between a successful/idempotent server submit and the local
        // durable pending-clear. A process crash still leaves the exact frame for retry.
        sessions.markOutboundInitSubmitted(
            ownerIdentityId = local.identityId,
            localContactId = pin.localId,
            inviteToken = invite.token,
            creatorAccountGeneration = creatorAccountGeneration,
            creatorOneTimePreKeyId = creatorOneTimePreKeyId,
        )
    }

    private fun ensureLocalBootstrap(
        local: SessionIdentityMaterial,
        cancellation: SessionCancellation,
    ): SessionAccountState {
        sessions.loadOrCreateAccount(local.identityId)
        publishPendingBootstrap(local, cancellation)
        val before = requireLocalState(local.identityId).account.oneTimeKeys.size
        val replenished = sessions.replenishOneTimeKeys(local.identityId)
        if (replenished.oneTimeKeys.size > before) {
            publishPendingBootstrap(local, cancellation)
        }
        return requireLocalState(local.identityId).account
    }

    private fun publishPendingBootstrap(
        local: SessionIdentityMaterial,
        cancellation: SessionCancellation,
    ) {
        val unsigned = sessions.prepareBootstrapPublicationOrNull(local.identityId) ?: return
        val signed = unsigned.copy(
            bindingSignature = signBounded(
                SessionCanonical.bootstrapPayload(unsigned),
                "M3 session bootstrap",
            ),
        )
        SessionCrypto.verifyBootstrapBundle(signed, local.identityId, local.identityPublicKey)
        checkCancelled(cancellation)
        val accepted = transport.publishBootstrap(signed)
        if (
            accepted.acceptedAccountGeneration != signed.accountGeneration ||
            accepted.acceptedPublicationRevision != signed.publicationRevision
        ) {
            throw SessionStateException("Server accepted unexpected M3 bootstrap provenance")
        }
        sessions.completeBootstrapPublication(
            ownerIdentityId = local.identityId,
            acceptedAccountGeneration = accepted.acceptedAccountGeneration,
            acceptedPublicationRevision = accepted.acceptedPublicationRevision,
        )
    }

    private fun requireReservedKey(reserved: SessionReserveWireResponse) {
        val matches = reserved.creatorBundle.oneTimePreKeys.filter {
            it.id == reserved.creatorOneTimePreKey.id
        }
        if (
            matches.size != 1 ||
            !matches.single().publicKey.contentEquals(reserved.creatorOneTimePreKey.publicKey)
        ) {
            throw SessionStateException("Reserved creator M3 one-time key is not bound to the verified bundle")
        }
    }

    private fun requireSessionMatchesPin(
        session: PersistedSession,
        pin: SessionPinnedContact,
        initiator: Boolean,
    ) {
        if (
            session.initiator != initiator ||
            !session.localContactId.contentEquals(pin.localId) ||
            !session.peerIdentityId.contentEquals(pin.identityId)
        ) {
            throw SessionStateException("Persisted M3 session conflicts with the pinned contact or deterministic role")
        }
    }

    private fun established(
        state: SessionState,
        session: PersistedSession,
        role: SessionBootstrapRole,
    ): EstablishedSession = EstablishedSession(
        localContactId = session.localContactId.copyOf(),
        peerIdentityId = session.peerIdentityId.copyOf(),
        localAccountGeneration = state.account.accountGeneration,
        peerAccountGeneration = session.peerAccountGeneration,
        role = role,
    )

    private fun findSession(state: SessionState, localContactId: ByteArray): PersistedSession? {
        if (localContactId.size != SessionStateCodec.LOCAL_CONTACT_ID_BYTES) {
            throw SessionStateException("Local contact id size is invalid")
        }
        val matches = state.sessions.filter { it.localContactId.contentEquals(localContactId) }
        if (matches.size > 1) {
            throw SessionStateException("Persisted M3 state contains duplicate sessions for one contact")
        }
        return matches.singleOrNull()
    }

    private fun requireSession(state: SessionState, localContactId: ByteArray): PersistedSession =
        findSession(state, localContactId)
            ?: throw SessionStateException("Expected persisted M3 session is unavailable")

    private fun requireLocalState(ownerIdentityId: ByteArray): SessionState =
        sessions.currentState(ownerIdentityId)
            ?: throw SessionStateException("M3 local session state is unavailable")

    private fun currentIdentity(): SessionIdentityMaterial = identity.current().also { local ->
        if (local.identityId.size != SESSION_IDENTITY_BYTES) {
            throw SessionStateException("Local M3 identity id size is invalid")
        }
        val derived = ContactCrypto.identityId(local.identityPublicKey)
        if (!derived.contentEquals(local.identityId)) {
            throw SessionStateException("Local M3 identity id does not match its P-256 public key")
        }
    }

    private fun signBounded(payload: ByteArray, operation: String): ByteArray = identity.sign(payload).also {
        if (it.isEmpty() || it.size > SESSION_MAX_SIGNATURE_BYTES) {
            throw SessionStateException("$operation signature size is invalid")
        }
    }

    private fun nowEpochSeconds(): Long = clock.nowEpochSeconds().also {
        if (it < 0) throw SessionStateException("M3 session clock returned an invalid timestamp")
    }

    private fun requireExecution(cancellation: SessionCancellation) {
        threadGuard.requireWorkerThread()
        checkCancelled(cancellation)
    }

    private fun checkCancelled(cancellation: SessionCancellation) {
        if (cancellation.isCancelled()) throw SessionOperationCancelledException()
    }

    companion object {
        private val NEVER_CANCELLED = SessionCancellation { false }

        fun create(context: Context, serviceOrigin: URI): SessionCoordinator {
            val identityProvider = LocalContactIdentityProvider(LocalIdentityRepository.create(context))
            return SessionCoordinator(
                identity = ContactSessionIdentityBoundary(identityProvider),
                contacts = LocalSessionContactBoundary(
                    ContactLocalState(SharedPreferencesContactStateStore(context)),
                ),
                sessions = LocalSessionBoundary(LocalSessionRepository.create(context)),
                transport = HttpSessionTransport(serviceOrigin),
                threadGuard = AndroidSessionThreadGuard,
                clock = SystemSessionClock,
            )
        }
    }
}

private class ContactSessionIdentityBoundary(
    private val delegate: ContactIdentityProvider,
) : SessionIdentityBoundary {
    override fun current(): SessionIdentityMaterial {
        val bundle = delegate.currentIdentity().toUnsignedContactBundle(1)
        return SessionIdentityMaterial(bundle.identityId.copyOf(), bundle.identityPublicKey.copyOf())
    }

    override fun sign(payload: ByteArray): ByteArray = delegate.sign(payload)
}

private class LocalSessionContactBoundary(
    private val state: ContactLocalState,
) : SessionContactBoundary {
    override fun requirePinnedContact(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        expectedPeerIdentityId: ByteArray,
    ): SessionPinnedContact {
        val matches = state.contacts(ownerIdentityId).filter { it.localId.contentEquals(localContactId) }
        if (matches.size != 1) {
            throw ContactIdentityConflictException("Local M2 contact binding is unavailable or ambiguous")
        }
        val pin = matches.single()
        if (!pin.identityId.contentEquals(expectedPeerIdentityId)) {
            throw ContactIdentityConflictException("M3 invite creator does not match the pinned M2 contact")
        }
        return pin.toSessionPin()
    }

    override fun requirePendingInvite(
        ownerIdentityId: ByteArray,
        invite: M2InviteDescriptor,
        nowEpochSeconds: Long,
    ) {
        val matches = state.pendingInvites(ownerIdentityId, nowEpochSeconds).filter {
            it.token.contentEquals(invite.token)
        }
        if (matches.size != 1) {
            throw SessionStateException("Pending M2 invite is unavailable or expired for M3 claim")
        }
        val pending = matches.single()
        if (
            !pending.creatorIdentityId.contentEquals(invite.creatorIdentityId) ||
            !pending.signature.contentEquals(invite.signature)
        ) {
            throw ContactIdentityConflictException("Pending M2 invite changed before M3 claim")
        }
    }

    override fun commitClaimedContact(
        ownerIdentityId: ByteArray,
        inviteToken: ByteArray,
        peerIdentityId: ByteArray,
        peerIdentityPublicKey: ByteArray,
        pinnedAtEpochSeconds: Long,
    ): SessionPinnedContact = state.commitClaimedIdentity(
        ownerIdentityId = ownerIdentityId,
        token = inviteToken,
        identityId = peerIdentityId,
        identityPublicKey = peerIdentityPublicKey,
        pinnedAtEpochSeconds = pinnedAtEpochSeconds,
    ).toSessionPin()

    private fun PinnedContact.toSessionPin(): SessionPinnedContact = SessionPinnedContact(
        localId = localId.copyOf(),
        identityId = identityId.copyOf(),
        identityPublicKey = identityPublicKey.copyOf(),
    )
}

private class LocalSessionBoundary(
    private val repository: LocalSessionRepository,
) : SessionLocalBoundary {
    override fun loadOrCreateAccount(ownerIdentityId: ByteArray): SessionAccountState =
        repository.loadOrCreateAccount(ownerIdentityId)

    override fun currentState(ownerIdentityId: ByteArray): SessionState? = repository.currentState(ownerIdentityId)

    override fun prepareBootstrapPublicationOrNull(ownerIdentityId: ByteArray): SessionBootstrapBundle? =
        repository.prepareBootstrapPublicationOrNull(ownerIdentityId)

    override fun completeBootstrapPublication(
        ownerIdentityId: ByteArray,
        acceptedAccountGeneration: Long,
        acceptedPublicationRevision: Long,
    ) = repository.completeBootstrapPublication(
        ownerIdentityId,
        acceptedAccountGeneration,
        acceptedPublicationRevision,
    )

    override fun replenishOneTimeKeys(ownerIdentityId: ByteArray): SessionAccountState =
        repository.replenishOneTimeKeys(ownerIdentityId)

    override fun createOutboundSession(
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
    ): NativeSessionMessage = repository.createOutboundSession(
        ownerIdentityId,
        localContactId,
        peerIdentityId,
        peerAccountGeneration,
        peerOlmEd25519IdentityKey,
        peerOlmCurve25519IdentityKey,
        creatorOneTimePreKeyId,
        peerOneTimeKey,
        inviteToken,
        initialPlaintext,
    )

    override fun pendingOutboundInit(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        inviteToken: ByteArray,
        creatorAccountGeneration: Long,
        creatorOneTimePreKeyId: Long,
    ): NativeSessionMessage? = repository.pendingOutboundInit(
        ownerIdentityId,
        localContactId,
        inviteToken,
        creatorAccountGeneration,
        creatorOneTimePreKeyId,
    )

    override fun markOutboundInitSubmitted(
        ownerIdentityId: ByteArray,
        localContactId: ByteArray,
        inviteToken: ByteArray,
        creatorAccountGeneration: Long,
        creatorOneTimePreKeyId: Long,
    ) = repository.markOutboundInitSubmitted(
        ownerIdentityId,
        localContactId,
        inviteToken,
        creatorAccountGeneration,
        creatorOneTimePreKeyId,
    )

    override fun createInboundSession(
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
    ): ByteArray = repository.createInboundSession(
        ownerIdentityId,
        localContactId,
        peerIdentityId,
        peerAccountGeneration,
        peerOlmEd25519IdentityKey,
        peerOlmCurve25519IdentityKey,
        consumedOneTimeKeyId,
        expectedInitialPlaintext,
        messageType,
        olmMessage,
    )
}

private object AndroidSessionThreadGuard : SessionThreadGuard {
    override fun requireWorkerThread() {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw SessionStateException("M3 session bootstrap must not run on the Android main thread")
        }
    }
}

private object SystemSessionClock : SessionClock {
    override fun nowEpochSeconds(): Long = Instant.now().epochSecond
}
