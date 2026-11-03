package com.sl.kenato

import android.content.Context
import com.sl.kenato.contact.ContactRepository
import com.sl.kenato.diagnostics.M45DiagnosticJournal
import com.sl.kenato.contact.PinnedContact
import com.sl.kenato.contact.ShareableInvite
import com.sl.kenato.identity.IdentityBundle
import com.sl.kenato.identity.LocalIdentityRepository
import com.sl.kenato.messaging.AtomicFileConversationHistoryStore
import com.sl.kenato.messaging.ConversationHistoryRepository
import com.sl.kenato.messaging.CoordinatorMessagingOutboundRecovery
import com.sl.kenato.messaging.DurableMessagingConversationTextSender
import com.sl.kenato.messaging.DurableMessagingInboundDeliveryHandler
import com.sl.kenato.messaging.DurableMessagingOutboundSender
import com.sl.kenato.messaging.DurableMessagingRecoveryDriver
import com.sl.kenato.messaging.ExecutorMessagingRetryScheduler
import com.sl.kenato.messaging.LocalMessagingIdentityAuthenticator
import com.sl.kenato.messaging.LocalMessagingInboundSessionDriver
import com.sl.kenato.messaging.LocalMessagingOutboundSessionDriver
import com.sl.kenato.messaging.LocalMessagingSessionHandoffRepository
import com.sl.kenato.messaging.MESSAGING_IDENTITY_BYTES
import com.sl.kenato.messaging.MessagingConversationMessage
import com.sl.kenato.messaging.MessagingConversationService
import com.sl.kenato.messaging.MessagingConversationState
import com.sl.kenato.messaging.MessagingRecoveryCoordinator
import com.sl.kenato.messaging.MessagingWssCoordinator
import com.sl.kenato.messaging.MessagingWssState
import com.sl.kenato.messaging.SerializedMessagingRetryScheduler
import com.sl.kenato.messaging.SerializedMessagingSocketFactory
import com.sl.kenato.messaging.OkHttpMessagingSocketFactory
import com.sl.kenato.messaging.WssMessagingDurableWorkFlusher
import com.sl.kenato.messaging.WssMessagingOutboundAdmission
import com.sl.kenato.session.EstablishedSession
import com.sl.kenato.session.LocalSessionRepository
import com.sl.kenato.session.SessionCoordinator
import com.sl.kenato.storage.ProcessLocalOwnerRegistry
import java.net.URI
import java.util.Base64

internal object M45ServiceOrigin {
    fun parse(value: String): URI {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) {
            throw IllegalArgumentException("Service origin is required")
        }
        val parsed = try {
            URI(trimmed)
        } catch (error: Exception) {
            throw IllegalArgumentException("Service origin is not a valid URI", error)
        }
        if (
            parsed.scheme != "https" ||
            parsed.host.isNullOrBlank() ||
            parsed.rawUserInfo != null ||
            parsed.rawQuery != null ||
            parsed.rawFragment != null ||
            (parsed.rawPath.isNotEmpty() && parsed.rawPath != "/") ||
            (parsed.port != -1 && parsed.port !in 1..65535)
        ) {
            throw IllegalArgumentException("Service origin must be an HTTPS origin without path, query, fragment, or user info")
        }
        return URI(
            "https",
            null,
            parsed.host.lowercase(),
            parsed.port,
            "/",
            null,
            null,
        )
    }
}

internal fun decodeM45IdentityId(encoded: String): ByteArray {
    if (encoded.isEmpty() || '=' in encoded || !encoded.matches(Regex("^[A-Za-z0-9_-]+$"))) {
        throw IllegalArgumentException("Identity id encoding is invalid")
    }
    val decoded = try {
        Base64.getUrlDecoder().decode(encoded)
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException("Identity id encoding is invalid", error)
    }
    if (
        decoded.size != MESSAGING_IDENTITY_BYTES ||
        Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != encoded
    ) {
        throw IllegalArgumentException("Identity id encoding is invalid")
    }
    return decoded
}

internal interface M45IdentityBoundary {
    fun loadOrCreate(): IdentityBundle
    fun current(): IdentityBundle?
}

internal interface M45ContactBoundary {
    fun publishIdentity()
    fun createInvite(): ShareableInvite
    fun redeemInvite(uri: String): PinnedContact
    fun pendingInvites(): List<ShareableInvite>
    fun contacts(): List<PinnedContact>
}

internal interface M45SessionBoundary {
    fun maintainBootstrap()
    fun establishOutbound(inviteUri: String, localContactId: ByteArray): EstablishedSession
    fun claimInbound(inviteUri: String): EstablishedSession
}

internal interface M45MessagingBoundary : AutoCloseable {
    fun start()
    fun stop()
    fun currentState(): MessagingWssState
    fun sendText(ownerIdentityId: ByteArray, peerIdentityId: ByteArray, text: String): MessagingConversationMessage
    fun conversation(ownerIdentityId: ByteArray, peerIdentityId: ByteArray): MessagingConversationState
}

/** Process-only WSS ownership; not a durable M2/M3/effect transaction. */
internal class M45ProcessTransportGate {
    @Volatile var mutationEpoch: Long = 0L
        private set
    private var activeOwner: Any? = null
    private var poisoned = false

    fun requireAvailable(requester: Any) {
        if (poisoned) throw IllegalStateException("Process WSS safety state is uncertain")
        if (activeOwner != null && activeOwner !== requester) {
            throw IllegalStateException("Another acceptance runtime owns the process WSS transport")
        }
    }

    fun beginMutation(requester: Any) {
        requireAvailable(requester)
        if (mutationEpoch >= Long.MAX_VALUE - 2L) {
            throw IllegalStateException("Process trust mutation generation exhausted")
        }
        mutationEpoch++
    }

    fun endMutation() {
        mutationEpoch++
    }

    fun started(requester: Any) {
        requireAvailable(requester)
        activeOwner = requester
    }

    fun stopped(requester: Any) {
        if (activeOwner === requester) activeOwner = null
    }

    fun poison() {
        poisoned = true
    }
}

private val processTransportGates = ProcessLocalOwnerRegistry<M45ProcessTransportGate>()

private fun sharedM45ProcessGate(context: Context): M45ProcessTransportGate =
    processTransportGates.getOrCreate(context.applicationContext.noBackupFilesDir.canonicalPath) {
        M45ProcessTransportGate()
    }

/**
 * Standalone M1/voice-consent writes must serialize with Android WSS and invalidate any
 * start request that was queued before the write. Never allow a second writer while
 * another acceptance runtime owns a transport for this private directory.
 */
private object M45StandaloneTrustWriter

internal fun <T> M45ProcessTransportGate.withStandaloneTrustMutation(block: () -> T): T =
    synchronized(this) {
        beginMutation(M45StandaloneTrustWriter)
        try {
            block()
        } finally {
            endMutation()
        }
    }

internal fun <T> withM45StandaloneTrustMutation(context: Context, block: () -> T): T =
    sharedM45ProcessGate(context).withStandaloneTrustMutation(block)

internal class M45AcceptanceRuntime(
    private val identity: M45IdentityBoundary,
    private val contacts: M45ContactBoundary,
    private val sessions: M45SessionBoundary,
    private val messaging: M45MessagingBoundary,
    private val processGate: M45ProcessTransportGate = M45ProcessTransportGate(),
) : AutoCloseable {
    private var messagingStarted = false
    private var closed = false
    @Volatile private var trustMutationEpoch = 0L

    /**
     * Protect manual M1/voice-consent mutations from asynchronous M3/WSS callbacks.
     * Do not confuse process-only suspension with a durable cross-store commit.
     */
    @Synchronized
    fun <T> withLocalTrustMutation(block: () -> T): T = withMessagingPaused { block() }

    @Synchronized
    fun initializeIdentity(): IdentityBundle = synchronized(processGate) {
        requireOpen()
        processGate.requireAvailable(this)
        identity.loadOrCreate()
    }

    fun currentIdentity(): IdentityBundle? = identity.current()

    @Synchronized
    fun prepareForAcceptance() = withMessagingPaused {
        identity.loadOrCreate()
        contacts.publishIdentity()
        sessions.maintainBootstrap()
    }

    @Synchronized
    fun createInvite(): ShareableInvite = withMessagingPaused {
        identity.loadOrCreate()
        // Do not expose a shareable invite until the creator's authenticated M3 bootstrap is
        // available. Otherwise the redeemer could consume M2 state and then fail reservation.
        contacts.publishIdentity()
        sessions.maintainBootstrap()
        contacts.createInvite()
    }

    @Synchronized
    fun redeemAndEstablish(inviteUri: String): PinnedContact = withMessagingPaused {
        identity.loadOrCreate()
        val pin = contacts.redeemInvite(inviteUri)
        sessions.establishOutbound(inviteUri, pin.localId)
        pin
    }

    @Synchronized
    fun claimAndEstablish(inviteUri: String): EstablishedSession = withMessagingPaused {
        identity.loadOrCreate()
        sessions.claimInbound(inviteUri)
    }

    @Synchronized
    fun pendingInvites(): List<ShareableInvite> = synchronized(processGate) {
        requireOpen()
        processGate.requireAvailable(this)
        identity.loadOrCreate()
        contacts.pendingInvites()
    }

    @Synchronized
    fun contacts(): List<PinnedContact> = synchronized(processGate) {
        requireOpen()
        processGate.requireAvailable(this)
        identity.loadOrCreate()
        contacts.contacts()
    }

    fun startMessaging() {
        // Capture both generations before waiting for either runtime monitor.
        val requestedEpoch = trustMutationEpoch
        val requestedProcessEpoch = processGate.mutationEpoch
        synchronized(this) {
            synchronized(processGate) {
                requireOpen()
                if (requestedEpoch != trustMutationEpoch || requestedEpoch % 2L != 0L ||
                    requestedProcessEpoch != processGate.mutationEpoch ||
                    requestedProcessEpoch % 2L != 0L
                ) {
                    throw IllegalStateException("Transport start was superseded by a trust mutation")
                }
                processGate.requireAvailable(this)
                identity.loadOrCreate()
                startMessagingGuarded()
            }
        }
    }

    @Synchronized
    fun stopMessaging() = synchronized(processGate) {
        if (!closed) stopMessagingGuarded()
    }

    fun messagingState(): MessagingWssState = messaging.currentState()

    @Synchronized
    fun sendText(peerIdentityId: ByteArray, text: String): MessagingConversationMessage =
        sendTextSelectingPeer({ peerIdentityId }, text)

    /**
     * Resolve the current pinned M2 peer while holding the same process gate as M3 staging.
     * Pre-resolving from the controller would permit a stale contact during a trust mutation.
     */
    @Synchronized
    fun sendTextSelectingPeer(
        resolveCurrentPeer: () -> ByteArray,
        text: String,
    ): MessagingConversationMessage = synchronized(processGate) {
        requireOpen()
        processGate.requireAvailable(this)
        val peer = resolveCurrentPeer().copyOf()
        messaging.sendText(currentIdentityId(), peer, text)
    }

    @Synchronized
    fun conversation(peerIdentityId: ByteArray): MessagingConversationState =
        synchronized(processGate) {
            requireOpen()
            processGate.requireAvailable(this)
            messaging.conversation(currentIdentityId(), peerIdentityId.copyOf())
        }

    @Synchronized
    override fun close() {
        synchronized(processGate) {
            if (closed) return@synchronized
        closed = true
        messagingStarted = false
        var failure: Exception? = null
        try {
            messaging.stop()
        } catch (error: Exception) {
            failure = error
        }
        try {
            messaging.close()
        } catch (error: Exception) {
            if (failure == null) failure = error else failure.addSuppressed(error)
        }
        if (failure == null) processGate.stopped(this) else processGate.poison()
            failure?.let { throw it }
        }
    }

    private fun currentIdentityId(): ByteArray {
        val bundle = identity.current() ?: identity.loadOrCreate()
        return decodeM45IdentityId(bundle.identityId)
    }

    private fun requireOpen() {
        if (closed) throw IllegalStateException("Acceptance runtime is closed")
    }

    private inline fun <T> withMessagingPaused(block: () -> T): T = synchronized(processGate) {
        requireOpen()
        if (trustMutationEpoch >= Long.MAX_VALUE - 2L) {
            throw IllegalStateException("Trust mutation generation exhausted")
        }
        processGate.beginMutation(this)
        trustMutationEpoch++ // Odd: mutation in progress.
        try {
            val restart = messagingStarted
            if (restart) stopMessagingGuarded()
            block().also {
                if (restart) startMessagingGuarded()
            }
        } finally {
            trustMutationEpoch++ // Even: queued starts must validate generation.
            processGate.endMutation()
        }
    }

    /** Failed WSS starts can occur after a socket or scheduler was activated. */
    private fun startMessagingGuarded() {
        try {
            messaging.start()
            processGate.started(this)
            messagingStarted = true
        } catch (error: Exception) {
            messagingStarted = false
            try {
                messaging.stop()
            } catch (stopError: Exception) {
                error.addSuppressed(stopError)
                terminateTransportAfterFailedStop(error)
            }
            throw error
        }
    }

    /** Never execute a trust mutation if transport quiescence is uncertain. */
    private fun stopMessagingGuarded() {
        messagingStarted = false
        try {
            messaging.stop()
            processGate.stopped(this)
        } catch (error: Exception) {
            terminateTransportAfterFailedStop(error)
            throw error
        }
    }

    private fun terminateTransportAfterFailedStop(error: Exception) {
        closed = true
        processGate.poison()
        try {
            messaging.close()
        } catch (closeError: Exception) {
            error.addSuppressed(closeError)
        }
    }

    companion object {
        fun create(context: Context, serviceOrigin: URI): M45AcceptanceRuntime {
            val appContext = context.applicationContext
            val processGate = sharedM45ProcessGate(appContext)
            val identityRepository = LocalIdentityRepository.create(appContext)
            val contactRepository = ContactRepository.create(appContext, serviceOrigin)
            // M3 bootstrap and M4 messaging must not race through distinct repository locks.
            val sessionRepository = LocalSessionRepository.create(appContext)
            val sessionCoordinator = SessionCoordinator.create(appContext, serviceOrigin, sessionRepository)
            val messagingBoundary = AndroidM45MessagingBoundary(
                appContext, serviceOrigin, sessionRepository, processGate,
            )

            return M45AcceptanceRuntime(
                identity = object : M45IdentityBoundary {
                    override fun loadOrCreate(): IdentityBundle = identityRepository.loadOrCreate()
                    override fun current(): IdentityBundle? = identityRepository.current()
                },
                contacts = object : M45ContactBoundary {
                    override fun publishIdentity() {
                        contactRepository.publishIdentity()
                    }

                    override fun createInvite(): ShareableInvite = contactRepository.createInvite()

                    override fun redeemInvite(uri: String): PinnedContact = contactRepository.redeemInvite(uri)

                    override fun pendingInvites(): List<ShareableInvite> = contactRepository.pendingInvites()

                    override fun contacts(): List<PinnedContact> = contactRepository.contacts()
                },
                sessions = object : M45SessionBoundary {
                    override fun maintainBootstrap() {
                        sessionCoordinator.maintainBootstrap()
                    }

                    override fun establishOutbound(
                        inviteUri: String,
                        localContactId: ByteArray,
                    ): EstablishedSession = sessionCoordinator.establishOutbound(inviteUri, localContactId)

                    override fun claimInbound(inviteUri: String): EstablishedSession =
                        sessionCoordinator.claimInbound(inviteUri)
                },
                messaging = messagingBoundary,
                processGate = processGate,
            )
        }
    }
}

private class AndroidM45MessagingBoundary(
    context: Context,
    serviceOrigin: URI,
    private val sessionRepository: LocalSessionRepository,
    processGate: M45ProcessTransportGate,
) : M45MessagingBoundary {
    private val identityRepository = LocalIdentityRepository.create(context)
    private val diagnosticJournal = M45DiagnosticJournal(context)
    private val history = ConversationHistoryRepository(AtomicFileConversationHistoryStore(context))
    private val recovery = MessagingRecoveryCoordinator(
        sessions = LocalMessagingSessionHandoffRepository(sessionRepository),
        history = history,
    )
    private val scheduler = ExecutorMessagingRetryScheduler()
    private val gatedScheduler = SerializedMessagingRetryScheduler(scheduler, processGate)
    private val wss = MessagingWssCoordinator(
        serviceOrigin = serviceOrigin,
        sockets = SerializedMessagingSocketFactory(OkHttpMessagingSocketFactory(), processGate),
        identity = LocalMessagingIdentityAuthenticator(identityRepository),
        recovery = DurableMessagingRecoveryDriver(recovery),
        inbound = DurableMessagingInboundDeliveryHandler(
            sessions = LocalMessagingInboundSessionDriver(sessionRepository),
            history = history,
        ),
        scheduler = gatedScheduler,
        diagnostics = diagnosticJournal::record,
    )
    private val outbound = DurableMessagingOutboundSender(
        sessions = LocalMessagingOutboundSessionDriver(sessionRepository),
        history = history,
        recovery = CoordinatorMessagingOutboundRecovery(recovery),
        admission = WssMessagingOutboundAdmission(wss, recovery),
    )
    private val conversations = MessagingConversationService(
        outbound = DurableMessagingConversationTextSender(outbound),
        history = history,
        durableWork = WssMessagingDurableWorkFlusher(wss),
    )

    override fun start() = wss.start()

    override fun stop() = wss.stop()

    override fun currentState(): MessagingWssState = wss.currentState()

    override fun sendText(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
        text: String,
    ): MessagingConversationMessage = conversations.sendText(ownerIdentityId, peerIdentityId, text)

    override fun conversation(
        ownerIdentityId: ByteArray,
        peerIdentityId: ByteArray,
    ): MessagingConversationState = conversations.conversation(ownerIdentityId, peerIdentityId)

    override fun close() {
        var failure: Throwable? = null
        try {
            wss.stop()
        } catch (error: Throwable) {
            failure = error
        }
        try {
            scheduler.close()
        } catch (error: Throwable) {
            val prior = failure
            if (prior == null) failure = error else prior.addSuppressed(error)
        }
        failure?.let { throw it }
    }
}
