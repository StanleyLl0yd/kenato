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
import com.sl.kenato.messaging.OkHttpMessagingSocketFactory
import com.sl.kenato.messaging.WssMessagingDurableWorkFlusher
import com.sl.kenato.messaging.WssMessagingOutboundAdmission
import com.sl.kenato.messaging.SerializedMessagingRetryScheduler
import com.sl.kenato.messaging.SerializedMessagingSocketFactory
import com.sl.kenato.storage.ProcessLocalOwnerRegistry
import com.sl.kenato.session.EstablishedSession
import com.sl.kenato.session.LocalSessionRepository
import com.sl.kenato.session.SessionCoordinator
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

/**
 * Stop and release are independent teardown obligations. Always attempt both
 * and preserve distinct failures. This is not proof of native socket shutdown.
 */
internal fun closeM45Resources(stop: () -> Unit, release: () -> Unit) {
    var failure: Throwable? = null
    try {
        stop()
    } catch (error: Throwable) {
        failure = error
    }
    try {
        release()
    } catch (error: Throwable) {
        val prior = failure
        if (prior == null) failure = error else if (prior !== error) prior.addSuppressed(error)
    }
    failure?.let { throw it }
}

private val processTransportGates = ProcessLocalOwnerRegistry<M45ProcessTransportGate>()

internal class M45AcceptanceRuntime(
    private val identity: M45IdentityBoundary,
    private val contacts: M45ContactBoundary,
    private val sessions: M45SessionBoundary,
    private val messaging: M45MessagingBoundary,
    private val processGate: M45ProcessTransportGate = M45ProcessTransportGate(),
    private val ownerToken: Any = Any(),
) : AutoCloseable {
    private var messagingStarted = false
    private var closed = false
    private var uncertainShutdown = false

    fun initializeIdentity(): IdentityBundle = withOwner { identity.loadOrCreate() }

    fun currentIdentity(): IdentityBundle? = withOwner { identity.current() }

    fun prepareForAcceptance() = withMessagingPaused {
        identity.loadOrCreate()
        contacts.publishIdentity()
        sessions.maintainBootstrap()
    }

    fun createInvite(): ShareableInvite = withMessagingPaused {
        identity.loadOrCreate()
        // Do not expose a shareable invite until the creator's authenticated M3 bootstrap is
        // available. Otherwise the redeemer could consume M2 state and then fail reservation.
        contacts.publishIdentity()
        sessions.maintainBootstrap()
        contacts.createInvite()
    }

    fun redeemAndEstablish(inviteUri: String): PinnedContact = withMessagingPaused {
        identity.loadOrCreate()
        val pin = contacts.redeemInvite(inviteUri)
        sessions.establishOutbound(inviteUri, pin.localId)
        pin
    }

    fun claimAndEstablish(inviteUri: String): EstablishedSession = withMessagingPaused {
        identity.loadOrCreate()
        sessions.claimInbound(inviteUri)
    }

    fun pendingInvites(): List<ShareableInvite> = withOwner {
        identity.loadOrCreate()
        contacts.pendingInvites()
    }

    fun contacts(): List<PinnedContact> = withOwner {
        identity.loadOrCreate()
        contacts.contacts()
    }

    fun startMessaging() {
        // Capture before waiting on the process owner. A queued start must not
        // resurrect transport after an intervening or failed trust mutation.
        val requestedEpoch = processGate.mutationEpoch
        withOwner {
            check(requestedEpoch == processGate.mutationEpoch && requestedEpoch % 2L == 0L) {
                "Transport start was superseded by a trust mutation"
            }
            identity.loadOrCreate()
            startMessagingGuarded()
        }
    }

    fun stopMessaging() = synchronized(processGate) {
        check(!uncertainShutdown) { "Acceptance runtime shutdown is uncertain" }
        if (!closed) stopMessagingGuarded()
    }

    fun messagingState(): MessagingWssState = synchronized(processGate) {
        if (uncertainShutdown || processGate.isPoisoned()) MessagingWssState.FAILED
        else messaging.currentState()
    }

    fun sendText(peerIdentityId: ByteArray, text: String): MessagingConversationMessage = withOwner {
        val owner = currentIdentityId()
        messaging.sendText(owner, peerIdentityId.copyOf(), text)
    }

    fun conversation(peerIdentityId: ByteArray): MessagingConversationState = withOwner {
        messaging.conversation(currentIdentityId(), peerIdentityId.copyOf())
    }

    override fun close() = synchronized(processGate) {
        if (closed) return@synchronized
        closed = true
        messagingStarted = false
        processGate.suspendCallbacks(ownerToken)
        try {
            closeM45Resources(messaging::stop, messaging::close)
            processGate.release(ownerToken)
        } catch (error: Throwable) {
            uncertainShutdown = true
            processGate.poison()
            throw error
        }
    }

    private fun currentIdentityId(): ByteArray {
        val bundle = identity.current() ?: identity.loadOrCreate()
        return decodeM45IdentityId(bundle.identityId)
    }

    private inline fun <T> withOwner(block: () -> T): T = synchronized(processGate) {
        check(!closed) { "Acceptance runtime is closed" }
        processGate.requireAvailable(ownerToken)
        block()
    }

    private inline fun <T> withMessagingPaused(block: () -> T): T = withOwner {
        processGate.beginMutation(ownerToken)
        try {
            val restart = messagingStarted
            if (restart) stopMessagingGuarded()
            // A failed mutation leaves transport stopped; only a fresh start may resume it.
            block().also { if (restart) startMessagingGuarded() }
        } finally {
            processGate.endMutation()
        }
    }

    private fun startMessagingGuarded() {
        // Claim before invoking an external start; synchronous callbacks already
        // need the current owner. Partial starts must be stopped on failure.
        processGate.claim(ownerToken)
        try {
            messaging.start()
            messagingStarted = true
        } catch (error: Throwable) {
            messagingStarted = false
            try {
                stopMessagingGuarded()
            } catch (stopError: Throwable) {
                if (error !== stopError) error.addSuppressed(stopError)
            }
            throw error
        }
    }

    private fun stopMessagingGuarded() {
        messagingStarted = false
        processGate.suspendCallbacks(ownerToken)
        try {
            messaging.stop()
            processGate.release(ownerToken)
        } catch (error: Throwable) {
            // Keep the process poisoned even if best-effort resource release succeeds.
            // A new Activity or service origin cannot prove the old native socket closed.
            closed = true
            uncertainShutdown = true
            processGate.poison()
            try {
                messaging.close()
            } catch (closeError: Throwable) {
                if (error !== closeError) error.addSuppressed(closeError)
            }
            throw error
        }
    }

    companion object {
        fun create(context: Context, serviceOrigin: URI): M45AcceptanceRuntime {
            val appContext = context.applicationContext
            val processGate = processTransportGates.getOrCreate(appContext.noBackupFilesDir.canonicalPath) {
                M45ProcessTransportGate()
            }
            val ownerToken = Any()
            val identityRepository = LocalIdentityRepository.create(appContext)
            val contactRepository = ContactRepository.create(appContext, serviceOrigin)
            // Bootstrap and WSS must share the exact same M3 repository and monitor.
            val sessionRepository = LocalSessionRepository.create(appContext)
            val sessionCoordinator = SessionCoordinator.create(appContext, serviceOrigin, sessionRepository)
            val messagingBoundary = AndroidM45MessagingBoundary(
                appContext, serviceOrigin, sessionRepository, processGate, ownerToken,
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
                ownerToken = ownerToken,
            )
        }
    }
}

private class AndroidM45MessagingBoundary(
    context: Context,
    serviceOrigin: URI,
    private val sessionRepository: LocalSessionRepository,
    processGate: M45ProcessTransportGate,
    ownerToken: Any,
) : M45MessagingBoundary {
    private val identityRepository = LocalIdentityRepository.create(context)
    private val diagnosticJournal = M45DiagnosticJournal(context)
    private val history = ConversationHistoryRepository(AtomicFileConversationHistoryStore(context))
    private val recovery = MessagingRecoveryCoordinator(
        sessions = LocalMessagingSessionHandoffRepository(sessionRepository),
        history = history,
    )
    private val scheduler = ExecutorMessagingRetryScheduler()
    private val gatedScheduler = SerializedMessagingRetryScheduler(scheduler, processGate) {
        processGate.captureCallbackPermission(ownerToken)
    }
    private val wss = MessagingWssCoordinator(
        serviceOrigin = serviceOrigin,
        sockets = SerializedMessagingSocketFactory(OkHttpMessagingSocketFactory(), processGate) {
            processGate.captureCallbackPermission(ownerToken)
        },
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
        closeM45Resources(wss::stop, scheduler::close)
    }
}
