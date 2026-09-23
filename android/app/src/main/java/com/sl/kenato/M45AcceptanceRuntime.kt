package com.sl.kenato

import android.content.Context
import com.sl.kenato.contact.ContactRepository
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

internal class M45AcceptanceRuntime(
    private val identity: M45IdentityBoundary,
    private val contacts: M45ContactBoundary,
    private val sessions: M45SessionBoundary,
    private val messaging: M45MessagingBoundary,
) : AutoCloseable {
    private var messagingStarted = false

    fun initializeIdentity(): IdentityBundle = identity.loadOrCreate()

    fun currentIdentity(): IdentityBundle? = identity.current()

    fun prepareForAcceptance() = withMessagingPaused {
        identity.loadOrCreate()
        contacts.publishIdentity()
        sessions.maintainBootstrap()
    }

    fun createInvite(): ShareableInvite = withMessagingPaused {
        identity.loadOrCreate()
        val invite = contacts.createInvite()
        sessions.maintainBootstrap()
        invite
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

    fun pendingInvites(): List<ShareableInvite> {
        identity.loadOrCreate()
        return contacts.pendingInvites()
    }

    fun contacts(): List<PinnedContact> {
        identity.loadOrCreate()
        return contacts.contacts()
    }

    fun startMessaging() {
        identity.loadOrCreate()
        messaging.start()
        messagingStarted = true
    }

    fun stopMessaging() {
        messagingStarted = false
        messaging.stop()
    }

    fun messagingState(): MessagingWssState = messaging.currentState()

    fun sendText(peerIdentityId: ByteArray, text: String): MessagingConversationMessage {
        val owner = currentIdentityId()
        return messaging.sendText(owner, peerIdentityId.copyOf(), text)
    }

    fun conversation(peerIdentityId: ByteArray): MessagingConversationState =
        messaging.conversation(currentIdentityId(), peerIdentityId.copyOf())

    override fun close() {
        messagingStarted = false
        messaging.stop()
        messaging.close()
    }

    private fun currentIdentityId(): ByteArray {
        val bundle = identity.current() ?: identity.loadOrCreate()
        return decodeM45IdentityId(bundle.identityId)
    }

    private inline fun <T> withMessagingPaused(block: () -> T): T {
        val restart = messagingStarted
        if (restart) {
            messagingStarted = false
            messaging.stop()
        }
        return try {
            block().also {
                if (restart) {
                    messaging.start()
                    messagingStarted = true
                }
            }
        } catch (error: Exception) {
            // A failed trust/session mutation leaves transport stopped. The user must explicitly
            // reconnect after inspecting/retrying the failed acceptance step.
            throw error
        }
    }

    companion object {
        fun create(context: Context, serviceOrigin: URI): M45AcceptanceRuntime {
            val appContext = context.applicationContext
            val identityRepository = LocalIdentityRepository.create(appContext)
            val contactRepository = ContactRepository.create(appContext, serviceOrigin)
            val sessionCoordinator = SessionCoordinator.create(appContext, serviceOrigin)
            val messagingBoundary = AndroidM45MessagingBoundary(appContext, serviceOrigin)

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
            )
        }
    }
}

private class AndroidM45MessagingBoundary(
    context: Context,
    serviceOrigin: URI,
) : M45MessagingBoundary {
    private val identityRepository = LocalIdentityRepository.create(context)
    private val sessionRepository = LocalSessionRepository.create(context)
    private val history = ConversationHistoryRepository(AtomicFileConversationHistoryStore(context))
    private val recovery = MessagingRecoveryCoordinator(
        sessions = LocalMessagingSessionHandoffRepository(sessionRepository),
        history = history,
    )
    private val scheduler = ExecutorMessagingRetryScheduler()
    private val wss = MessagingWssCoordinator(
        serviceOrigin = serviceOrigin,
        sockets = OkHttpMessagingSocketFactory(),
        identity = LocalMessagingIdentityAuthenticator(identityRepository),
        recovery = DurableMessagingRecoveryDriver(recovery),
        inbound = DurableMessagingInboundDeliveryHandler(
            sessions = LocalMessagingInboundSessionDriver(sessionRepository),
            history = history,
        ),
        scheduler = scheduler,
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
        wss.stop()
        scheduler.close()
    }
}
