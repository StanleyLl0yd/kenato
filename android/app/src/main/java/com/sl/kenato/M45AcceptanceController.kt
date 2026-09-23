package com.sl.kenato

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.sl.kenato.contact.ContactLocalState
import com.sl.kenato.contact.InviteUriCodec
import com.sl.kenato.contact.M2InviteDescriptor
import com.sl.kenato.contact.SharedPreferencesContactStateStore
import com.sl.kenato.identity.LocalIdentityRepository
import com.sl.kenato.messaging.MessagingConversationDirection
import com.sl.kenato.messaging.MessagingConversationDeliveryState
import com.sl.kenato.messaging.MessagingWssState
import java.time.Instant
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

internal data class M45UiContact(
    val localId: String,
    val peerIdentityId: String,
)

internal data class M45UiMessage(
    val messageId: String,
    val direction: MessagingConversationDirection,
    val deliveryState: MessagingConversationDeliveryState,
    val sentAtEpochSeconds: Long,
    val text: String,
)

internal data class M45AcceptanceUiState(
    val serviceOrigin: String = "",
    val identityId: String? = null,
    val pendingInvites: List<String> = emptyList(),
    val contacts: List<M45UiContact> = emptyList(),
    val selectedPeerIdentityId: String? = null,
    val messagingEnabled: Boolean = false,
    val messagingState: MessagingWssState = MessagingWssState.STOPPED,
    val messages: List<M45UiMessage> = emptyList(),
    val busy: Boolean = false,
    val notice: String? = null,
    val error: String? = null,
)

internal class M45AcceptanceController(context: Context) : AutoCloseable {
    private val appContext = context.applicationContext
    private val identityRepository = LocalIdentityRepository.create(appContext)
    private val contactState = ContactLocalState(SharedPreferencesContactStateStore(appContext))
    private val preferences = appContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    private val worker = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "kenato-m45-acceptance").apply { isDaemon = true }
    }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val silentRefreshInFlight = AtomicBoolean(false)

    private var foreground = false
    private var runtime: M45AcceptanceRuntime? = null
    private var runtimeOrigin: String? = null

    var state by mutableStateOf(
        M45AcceptanceUiState(
            serviceOrigin = preferences.getString(KEY_SERVICE_ORIGIN, "").orEmpty(),
            messagingEnabled = preferences.getBoolean(KEY_MESSAGING_ENABLED, false),
        ),
    )
        private set

    private val pollRunnable = object : Runnable {
        override fun run() {
            if (!foreground) return
            refreshSilently()
            mainHandler.postDelayed(this, POLL_INTERVAL_MILLIS)
        }
    }

    init {
        refreshSilently()
    }

    fun onAppForeground() {
        foreground = true
        mainHandler.removeCallbacks(pollRunnable)
        worker.execute {
            try {
                if (
                    preferences.getBoolean(KEY_MESSAGING_ENABLED, false) &&
                    preferences.getString(KEY_SERVICE_ORIGIN, "").orEmpty().isNotBlank() &&
                    identityRepository.current() != null
                ) {
                    requireRuntime().startMessaging()
                }
                val snapshot = buildSnapshot()
                mainHandler.post { applySnapshot(snapshot) }
            } catch (error: Exception) {
                mainHandler.post {
                    state = state.copy(error = userError(error))
                }
            }
        }
        mainHandler.postDelayed(pollRunnable, POLL_INTERVAL_MILLIS)
    }

    fun onAppBackground() {
        foreground = false
        mainHandler.removeCallbacks(pollRunnable)
        worker.execute {
            runCatching { runtime?.stopMessaging() }
        }
    }

    fun saveServiceOrigin(value: String) = launchOperation("Service origin saved") {
        val normalized = M45ServiceOrigin.parse(value).toString()
        runtime?.close()
        runtime = null
        runtimeOrigin = null
        if (!preferences.edit().putString(KEY_SERVICE_ORIGIN, normalized).commit()) {
            throw IllegalStateException("Unable to persist service origin")
        }
        if (
            foreground &&
            preferences.getBoolean(KEY_MESSAGING_ENABLED, false) &&
            identityRepository.current() != null
        ) {
            requireRuntime().startMessaging()
        }
    }

    fun initializeIdentity() = launchOperation("Local identity is ready") {
        identityRepository.loadOrCreate()
    }

    fun prepareForAcceptance() = launchOperation("Identity and M3 bootstrap are published") {
        requireRuntime().prepareForAcceptance()
    }

    fun createInvite() = launchOperation("Invite created and creator bootstrap is ready") {
        requireRuntime().createInvite()
    }

    fun redeemAndEstablish(inviteUri: String) = launchOperation("Invite redeemed and outbound M3 session established") {
        if (inviteUri.isBlank()) throw IllegalArgumentException("Invite URI is required")
        requireRuntime().redeemAndEstablish(inviteUri.trim())
    }

    fun claimAndEstablish(inviteUri: String) = launchOperation("Inbound M3 session and contact are established") {
        if (inviteUri.isBlank()) throw IllegalArgumentException("Invite URI is required")
        requireRuntime().claimAndEstablish(inviteUri.trim())
    }

    fun selectContact(peerIdentityId: String) = launchOperation("Contact selected") {
        val owner = requireOwnerIdentityId()
        val peer = decodeM45IdentityId(peerIdentityId)
        val exists = contactState.contacts(owner).any { it.identityId.contentEquals(peer) }
        if (!exists) throw IllegalArgumentException("Selected contact is not pinned locally")
        if (!preferences.edit().putString(KEY_SELECTED_PEER, peerIdentityId).commit()) {
            throw IllegalStateException("Unable to persist selected contact")
        }
    }

    fun startMessaging() = launchOperation("Messaging transport started") {
        requireRuntime().startMessaging()
        if (!preferences.edit().putBoolean(KEY_MESSAGING_ENABLED, true).commit()) {
            requireRuntime().stopMessaging()
            throw IllegalStateException("Unable to persist messaging state")
        }
    }

    fun stopMessaging() = launchOperation("Messaging transport stopped") {
        runtime?.stopMessaging()
        if (!preferences.edit().putBoolean(KEY_MESSAGING_ENABLED, false).commit()) {
            throw IllegalStateException("Unable to persist messaging state")
        }
    }

    fun sendText(text: String) = launchOperation("Message staged for durable delivery") {
        val peer = selectedPeerBytes()
        requireRuntime().sendText(peer, text)
    }

    fun refresh() = launchOperation("State refreshed") { }

    override fun close() {
        foreground = false
        mainHandler.removeCallbacks(pollRunnable)
        worker.execute {
            runCatching { runtime?.close() }
            runtime = null
        }
        worker.shutdown()
    }

    private fun launchOperation(notice: String, operation: () -> Unit) {
        if (state.busy) return
        state = state.copy(busy = true, notice = null, error = null)
        worker.execute {
            try {
                operation()
                val snapshot = buildSnapshot()
                mainHandler.post {
                    applySnapshot(snapshot, notice = notice)
                }
            } catch (error: Exception) {
                val snapshot = runCatching { buildSnapshot() }.getOrNull()
                mainHandler.post {
                    if (snapshot != null) {
                        applySnapshot(snapshot, error = userError(error))
                    } else {
                        state = state.copy(
                            busy = false,
                            notice = null,
                            error = userError(error),
                        )
                    }
                }
            }
        }
    }

    private fun refreshSilently() {
        if (!silentRefreshInFlight.compareAndSet(false, true)) return
        worker.execute {
            val result = runCatching { buildSnapshot() }
            mainHandler.post {
                silentRefreshInFlight.set(false)
                result.onSuccess { snapshot ->
                    if (!state.busy) applySnapshot(snapshot)
                }
            }
        }
    }

    private fun requireRuntime(): M45AcceptanceRuntime {
        val origin = M45ServiceOrigin.parse(
            preferences.getString(KEY_SERVICE_ORIGIN, "").orEmpty(),
        )
        val normalized = origin.toString()
        if (runtime == null || runtimeOrigin != normalized) {
            runtime?.close()
            runtime = M45AcceptanceRuntime.create(appContext, origin)
            runtimeOrigin = normalized
        }
        return checkNotNull(runtime)
    }

    private fun requireOwnerIdentityId(): ByteArray {
        val identity = identityRepository.current()
            ?: throw IllegalStateException("Initialize the local identity first")
        return decodeM45IdentityId(identity.identityId)
    }

    private fun selectedPeerBytes(): ByteArray {
        val owner = requireOwnerIdentityId()
        val localContacts = contactState.contacts(owner)
        val encoded = preferences.getString(KEY_SELECTED_PEER, null)
            ?: localContacts.firstOrNull()?.identityId?.let {
                Base64.getUrlEncoder().withoutPadding().encodeToString(it)
            }
            ?: throw IllegalStateException("Select a contact first")
        val peer = decodeM45IdentityId(encoded)
        if (localContacts.none { it.identityId.contentEquals(peer) }) {
            throw IllegalStateException("Selected contact is no longer pinned locally")
        }
        return peer
    }

    private fun buildSnapshot(): M45AcceptanceUiState {
        val origin = preferences.getString(KEY_SERVICE_ORIGIN, "").orEmpty()
        val identity = identityRepository.current()
        if (identity == null) {
            return M45AcceptanceUiState(
                serviceOrigin = origin,
                messagingEnabled = preferences.getBoolean(KEY_MESSAGING_ENABLED, false),
                messagingState = runtime?.messagingState() ?: MessagingWssState.STOPPED,
            )
        }

        val owner = decodeM45IdentityId(identity.identityId)
        val now = Instant.now().epochSecond
        val pendingInvites = contactState.pendingInvites(owner, now).map { pending ->
            InviteUriCodec.encode(
                M2InviteDescriptor(
                    creatorIdentityId = pending.creatorIdentityId,
                    token = pending.token,
                    signature = pending.signature,
                ),
            )
        }
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val contacts = contactState.contacts(owner).map { contact ->
            M45UiContact(
                localId = encoder.encodeToString(contact.localId),
                peerIdentityId = encoder.encodeToString(contact.identityId),
            )
        }

        val persistedPeer = preferences.getString(KEY_SELECTED_PEER, null)
        val selectedPeer = persistedPeer?.takeIf { candidate ->
            runCatching {
                val decoded = decodeM45IdentityId(candidate)
                contacts.any { it.peerIdentityId == candidate } &&
                    !decoded.contentEquals(owner)
            }.getOrDefault(false)
        } ?: contacts.firstOrNull()?.peerIdentityId

        val messages = if (selectedPeer != null && origin.isNotBlank()) {
            val peer = decodeM45IdentityId(selectedPeer)
            requireRuntime().conversation(peer).messages.map { message ->
                M45UiMessage(
                    messageId = message.messageId,
                    direction = message.direction,
                    deliveryState = message.deliveryState,
                    sentAtEpochSeconds = message.sentAtEpochSeconds,
                    text = message.text,
                )
            }
        } else {
            emptyList()
        }

        return M45AcceptanceUiState(
            serviceOrigin = origin,
            identityId = identity.identityId,
            pendingInvites = pendingInvites,
            contacts = contacts,
            selectedPeerIdentityId = selectedPeer,
            messagingEnabled = preferences.getBoolean(KEY_MESSAGING_ENABLED, false),
            messagingState = runtime?.messagingState() ?: MessagingWssState.STOPPED,
            messages = messages,
        )
    }

    private fun applySnapshot(
        snapshot: M45AcceptanceUiState,
        notice: String? = state.notice,
        error: String? = state.error,
    ) {
        state = snapshot.copy(
            busy = false,
            notice = notice,
            error = error,
        )
    }

    private fun userError(error: Throwable): String {
        val message = error.message
            ?.replace(Regex("\\s+"), " ")
            ?.take(MAX_ERROR_CHARS)
            ?.takeIf { it.isNotBlank() }
        return if (message == null) {
            error.javaClass.simpleName
        } else {
            "${error.javaClass.simpleName}: $message"
        }
    }

    private companion object {
        const val PREFERENCES_NAME = "kenato_m45_acceptance_v1"
        const val KEY_SERVICE_ORIGIN = "service_origin"
        const val KEY_MESSAGING_ENABLED = "messaging_enabled"
        const val KEY_SELECTED_PEER = "selected_peer"
        const val POLL_INTERVAL_MILLIS = 2_000L
        const val MAX_ERROR_CHARS = 240
    }
}
