package com.sl.kenato.messaging

import com.sl.kenato.identity.LocalIdentityRepository
import java.net.URI
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import kotlin.math.min

internal class MessagingWssException(message: String, cause: Throwable? = null) : IllegalStateException(message, cause)

private class MessagingWssRetryException(message: String) : IllegalStateException(message)

internal enum class MessagingWssState {
    STOPPED,
    CONNECTING,
    AWAITING_CHALLENGE,
    AWAITING_AUTHENTICATED,
    AUTHENTICATED,
    RETRY_WAIT,
    FAILED,
}

internal interface MessagingIdentityAuthenticator {
    fun identityId(): ByteArray
    fun signProtocolPayload(payload: ByteArray): ByteArray
}

internal class LocalMessagingIdentityAuthenticator(
    private val repository: LocalIdentityRepository,
) : MessagingIdentityAuthenticator {
    override fun identityId(): ByteArray = repository.current()?.identityId?.copyOf()
        ?: throw MessagingWssException("Local identity is not initialized")

    override fun signProtocolPayload(payload: ByteArray): ByteArray =
        repository.signIdentityProtocolPayload(payload)
}

internal interface MessagingRecoveryDriver {
    fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan
    fun recordSendAccepted(ownerIdentityId: ByteArray, accepted: MessagingSendAccepted)
}

internal class DurableMessagingRecoveryDriver(
    private val coordinator: MessagingRecoveryCoordinator,
) : MessagingRecoveryDriver {
    override fun recover(ownerIdentityId: ByteArray): MessagingRecoveryPlan = coordinator.recover(ownerIdentityId)

    override fun recordSendAccepted(ownerIdentityId: ByteArray, accepted: MessagingSendAccepted) =
        coordinator.recordSendAccepted(ownerIdentityId, accepted)
}

/**
 * Delivery processing is deliberately outside the socket layer. Implementations must return an ACK
 * only after the exact delivery is already represented durably in authenticated local history.
 */
internal fun interface MessagingInboundDeliveryHandler {
    fun handle(envelope: MessagingEnvelope): MessagingDeliveryAck?
}

internal interface MessagingScheduledTask {
    fun cancel()
}

internal fun interface MessagingRetryScheduler {
    fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask
}

internal class ExecutorMessagingRetryScheduler(
    private val executor: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "kenato-m4-wss-retry").apply { isDaemon = true }
    },
) : MessagingRetryScheduler, AutoCloseable {
    override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask {
        if (delayMillis < 0) throw MessagingWssException("M4 retry delay is invalid")
        val future = executor.schedule(task, delayMillis, TimeUnit.MILLISECONDS)
        return FutureMessagingScheduledTask(future)
    }

    override fun close() {
        executor.shutdownNow()
    }
}

private class FutureMessagingScheduledTask(
    private val future: ScheduledFuture<*>,
) : MessagingScheduledTask {
    override fun cancel() {
        future.cancel(false)
    }
}

internal fun interface MessagingWssClock {
    fun nowEpochSeconds(): Long
}

private object SystemMessagingWssClock : MessagingWssClock {
    override fun nowEpochSeconds(): Long = Instant.now().epochSecond
}

/**
 * Owns exactly one Android M4 WSS lifecycle. All network sends originate from durable recovery
 * state or a durable inbound delivery result. The coordinator performs no message encryption and
 * never fabricates retry ciphertext.
 */
internal class MessagingWssCoordinator(
    serviceOrigin: URI,
    private val sockets: MessagingSocketFactory,
    private val identity: MessagingIdentityAuthenticator,
    private val recovery: MessagingRecoveryDriver,
    private val inbound: MessagingInboundDeliveryHandler,
    private val scheduler: MessagingRetryScheduler,
    private val clock: MessagingWssClock = SystemMessagingWssClock,
) : MessagingSocketListener {
    private val endpoint = messagingEndpoint(serviceOrigin)

    private var state = MessagingWssState.STOPPED
    private var running = false
    private var activeSocket: MessagingSocket? = null
    private var scheduledReconnect: MessagingScheduledTask? = null
    private var authenticationTimeout: MessagingScheduledTask? = null
    private var reconnectAttempts = 0
    private var authenticatedIdentityId: ByteArray? = null
    private val sentThisConnection = HashSet<MessageKey>()
    private val recoveredAcksSentThisConnection = HashSet<MessageKey>()

    @Synchronized
    fun currentState(): MessagingWssState = state

    @Synchronized
    fun start() {
        if (running) return
        running = true
        reconnectAttempts = 0
        connectNow()
    }

    @Synchronized
    fun stop() {
        running = false
        cancelTimers()
        activeSocket?.cancel()
        activeSocket = null
        authenticatedIdentityId = null
        sentThisConnection.clear()
        recoveredAcksSentThisConnection.clear()
        state = MessagingWssState.STOPPED
    }

    @Synchronized
    override fun onOpen(socket: MessagingSocket) {
        if (!running || socket !== activeSocket) {
            socket.cancel()
            return
        }
        state = MessagingWssState.AWAITING_CHALLENGE
        authenticationTimeout?.cancel()
        authenticationTimeout = scheduler.schedule(AUTHENTICATION_TIMEOUT_MILLIS) {
            synchronized(this) {
                if (
                    running &&
                    socket === activeSocket &&
                    state != MessagingWssState.AUTHENTICATED
                ) {
                    retryConnection(socket)
                }
            }
        }
    }

    @Synchronized
    override fun onBinaryMessage(socket: MessagingSocket, value: ByteArray) {
        if (!running || socket !== activeSocket) return
        if (value.isEmpty() || value.size > MESSAGING_MAX_WIRE_FRAME_BYTES) {
            failClosed(socket)
            return
        }
        val frame = try {
            MessagingWire.decodeServerFrame(value)
        } catch (_: Exception) {
            failClosed(socket)
            return
        }
        try {
            when (state) {
                MessagingWssState.AWAITING_CHALLENGE -> handleChallenge(socket, frame)
                MessagingWssState.AWAITING_AUTHENTICATED -> handleAuthenticated(socket, frame)
                MessagingWssState.AUTHENTICATED -> handleAuthenticatedFrame(socket, frame)
                else -> throw MessagingWssException("Unexpected M4 frame for current socket state")
            }
        } catch (_: MessagingWssRetryException) {
            retryConnection(socket)
        } catch (_: Exception) {
            failClosed(socket)
        }
    }

    @Synchronized
    override fun onClosed(socket: MessagingSocket) {
        if (socket === activeSocket) retryConnection(socket)
    }

    @Synchronized
    override fun onFailure(socket: MessagingSocket, error: Throwable) {
        if (socket === activeSocket) retryConnection(socket)
    }

    private fun handleChallenge(socket: MessagingSocket, frame: MessagingServerFrame) {
        val challenge = frame.authChallenge
        if (
            challenge == null ||
            frame.authenticated ||
            frame.delivery != null ||
            frame.sendAccepted != null ||
            frame.error != null
        ) {
            throw MessagingWssException("Expected M4 authentication challenge")
        }
        val now = nowEpochSeconds()
        MessagingProtocol.validateAuthChallenge(challenge, now)
        val identityId = identity.identityId()
        requireIdentity(identityId)
        val payload = MessagingProtocol.authPayload(
            identityId,
            challenge.challenge,
            challenge.expiresAtEpochSeconds,
        )
        val signature = identity.signProtocolPayload(payload)
        val response = MessagingAuthResponse(
            identityId = identityId.copyOf(),
            challenge = challenge.challenge.copyOf(),
            expiresAtEpochSeconds = challenge.expiresAtEpochSeconds,
            signature = signature.copyOf(),
        )
        sendFrame(socket, MessagingClientFrame(authResponse = response))
        authenticatedIdentityId = identityId.copyOf()
        state = MessagingWssState.AWAITING_AUTHENTICATED
    }

    private fun handleAuthenticated(socket: MessagingSocket, frame: MessagingServerFrame) {
        if (
            !frame.authenticated ||
            frame.authChallenge != null ||
            frame.delivery != null ||
            frame.sendAccepted != null ||
            frame.error != null
        ) {
            throw MessagingWssException("Expected M4 authenticated confirmation")
        }
        authenticationTimeout?.cancel()
        authenticationTimeout = null
        reconnectAttempts = 0
        sentThisConnection.clear()
        recoveredAcksSentThisConnection.clear()
        state = MessagingWssState.AUTHENTICATED
        pumpRecovery(socket)
    }

    private fun handleAuthenticatedFrame(socket: MessagingSocket, frame: MessagingServerFrame) {
        when {
            frame.delivery != null -> handleDelivery(socket, frame.delivery)
            frame.sendAccepted != null -> {
                val owner = requireAuthenticatedIdentity()
                recovery.recordSendAccepted(owner, frame.sendAccepted)
                sentThisConnection.remove(MessageKey(frame.sendAccepted.recipientIdentityId, frame.sendAccepted.messageId))
                pumpRecovery(socket)
            }
            frame.error != null -> handleServerError(socket, frame.error)
            else -> throw MessagingWssException("Unexpected M4 server frame after authentication")
        }
    }

    private fun handleDelivery(socket: MessagingSocket, envelope: MessagingEnvelope) {
        val owner = requireAuthenticatedIdentity()
        MessagingProtocol.validateEnvelope(envelope, nowEpochSeconds())
        if (!envelope.recipientIdentityId.contentEquals(owner)) {
            throw MessagingWssException("M4 delivery recipient does not match authenticated identity")
        }
        val ack = inbound.handle(envelope) ?: return
        if (
            !ack.senderIdentityId.contentEquals(envelope.senderIdentityId) ||
            !ack.messageId.contentEquals(envelope.messageId)
        ) {
            throw MessagingWssException("M4 delivery handler returned a mismatched ACK")
        }
        // ACK is idempotent server-side. A repeated delivery is deliberately re-ACKed after the
        // durable handler has revalidated it, avoiding loss if an earlier queued ACK never arrived.
        sendFrame(socket, MessagingClientFrame(ack = ack))
    }

    private fun handleServerError(socket: MessagingSocket, error: MessagingWireError) {
        when (error.code) {
            MESSAGING_ERROR_RETRY_LATER -> retryConnection(socket)
            MESSAGING_ERROR_MALFORMED,
            MESSAGING_ERROR_AUTHENTICATION_FAILED,
            MESSAGING_ERROR_SEND_REJECTED,
            -> failClosed(socket)
            else -> failClosed(socket)
        }
    }

    private fun pumpRecovery(socket: MessagingSocket) {
        if (socket !== activeSocket || state != MessagingWssState.AUTHENTICATED) return
        val owner = requireAuthenticatedIdentity()
        val plan = recovery.recover(owner)
        if (plan.outboundSends.size > MAX_QUEUED_STAGED_SENDS) {
            throw MessagingWssException("M4 staged send count exceeds the transport bound")
        }
        plan.outboundSends.forEach { recovered ->
            val key = MessageKey(recovered.peerIdentityId, recovered.messageId)
            if (sentThisConnection.add(key)) {
                val envelope = decodeExactRecoveredEnvelope(recovered, owner)
                sendFrame(socket, MessagingClientFrame(send = envelope))
            }
        }
        plan.inboundAcks.forEach { recovered ->
            val key = MessageKey(recovered.peerIdentityId, recovered.messageId)
            if (recoveredAcksSentThisConnection.add(key)) {
                sendFrame(
                    socket,
                    MessagingClientFrame(
                        ack = MessagingDeliveryAck(
                            senderIdentityId = recovered.peerIdentityId.copyOf(),
                            messageId = recovered.messageId.copyOf(),
                        ),
                    ),
                )
            }
        }
    }

    private fun decodeExactRecoveredEnvelope(
        recovered: MessagingRecoveredSend,
        ownerIdentityId: ByteArray,
    ): MessagingEnvelope {
        val envelope = MessagingWire.decodeEnvelope(recovered.encodedEnvelope)
        val canonical = MessagingWire.encodeEnvelope(envelope)
        if (!canonical.contentEquals(recovered.encodedEnvelope)) {
            throw MessagingWssException("Recovered M4 envelope is not canonical")
        }
        if (
            !envelope.senderIdentityId.contentEquals(ownerIdentityId) ||
            !envelope.recipientIdentityId.contentEquals(recovered.peerIdentityId) ||
            !envelope.messageId.contentEquals(recovered.messageId)
        ) {
            throw MessagingWssException("Recovered M4 envelope provenance is invalid")
        }
        MessagingProtocol.validateEnvelope(envelope, nowEpochSeconds())
        return envelope
    }

    private fun sendFrame(socket: MessagingSocket, frame: MessagingClientFrame) {
        val encoded = MessagingWire.encodeClientFrame(frame)
        if (!socket.sendBinary(encoded)) {
            throw MessagingWssRetryException("Unable to enqueue M4 WebSocket frame")
        }
    }

    private fun connectNow() {
        if (!running || activeSocket != null) return
        state = MessagingWssState.CONNECTING
        val socket = try {
            sockets.create(endpoint, this)
        } catch (_: Exception) {
            null
        }
        if (socket == null) {
            scheduleReconnect()
            return
        }
        activeSocket = socket
        try {
            socket.connect()
        } catch (_: Exception) {
            retryConnection(socket)
        }
    }

    private fun retryConnection(socket: MessagingSocket) {
        if (socket !== activeSocket) return
        authenticationTimeout?.cancel()
        authenticationTimeout = null
        socket.cancel()
        activeSocket = null
        authenticatedIdentityId = null
        sentThisConnection.clear()
        recoveredAcksSentThisConnection.clear()
        if (running) scheduleReconnect() else state = MessagingWssState.STOPPED
    }

    private fun scheduleReconnect() {
        if (!running) return
        scheduledReconnect?.cancel()
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            running = false
            state = MessagingWssState.FAILED
            return
        }
        val shift = min(reconnectAttempts, 30)
        val exponential = INITIAL_RECONNECT_DELAY_MILLIS * (1L shl shift)
        val delay = min(exponential, MAX_RECONNECT_DELAY_MILLIS)
        reconnectAttempts++
        state = MessagingWssState.RETRY_WAIT
        scheduledReconnect = scheduler.schedule(delay) {
            synchronized(this) {
                scheduledReconnect = null
                if (running && activeSocket == null) connectNow()
            }
        }
    }

    private fun failClosed(socket: MessagingSocket) {
        if (socket !== activeSocket) return
        running = false
        cancelTimers()
        socket.cancel()
        activeSocket = null
        authenticatedIdentityId = null
        sentThisConnection.clear()
        recoveredAcksSentThisConnection.clear()
        state = MessagingWssState.FAILED
    }

    private fun cancelTimers() {
        scheduledReconnect?.cancel()
        scheduledReconnect = null
        authenticationTimeout?.cancel()
        authenticationTimeout = null
    }

    private fun requireAuthenticatedIdentity(): ByteArray =
        authenticatedIdentityId?.copyOf()
            ?: throw MessagingWssException("M4 socket is not authenticated")

    private fun requireIdentity(value: ByteArray) {
        if (value.size != MESSAGING_IDENTITY_BYTES) {
            throw MessagingWssException("M4 local identity id size is invalid")
        }
    }

    private fun nowEpochSeconds(): Long = clock.nowEpochSeconds().also {
        if (it < 0) throw MessagingWssException("M4 clock returned an invalid timestamp")
    }

    private class MessageKey(peerIdentityId: ByteArray, messageId: ByteArray) {
        private val peer = peerIdentityId.copyOf()
        private val message = messageId.copyOf()

        override fun equals(other: Any?): Boolean =
            other is MessageKey && peer.contentEquals(other.peer) && message.contentEquals(other.message)

        override fun hashCode(): Int = 31 * peer.contentHashCode() + message.contentHashCode()
    }

    companion object {
        const val MAX_QUEUED_STAGED_SENDS = 32
        const val MAX_RECONNECT_ATTEMPTS = 8
        const val INITIAL_RECONNECT_DELAY_MILLIS = 1_000L
        const val MAX_RECONNECT_DELAY_MILLIS = 30_000L
        const val AUTHENTICATION_TIMEOUT_MILLIS = 15_000L

        private const val MESSAGING_PATH = "/v1/messaging/ws"

        private fun messagingEndpoint(serviceOrigin: URI): String {
            if (
                serviceOrigin.scheme != "https" ||
                serviceOrigin.host.isNullOrBlank() ||
                serviceOrigin.rawUserInfo != null ||
                serviceOrigin.rawQuery != null ||
                serviceOrigin.rawFragment != null ||
                (serviceOrigin.rawPath.isNotEmpty() && serviceOrigin.rawPath != "/")
            ) {
                throw MessagingWssException("M4 messaging service origin must be an HTTPS origin")
            }
            return URI(
                "wss",
                null,
                serviceOrigin.host,
                serviceOrigin.port,
                MESSAGING_PATH,
                null,
                null,
            ).toString()
        }
    }
}
