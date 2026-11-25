package com.sl.kenato.messaging

/**
 * Capture the activation's callback permission at socket creation, then acquire
 * the process owner before entering the WSS coordinator. A late callback from
 * a stopped activation must not acquire the authority of a new activation.
 */
internal class SerializedMessagingSocketFactory(
    private val delegate: MessagingSocketFactory,
    private val ownerMonitor: Any,
    private val capturePermission: () -> (() -> Boolean),
) : MessagingSocketFactory {
    override fun create(url: String, listener: MessagingSocketListener): MessagingSocket {
        val permits = capturePermission()
        return delegate.create(url, object : MessagingSocketListener {
            override fun onOpen(socket: MessagingSocket) = synchronized(ownerMonitor) {
                if (permits()) listener.onOpen(socket)
            }

            override fun onBinaryMessage(socket: MessagingSocket, value: ByteArray) {
                val received = if (
                    value.isNotEmpty() && value.size <= MESSAGING_MAX_WIRE_FRAME_BYTES
                ) value.copyOf() else byteArrayOf()
                synchronized(ownerMonitor) {
                    if (permits()) listener.onBinaryMessage(socket, received)
                }
            }

            override fun onClosed(socket: MessagingSocket) = synchronized(ownerMonitor) {
                if (permits()) listener.onClosed(socket)
            }

            override fun onFailure(socket: MessagingSocket, error: Throwable) =
                synchronized(ownerMonitor) {
                    if (permits()) listener.onFailure(socket, error)
                }
        })
    }
}

/** Timer callbacks use the same owner-first lock order and activation fence. */
internal class SerializedMessagingRetryScheduler(
    private val delegate: MessagingRetryScheduler,
    private val ownerMonitor: Any,
    private val capturePermission: () -> (() -> Boolean),
) : MessagingRetryScheduler {
    override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask {
        val permits = capturePermission()
        return delegate.schedule(delayMillis) {
            synchronized(ownerMonitor) {
                if (permits()) task()
            }
        }
    }
}
