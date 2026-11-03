package com.sl.kenato.messaging

/**
 * The Android-owned M4 WSS callback path must acquire the same process-local monitor as
 * M2/M3 trust mutation and outbound staging BEFORE entering the coordinator's monitor.
 * This is not an inter-process or durable multi-store transaction boundary.
 */
internal class SerializedMessagingSocketFactory(
    private val delegate: MessagingSocketFactory,
    private val ownerMonitor: Any,
    private val permitCallback: () -> Boolean = { true },
) : MessagingSocketFactory {
    override fun create(url: String, listener: MessagingSocketListener): MessagingSocket =
        delegate.create(url, object : MessagingSocketListener {
            override fun onOpen(socket: MessagingSocket) = synchronized(ownerMonitor) {
                if (permitCallback()) listener.onOpen(socket)
            }

            override fun onBinaryMessage(socket: MessagingSocket, value: ByteArray) =
                synchronized(ownerMonitor) {
                    if (permitCallback()) listener.onBinaryMessage(socket, value)
                }

            override fun onClosed(socket: MessagingSocket) = synchronized(ownerMonitor) {
                if (permitCallback()) listener.onClosed(socket)
            }

            override fun onFailure(socket: MessagingSocket, error: Throwable) =
                synchronized(ownerMonitor) {
                    if (permitCallback()) listener.onFailure(socket, error)
                }
        })
}

/**
 * Scheduled reconnect, timeout and durable ACK/retry callbacks use the same lock order:
 * process transport owner first, then M4 coordinator. Cancellation is still delegated.
 */
internal class SerializedMessagingRetryScheduler(
    private val delegate: MessagingRetryScheduler,
    private val ownerMonitor: Any,
    private val permitCallback: () -> Boolean = { true },
) : MessagingRetryScheduler {
    override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask =
        delegate.schedule(delayMillis) {
            synchronized(ownerMonitor) {
                if (permitCallback()) task()
            }
        }
}
