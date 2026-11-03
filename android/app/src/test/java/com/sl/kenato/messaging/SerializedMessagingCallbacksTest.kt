package com.sl.kenato.messaging

import com.sl.kenato.M45ProcessTransportGate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SerializedMessagingCallbacksTest {
    @Test
    fun binaryCallbackOwnsBoundedImmutableReceiveSnapshot() {
        val sockets = FakeSocketFactory()
        val observed = ArrayList<ByteArray>()
        val listener = object : MessagingSocketListener {
            override fun onOpen(socket: MessagingSocket) = Unit
            override fun onBinaryMessage(socket: MessagingSocket, value: ByteArray) {
                observed += value
            }
            override fun onClosed(socket: MessagingSocket) = Unit
            override fun onFailure(socket: MessagingSocket, error: Throwable) = Unit
        }
        val socket = SerializedMessagingSocketFactory(sockets, Any()) { true }
            .create("wss://example.test/v1/messaging/ws", listener)
        val raw = byteArrayOf(1, 2, 3)
        sockets.callback.onBinaryMessage(socket, raw)
        raw[0] = 9
        assertArrayEquals(byteArrayOf(1, 2, 3), observed.single())

        sockets.callback.onBinaryMessage(socket, ByteArray(MESSAGING_MAX_WIRE_FRAME_BYTES + 1))
        assertEquals(2, observed.size)
        assertTrue(observed[1].isEmpty())
    }

    @Test
    fun poisonedProcessGateDropsAllLateSocketAndSchedulerCallbacks() {
        val gate = M45ProcessTransportGate()
        val sockets = FakeSocketFactory()
        val invoked = CountDownLatch(5)
        val listener = object : MessagingSocketListener {
            override fun onOpen(socket: MessagingSocket) { invoked.countDown() }
            override fun onBinaryMessage(socket: MessagingSocket, value: ByteArray) {
                invoked.countDown()
            }
            override fun onClosed(socket: MessagingSocket) { invoked.countDown() }
            override fun onFailure(socket: MessagingSocket, error: Throwable) {
                invoked.countDown()
            }
        }
        val socket = SerializedMessagingSocketFactory(
            sockets, gate, gate::permitsTransportCallbacks,
        ).create("wss://example.test/v1/messaging/ws", listener)
        val scheduler = FakeScheduler()
        SerializedMessagingRetryScheduler(
            scheduler, gate, gate::permitsTransportCallbacks,
        ).schedule(50L) { invoked.countDown() }

        gate.poison()
        sockets.callback.onOpen(socket)
        sockets.callback.onBinaryMessage(socket, byteArrayOf(1))
        sockets.callback.onClosed(socket)
        sockets.callback.onFailure(socket, IllegalStateException("synthetic failure"))
        scheduler.fire()
        assertEquals(5L, invoked.count)
        assertFalse(gate.permitsTransportCallbacks())
    }

    @Test
    fun everySocketCallbackWaitsForTheOwnerMonitorBeforeEnteringCoordinator() {
        val monitor = Any()
        val sockets = FakeSocketFactory()
        val received = CountDownLatch(4)
        val listener = object : MessagingSocketListener {
            override fun onOpen(socket: MessagingSocket) { received.countDown() }
            override fun onBinaryMessage(socket: MessagingSocket, value: ByteArray) {
                received.countDown()
            }
            override fun onClosed(socket: MessagingSocket) { received.countDown() }
            override fun onFailure(socket: MessagingSocket, error: Throwable) {
                received.countDown()
            }
        }
        val socket = SerializedMessagingSocketFactory(sockets, monitor) { true }
            .create("wss://example.test/v1/messaging/ws", listener)
        val pool = Executors.newFixedThreadPool(4)
        val dispatched = CountDownLatch(4)
        try {
            val tasks = listOf<() -> Unit>(
                { sockets.callback.onOpen(socket) },
                { sockets.callback.onBinaryMessage(socket, byteArrayOf(1)) },
                { sockets.callback.onClosed(socket) },
                { sockets.callback.onFailure(socket, IllegalStateException("synthetic failure")) },
            )
            val futures = synchronized(monitor) {
                tasks.map { task ->
                    pool.submit {
                        dispatched.countDown()
                        task()
                    }
                }.also {
                    assertTrue(dispatched.await(10, TimeUnit.SECONDS))
                    assertFalse(received.await(150, TimeUnit.MILLISECONDS))
                }
            }
            futures.forEach { it.get(10, TimeUnit.SECONDS) }
            assertEquals(0L, received.count)
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun retryCallbackWaitsForOwnerMonitorAndPreservesCancellation() {
        val monitor = Any()
        val scheduler = FakeScheduler()
        val serialized = SerializedMessagingRetryScheduler(scheduler, monitor) { true }
        val delivered = CountDownLatch(1)
        val pool = Executors.newSingleThreadExecutor()
        val dispatched = CountDownLatch(1)
        try {
            val scheduled = serialized.schedule(50L) { delivered.countDown() }
            assertEquals(50L, scheduler.delay)
            val future = synchronized(monitor) {
                pool.submit {
                    dispatched.countDown()
                    scheduler.fire()
                }.also {
                    assertTrue(dispatched.await(10, TimeUnit.SECONDS))
                    assertFalse(delivered.await(150, TimeUnit.MILLISECONDS))
                }
            }
            future.get(10, TimeUnit.SECONDS)
            assertEquals(0L, delivered.count)
            scheduled.cancel()
            assertTrue(scheduler.cancelled)
        } finally {
            pool.shutdownNow()
        }
    }

    private class FakeSocketFactory : MessagingSocketFactory {
        lateinit var callback: MessagingSocketListener
        override fun create(url: String, listener: MessagingSocketListener): MessagingSocket {
            callback = listener
            return object : MessagingSocket {
                override fun connect() = Unit
                override fun sendBinary(value: ByteArray): Boolean = true
                override fun cancel() = Unit
            }
        }
    }

    private class FakeScheduler : MessagingRetryScheduler {
        var delay: Long = -1L
        var cancelled = false
        private lateinit var callback: () -> Unit

        override fun schedule(delayMillis: Long, task: () -> Unit): MessagingScheduledTask {
            delay = delayMillis
            callback = task
            return object : MessagingScheduledTask {
                override fun cancel() { cancelled = true }
            }
        }

        fun fire() = callback()
    }
}
