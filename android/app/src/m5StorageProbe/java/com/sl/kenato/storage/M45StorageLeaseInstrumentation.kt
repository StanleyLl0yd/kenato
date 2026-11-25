package com.sl.kenato.storage

import android.app.Activity
import android.app.Instrumentation
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import android.os.Process
import com.sl.kenato.M45ProcessTransportGate
import com.sl.kenato.M45StorageLeaseUnavailableException
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** Explicit local instrumentation only; reports fixed case IDs, never state contents. */
class M45StorageLeaseInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        val evidence = Bundle()
        var current = "SETUP"
        try {
            check(targetContext.packageName == M45StorageProbeProtocol.PACKAGE)
            val ctx = targetContext
            val firstToken = token()
            val secondToken = token()
            val first = M45StorageProbeProtocol.directory(ctx, firstToken)
            val second = M45StorageProbeProtocol.directory(ctx, secondToken)
            val sentinel = File(second, "synthetic-sentinel")
            sentinel.writeText("unchanged")
            val firstLease = M45CrossProcessLease.shared(first)
            try {
                Remote(ctx).use { remote ->
                    current = "L01"
                    firstLease.requireActive()
                    val busy = remote.acquire(firstToken)
                    check(busy.first == M45StorageProbeProtocol.BUSY)
                    check(busy.second > 0 && busy.second != Process.myPid())
                    evidence.putString(current, "PASS")

                    current = "L02"
                    val acquired = remote.acquire(secondToken)
                    check(acquired.first == M45StorageProbeProtocol.ACQUIRED)
                    check(acquired.second == busy.second)
                    val secondGate = M45ProcessTransportGate { M45CrossProcessLease.shared(second) }
                    check(!secondGate.isAvailable(Any()))
                    expectDenied { secondGate.localRevocation { throw AssertionError("unexpected write") } }
                    evidence.putString(current, "PASS")

                    current = "L03"
                    remote.killAndAwaitDeath()
                    val secondLease = M45CrossProcessLease.shared(second)
                    try {
                        secondLease.requireActive()
                        check(sentinel.readText() == "unchanged")
                        check(File(second, M45CrossProcessLease.LOCK_FILE_NAME).isFile)
                    } finally {
                        secondLease.close()
                    }
                    evidence.putString(current, "PASS")
                }

                current = "L04"
                val gate = M45ProcessTransportGate { firstLease }
                val owner = Any()
                gate.claim(owner)
                val callback = gate.captureCallbackPermission(owner)
                check(callback())
                firstLease.close()
                check(!callback() && !gate.isAvailable(owner))
                expectDenied { gate.localRevocation { throw AssertionError("unexpected write") } }
                evidence.putString(current, "PASS")

                current = "L05"
                val third = M45StorageProbeProtocol.directory(ctx, token())
                val external = File(third, "synthetic-target").apply { writeText("unchanged") }
                val link = File(third, M45CrossProcessLease.LOCK_FILE_NAME).toPath()
                Files.createSymbolicLink(link, external.toPath())
                var rejected = false
                try {
                    M45CrossProcessLease.shared(third).close()
                } catch (_: IOException) {
                    rejected = true
                }
                check(rejected && Files.isSymbolicLink(link) && external.readText() == "unchanged")
                evidence.putString(current, "PASS")
            } finally {
                firstLease.close()
            }
            evidence.putString("storage_lease_probe", "PASS")
            finish(Activity.RESULT_OK, evidence)
        } catch (_: Throwable) {
            evidence.putString(current, "FAIL")
            evidence.putString("storage_lease_probe", "FAIL")
            finish(Activity.RESULT_CANCELED, evidence)
        }
    }

    private fun token(): String = ByteArray(16).also(SecureRandom()::nextBytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun expectDenied(action: () -> Unit) {
        try {
            action()
            throw AssertionError("missing denial")
        } catch (_: M45StorageLeaseUnavailableException) {
            // Expected, not a generic failure from an executed action.
        }
    }

    private class Remote(private val context: Context) : AutoCloseable {
        private val connected = LinkedBlockingQueue<IBinder>(1)
        private val replies = LinkedBlockingQueue<Pair<Int, Int>>(1)
        private val thread = HandlerThread("storage-lease-probe-reply").apply { start() }
        private val reply = Messenger(Handler(thread.looper) { message ->
            replies.offer(message.what to message.arg1)
            true
        })
        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                connected.offer(service)
            }
            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        private val binder: IBinder

        init {
            val intent = Intent(context, M45StorageLeaseProbeService::class.java)
            var bound = false
            try {
                bound = context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
                check(bound)
                binder = checkNotNull(connected.poll(15, TimeUnit.SECONDS))
            } catch (error: Throwable) {
                if (bound) context.unbindService(connection)
                thread.quitSafely()
                throw error
            }
        }

        fun acquire(token: String): Pair<Int, Int> {
            val message = Message.obtain(null, M45StorageProbeProtocol.ACQUIRE, Process.myPid(), 0)
            message.data = Bundle().apply { putString("token", token) }
            message.replyTo = reply
            Messenger(binder).send(message)
            return checkNotNull(replies.poll(15, TimeUnit.SECONDS))
        }

        fun killAndAwaitDeath() {
            val death = CountDownLatch(1)
            val recipient = IBinder.DeathRecipient { death.countDown() }
            binder.linkToDeath(recipient, 0)
            try {
                Messenger(binder).send(
                    Message.obtain(null, M45StorageProbeProtocol.KILL, Process.myPid(), 0),
                )
                check(death.await(15, TimeUnit.SECONDS))
            } finally {
                binder.unlinkToDeath(recipient, 0)
            }
        }

        override fun close() {
            try {
                context.unbindService(connection)
            } finally {
                thread.quitSafely()
            }
        }
    }
}
