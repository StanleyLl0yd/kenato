package com.sl.kenato.storage

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process
import java.io.File

internal object M45StorageProbeProtocol {
    const val PACKAGE = "com.sl.kenato.m5storageprobe"
    const val ACQUIRE = 1
    const val KILL = 2
    const val ACQUIRED = 10
    const val BUSY = 11
    const val FAILED = 12

    fun directory(context: Context, token: String): File {
        check(context.packageName == PACKAGE)
        require(token.matches(Regex("[0-9a-f]{32}")))
        val root = context.noBackupFilesDir.canonicalFile
        val directory = File(root, "lease-probe-" + token)
        check(directory.canonicalFile == directory)
        check(directory.isDirectory || directory.mkdir())
        return directory
    }
}

/** Nonexported, disposable secondary process. No real application state. */
class M45StorageLeaseProbeService : Service() {
    private val endpoint = Messenger(Handler(Looper.getMainLooper()) { request ->
        val caller = request.arg1
        if (packageName != M45StorageProbeProtocol.PACKAGE || caller == Process.myPid()) {
            return@Handler true
        }
        when (request.what) {
            M45StorageProbeProtocol.ACQUIRE -> {
                val result = try {
                    val directory = M45StorageProbeProtocol.directory(
                        this, requireNotNull(request.data.getString("token")),
                    )
                    M45CrossProcessLease.shared(directory).requireActive()
                    M45StorageProbeProtocol.ACQUIRED
                } catch (error: IllegalStateException) {
                    if (error.message == "Another process owns the M4.5 acceptance state") {
                        M45StorageProbeProtocol.BUSY
                    } else M45StorageProbeProtocol.FAILED
                } catch (_: Exception) {
                    M45StorageProbeProtocol.FAILED
                }
                request.replyTo?.send(Message.obtain(null, result, Process.myPid(), 0))
            }
            M45StorageProbeProtocol.KILL -> Process.killProcess(Process.myPid())
        }
        true
    })

    override fun onBind(intent: Intent): IBinder {
        check(packageName == M45StorageProbeProtocol.PACKAGE)
        return endpoint.binder
    }
}
