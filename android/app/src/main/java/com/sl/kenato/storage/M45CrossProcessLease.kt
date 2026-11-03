package com.sl.kenato.storage

import java.io.File
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.file.StandardOpenOption

/**
 * A process-lifetime advisory lease for the Android M4.5 acceptance entrypoint.
 * It is not an M2/M3/WSS/voice transaction, a replay-proof journal, or crash recovery.
 */
internal class M45CrossProcessLease private constructor(
    private val channel: FileChannel,
    private val lock: FileLock,
) : AutoCloseable {
    @Volatile private var closed = false

    fun permitsOperations(): Boolean = !closed && channel.isOpen && lock.isValid

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        try {
            if (lock.isValid) lock.release()
        } catch (error: Throwable) {
            failure = error
        }
        try {
            channel.close()
        } catch (error: Throwable) {
            val earlier = failure
            if (earlier == null) failure = error else earlier.addSuppressed(error)
        }
        failure?.let { throw IllegalStateException("Unable to release M4.5 owner lease safely", it) }
    }

    companion object {
        const val LOCK_FILE_NAME = "kenato_m45_process_owner.lock"
        private val applicationLeases = ProcessLocalOwnerRegistry<M45CrossProcessLease>()

        fun shared(noBackupDirectory: File): M45CrossProcessLease {
            val directory = noBackupDirectory.canonicalFile
            return applicationLeases.getOrCreate(directory.path) { acquire(directory) }.also {
                check(it.permitsOperations()) { "Cross-process state owner lease was lost" }
            }
        }

        fun acquire(noBackupDirectory: File): M45CrossProcessLease {
            require(noBackupDirectory.isDirectory) { "Private M4.5 storage directory is missing" }
            val options: Set<OpenOption> = setOf(
                StandardOpenOption.CREATE,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            )
            val channel = FileChannel.open(noBackupDirectory.toPath().resolve(LOCK_FILE_NAME), options)
            try {
                val lock = try {
                    channel.tryLock()
                } catch (_: OverlappingFileLockException) {
                    null
                } ?: throw IllegalStateException("Another process owns the M4.5 acceptance state")
                return M45CrossProcessLease(channel, lock)
            } catch (error: Throwable) {
                try {
                    channel.close()
                } catch (closeError: Throwable) {
                    error.addSuppressed(closeError)
                }
                throw error
            }
        }
    }
}
