package com.sl.kenato.session

import android.content.Context
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException

internal interface SessionStateStore {
    fun read(): ByteArray?

    fun write(value: ByteArray): Boolean

    fun clear(): Boolean
}

internal class AtomicFileSessionStateStore(context: Context) : SessionStateStore {
    private val file = AtomicFile(File(context.applicationContext.noBackupFilesDir, STATE_FILE_NAME))

    override fun read(): ByteArray? {
        val input = try {
            file.openRead()
        } catch (_: FileNotFoundException) {
            return null
        } catch (error: Exception) {
            throw SessionStateException("Unable to read persisted session state", error)
        }

        return try {
            input.use {
                // AtomicFile.openRead() restores a pending backup before opening the
                // base file, so size validation must happen only after that recovery.
                val length = file.baseFile.length()
                if (length !in 1..SessionStateCodec.MAX_STATE_BYTES.toLong()) {
                    throw SessionStateException("Persisted session state size is invalid")
                }

                val output = ByteArrayOutputStream(length.toInt())
                val buffer = ByteArray(READ_BUFFER_BYTES)
                var total = 0
                while (true) {
                    val read = it.read(buffer)
                    if (read < 0) {
                        break
                    }
                    total += read
                    if (total > SessionStateCodec.MAX_STATE_BYTES) {
                        throw SessionStateException("Persisted session state is too large")
                    }
                    output.write(buffer, 0, read)
                }
                output.toByteArray().also { state ->
                    if (state.isEmpty()) {
                        throw SessionStateException("Persisted session state is empty")
                    }
                }
            }
        } catch (error: SessionStateException) {
            throw error
        } catch (error: Exception) {
            throw SessionStateException("Unable to read persisted session state", error)
        }
    }

    override fun write(value: ByteArray): Boolean {
        if (value.isEmpty() || value.size > SessionStateCodec.MAX_STATE_BYTES) {
            throw SessionStateException("Session state size is invalid")
        }

        val output = try {
            file.startWrite()
        } catch (error: Exception) {
            throw SessionStateException("Unable to start atomic session-state write", error)
        }
        return try {
            output.write(value)
            output.fd.sync()
            file.finishWrite(output)
            true
        } catch (error: Exception) {
            runCatching { file.failWrite(output) }
            throw SessionStateException("Unable to atomically persist session state", error)
        }
    }

    override fun clear(): Boolean = try {
        file.delete()
        !file.baseFile.exists()
    } catch (error: Exception) {
        throw SessionStateException("Unable to clear persisted session state", error)
    }

    private companion object {
        const val STATE_FILE_NAME = "kenato_session_v1.state"
        const val READ_BUFFER_BYTES = 8 * 1024
    }
}
