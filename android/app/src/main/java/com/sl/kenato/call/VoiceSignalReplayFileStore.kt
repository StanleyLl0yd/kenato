package com.sl.kenato.call

import android.content.Context
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException

/** No-backup atomic metadata journal. No voice content or ciphertext is persisted here. */
internal class AtomicFileVoiceSignalReplayStore(context: Context) : VoiceSignalReplayStore {
    private val file = AtomicFile(File(context.applicationContext.noBackupFilesDir, "kenato_voice_replay_v1.state"))

    override fun read(): ByteArray? {
        val input = try {
            file.openRead()
        } catch (_: FileNotFoundException) {
            return null
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Unable to open voice replay state", error)
        }
        return try {
            input.use { stream ->
                val length = file.baseFile.length()
                if (length !in 1..VoiceSignalReplayStateCodec.MAX_STATE_BYTES.toLong()) {
                    throw VoiceSignalReplayException("Voice replay file length is invalid")
                }
                val output = ByteArrayOutputStream(length.toInt())
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val read = stream.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > VoiceSignalReplayStateCodec.MAX_STATE_BYTES) {
                        throw VoiceSignalReplayException("Voice replay file is oversized")
                    }
                    output.write(buffer, 0, read)
                }
                output.toByteArray()
            }
        } catch (error: VoiceSignalReplayException) {
            throw error
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Unable to read voice replay state", error)
        }
    }

    override fun write(bytes: ByteArray): Boolean {
        if (bytes.isEmpty() || bytes.size > VoiceSignalReplayStateCodec.MAX_STATE_BYTES) {
            throw VoiceSignalReplayException("Voice replay state size is invalid")
        }
        val output = try {
            file.startWrite()
        } catch (error: Exception) {
            throw VoiceSignalReplayException("Unable to begin atomic voice replay write", error)
        }
        return try {
            output.write(bytes)
            output.fd.sync()
            file.finishWrite(output)
            true
        } catch (error: Exception) {
            runCatching { file.failWrite(output) }
            throw VoiceSignalReplayException("Unable to persist voice replay state", error)
        }
    }

    override fun clear(): Boolean = try {
        file.delete()
        !file.baseFile.exists()
    } catch (error: Exception) {
        throw VoiceSignalReplayException("Unable to clear voice replay state", error)
    }
}
