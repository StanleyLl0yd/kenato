package com.sl.kenato.messaging

import android.content.Context
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException

internal interface ConversationHistoryStore {
    fun read(): ByteArray?

    fun write(value: ByteArray): Boolean

    fun clear(): Boolean
}

internal class AtomicFileConversationHistoryStore(context: Context) : ConversationHistoryStore {
    private val file = AtomicFile(File(context.applicationContext.noBackupFilesDir, STATE_FILE_NAME))

    override fun read(): ByteArray? {
        val input = try {
            file.openRead()
        } catch (_: FileNotFoundException) {
            return null
        } catch (error: Exception) {
            throw ConversationHistoryException("Unable to read persisted conversation history", error)
        }

        return try {
            input.use {
                val length = file.baseFile.length()
                if (length !in 1..ConversationHistoryStateCodec.MAX_STATE_BYTES.toLong()) {
                    throw ConversationHistoryException("Persisted conversation history size is invalid")
                }

                val output = ByteArrayOutputStream(length.toInt())
                val buffer = ByteArray(READ_BUFFER_BYTES)
                var total = 0
                while (true) {
                    val read = it.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > ConversationHistoryStateCodec.MAX_STATE_BYTES) {
                        throw ConversationHistoryException("Persisted conversation history is too large")
                    }
                    output.write(buffer, 0, read)
                }
                output.toByteArray().also { state ->
                    if (state.isEmpty()) {
                        throw ConversationHistoryException("Persisted conversation history is empty")
                    }
                }
            }
        } catch (error: ConversationHistoryException) {
            throw error
        } catch (error: Exception) {
            throw ConversationHistoryException("Unable to read persisted conversation history", error)
        }
    }

    override fun write(value: ByteArray): Boolean {
        if (value.isEmpty() || value.size > ConversationHistoryStateCodec.MAX_STATE_BYTES) {
            throw ConversationHistoryException("Conversation history size is invalid")
        }

        val output = try {
            file.startWrite()
        } catch (error: Exception) {
            throw ConversationHistoryException("Unable to start atomic conversation-history write", error)
        }
        return try {
            output.write(value)
            output.fd.sync()
            file.finishWrite(output)
            true
        } catch (error: Exception) {
            runCatching { file.failWrite(output) }
            throw ConversationHistoryException("Unable to atomically persist conversation history", error)
        }
    }

    override fun clear(): Boolean = try {
        file.delete()
        !file.baseFile.exists()
    } catch (error: Exception) {
        throw ConversationHistoryException("Unable to clear persisted conversation history", error)
    }

    private companion object {
        const val STATE_FILE_NAME = "kenato_conversation_history_v1.state"
        const val READ_BUFFER_BYTES = 8 * 1024
    }
}
