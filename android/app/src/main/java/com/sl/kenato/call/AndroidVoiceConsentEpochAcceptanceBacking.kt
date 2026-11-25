package com.sl.kenato.call

import android.content.Context
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException

/**
 * Disposable acceptance-only AtomicFile. Never points to the active KCS1
 * consent file, M3 ratchet or signed app's live state.
 */
internal class AndroidVoiceConsentEpochAcceptanceBacking(
    context: Context,
    probeId: String,
) : VoiceConsentEpochRawStore {
    init {
        require(Regex("[0-9a-f]{32}").matches(probeId)) {
            "Probe storage requires random 128-bit namespace"
        }
    }

    private val file = AtomicFile(
        File(context.applicationContext.noBackupFilesDir, "kenato_m5_consent_epoch_acceptance_$probeId.bin"),
    )

    override fun read(): ByteArray? {
        val input = try {
            file.openRead()
        } catch (_: FileNotFoundException) {
            return null
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Cannot open probe consent envelope", error)
        }
        return try {
            input.use { source ->
                val length = file.baseFile.length()
                if (length !in 1..MAX_PERSISTED_BYTES.toLong()) {
                    throw VoiceCapabilityConsentException("Probe consent envelope size invalid")
                }
                val bytes = ByteArrayOutputStream(length.toInt())
                val buffer = ByteArray(4096)
                var size = 0
                while (true) {
                    val count = source.read(buffer)
                    if (count < 0) break
                    size += count
                    if (size > MAX_PERSISTED_BYTES) {
                        throw VoiceCapabilityConsentException("Probe consent envelope exceeds bound")
                    }
                    bytes.write(buffer, 0, count)
                }
                bytes.toByteArray()
            }
        } catch (error: VoiceCapabilityConsentException) {
            throw error
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Unable to read probe consent envelope", error)
        }
    }

    override fun write(bytes: ByteArray): Boolean {
        if (bytes.isEmpty() || bytes.size > MAX_PERSISTED_BYTES) {
            throw VoiceCapabilityConsentException("Probe consent envelope write size invalid")
        }
        val output = try {
            file.startWrite()
        } catch (error: Exception) {
            throw VoiceCapabilityConsentException("Cannot start probe AtomicFile write", error)
        }
        return try {
            output.write(bytes)
            output.fd.sync()
            file.finishWrite(output)
            true
        } catch (error: Exception) {
            runCatching { file.failWrite(output) }
            throw VoiceCapabilityConsentException("Probe consent AtomicFile commit failed", error)
        }
    }

    /** Explicit teardown of this randomized probe file, never the production file. */
    fun deleteOnlyProbeFile() = file.delete()

    private companion object {
        const val MAX_PERSISTED_BYTES = VoiceCapabilityConsentStateCodec.MAX_ENCRYPTED_BYTES + 128
    }
}
