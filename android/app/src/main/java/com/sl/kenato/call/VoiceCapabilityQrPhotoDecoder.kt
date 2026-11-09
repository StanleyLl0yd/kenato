package com.sl.kenato.call

import com.google.zxing.BinaryBitmap
import com.google.zxing.ReaderException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.Base64

/** A QR image is unauthenticated input. Decoding never signs, imports or approves consent. */
internal enum class VoiceCapabilityQrPhotoKind {
    CHALLENGE,
    PROOF,
}

internal object VoiceCapabilityQrPhotoDecoder {
    private const val MAX_SIDE = 1536
    private const val MAX_PIXELS = 1536 * 1536
    private const val MAX_RECORD_CHARS = 512
    private const val CHALLENGE_PREFIX = "kenato-voice-v2:challenge:"
    private const val PROOF_PREFIX = "kenato-voice-v2:proof:"
    private val alphabet = Regex("^[A-Za-z0-9_-]+$")

    fun decode(
        width: Int,
        height: Int,
        pixels: IntArray,
        expected: VoiceCapabilityQrPhotoKind,
    ): String {
        if (width !in 64..MAX_SIDE || height !in 64..MAX_SIDE ||
            width.toLong() * height > MAX_PIXELS || pixels.size != width * height
        ) {
            throw VoiceCapabilityQrException("Selected QR image is too large or invalid")
        }

        val record = try {
            val source = RGBLuminanceSource(width, height, pixels)
            QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source))).text
        } catch (error: ReaderException) {
            throw VoiceCapabilityQrException("No readable Kenato QR in the selected image", error)
        } catch (error: IllegalArgumentException) {
            throw VoiceCapabilityQrException("Invalid selected QR image", error)
        }

        val prefix = when (expected) {
            VoiceCapabilityQrPhotoKind.CHALLENGE -> CHALLENGE_PREFIX
            VoiceCapabilityQrPhotoKind.PROOF -> PROOF_PREFIX
        }
        if (record.length !in (prefix.length + 1)..MAX_RECORD_CHARS ||
            !record.startsWith(prefix)
        ) {
            throw VoiceCapabilityQrException("This image is not the expected Kenato voice QR")
        }
        val payload = record.substring(prefix.length)
        if (!alphabet.matches(payload)) {
            throw VoiceCapabilityQrException("Invalid Kenato QR encoding")
        }
        val bytes = try {
            Base64.getUrlDecoder().decode(payload)
        } catch (error: IllegalArgumentException) {
            throw VoiceCapabilityQrException("Invalid Kenato QR encoding", error)
        }
        if (Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) != payload) {
            throw VoiceCapabilityQrException("Noncanonical Kenato QR encoding")
        }
        // Format/identity/signature/expiry checks remain in the existing explicit approval UI.
        return record
    }
}
