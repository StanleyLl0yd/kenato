package com.sl.kenato.call

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.WriterException
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.Base64

/**
 * Display-only representation for locally generated voice-v2 challenge/proof text.
 * QR contents are not trusted or redeemed here; explicit user consent and pinned
 * identity/signature validation remain in the existing capability repository.
 */
internal object VoiceCapabilityQrEncoder {
    private const val CHALLENGE_PREFIX = "kenato-voice-v2:challenge:"
    private const val PROOF_PREFIX = "kenato-voice-v2:proof:"
    private const val MAX_RECORD_CHARS = 512
    private val characters = Regex("^[A-Za-z0-9_-]+$")
    private val decoder = Base64.getUrlDecoder()
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    fun encode(record: String, sidePixels: Int = 512): BitMatrix {
        if (sidePixels !in 128..1024 || record.length !in 1..MAX_RECORD_CHARS) {
            throw VoiceCapabilityQrException("Capability display QR size is invalid")
        }
        val prefix = when {
            record.startsWith(CHALLENGE_PREFIX) -> CHALLENGE_PREFIX
            record.startsWith(PROOF_PREFIX) -> PROOF_PREFIX
            else -> throw VoiceCapabilityQrException("Unknown capability display QR type")
        }
        val payload = record.removePrefix(prefix)
        if (!characters.matches(payload)) {
            throw VoiceCapabilityQrException("Capability display QR data is malformed")
        }
        val decoded = try {
            decoder.decode(payload)
        } catch (error: IllegalArgumentException) {
            throw VoiceCapabilityQrException("Capability display QR data is invalid", error)
        }
        if (encoder.encodeToString(decoded) != payload) {
            throw VoiceCapabilityQrException("Capability display QR data is noncanonical")
        }
        return try {
            QRCodeWriter().encode(
                record,
                BarcodeFormat.QR_CODE,
                sidePixels,
                sidePixels,
                mapOf(
                    EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
                    EncodeHintType.MARGIN to 4,
                ),
            )
        } catch (error: WriterException) {
            throw VoiceCapabilityQrException("Unable to render capability QR", error)
        }
    }
}
