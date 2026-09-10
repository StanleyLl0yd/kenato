package com.sl.kenato.contact

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.WriterException
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** Encodes only canonical M2 invite URIs; invite bearer material is never logged or transformed. */
internal object InviteQr {
    const val DEFAULT_SIDE_PIXELS = 512
    const val MIN_SIDE_PIXELS = 128
    const val MAX_SIDE_PIXELS = 1_024

    fun encode(payload: String, sidePixels: Int = DEFAULT_SIDE_PIXELS): BitMatrix {
        if (sidePixels !in MIN_SIDE_PIXELS..MAX_SIDE_PIXELS) {
            throw ContactProtocolException("Invite QR size is out of bounds")
        }
        val invite = InviteUriCodec.decode(payload)
        if (InviteUriCodec.encode(invite) != payload) {
            throw ContactProtocolException("Invite QR payload is non-canonical")
        }
        return try {
            QRCodeWriter().encode(
                payload,
                BarcodeFormat.QR_CODE,
                sidePixels,
                sidePixels,
                mapOf(
                    EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
                    EncodeHintType.MARGIN to QUIET_ZONE_MODULES,
                ),
            )
        } catch (error: WriterException) {
            throw ContactProtocolException("Invite QR payload cannot be encoded", error)
        }
    }

    private const val QUIET_ZONE_MODULES = 4
}
