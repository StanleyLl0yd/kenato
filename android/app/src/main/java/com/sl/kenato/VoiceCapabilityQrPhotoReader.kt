package com.sl.kenato

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.sl.kenato.call.VoiceCapabilityQrException
import com.sl.kenato.call.VoiceCapabilityQrPhotoDecoder
import com.sl.kenato.call.VoiceCapabilityQrPhotoKind

/**
 * User-selected image only. Never opens a camera, requests storage permissions,
 * saves the file, logs its URI/content or approves a voice capability.
 */
internal object VoiceCapabilityQrPhotoReader {
    private const val MAX_IMAGE_SIDE = 12_000
    private const val TARGET_SIDE = 1536

    fun read(context: Context, uri: Uri, expected: VoiceCapabilityQrPhotoKind): String {
        if (uri.scheme != "content") {
            throw VoiceCapabilityQrException("Only user-selected image content is supported")
        }
        val resolver = context.contentResolver
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        val boundsStream = resolver.openInputStream(uri)
            ?: throw VoiceCapabilityQrException("Unable to read the selected image")
        // A bounds-only BitmapFactory decode intentionally returns null.
        boundsStream.use { BitmapFactory.decodeStream(it, null, bounds) }
        if (bounds.outWidth !in 64..MAX_IMAGE_SIDE ||
            bounds.outHeight !in 64..MAX_IMAGE_SIDE
        ) {
            throw VoiceCapabilityQrException("Selected image dimensions are not supported")
        }
        var sample = 1
        while (bounds.outWidth / sample > TARGET_SIDE ||
            bounds.outHeight / sample > TARGET_SIDE
        ) {
            sample *= 2
        }
        val options = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val bitmap = resolver.openInputStream(uri)?.use {
            BitmapFactory.decodeStream(it, null, options)
        } ?: throw VoiceCapabilityQrException("Unable to decode the selected image")

        try {
            val width = bitmap.width
            val height = bitmap.height
            if (width !in 64..TARGET_SIDE || height !in 64..TARGET_SIDE) {
                throw VoiceCapabilityQrException("Selected QR image dimensions are invalid")
            }
            val pixels = IntArray(width * height)
            bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
            return VoiceCapabilityQrPhotoDecoder.decode(width, height, pixels, expected)
        } finally {
            bitmap.recycle()
        }
    }
}
