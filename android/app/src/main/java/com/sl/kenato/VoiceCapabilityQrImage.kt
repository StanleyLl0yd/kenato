package com.sl.kenato

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.sl.kenato.call.VoiceCapabilityQrEncoder

/** Display only; using a QR does not grant voice consent or start a microphone. */
@Composable
internal fun VoiceCapabilityQrImage(record: String, description: String) {
    val qr = remember(record) {
        runCatching {
            val side = 512
            val bits = VoiceCapabilityQrEncoder.encode(record, side)
            val colors = IntArray(side * side) { index ->
                if (bits[index % side, index / side]) Color.BLACK else Color.WHITE
            }
            Bitmap.createBitmap(side, side, Bitmap.Config.ARGB_8888).apply {
                setPixels(colors, 0, side, 0, 0, side, side)
            }.asImageBitmap()
        }.getOrNull()
    }
    if (qr == null) {
        Text("QR unavailable. Copy or share the capability text instead.")
    } else {
        Image(
            bitmap = qr,
            contentDescription = description,
            modifier = Modifier.size(264.dp),
            filterQuality = FilterQuality.None,
        )
    }
}
