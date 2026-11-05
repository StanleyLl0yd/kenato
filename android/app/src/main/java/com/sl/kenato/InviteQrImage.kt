package com.sl.kenato

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.sl.kenato.contact.InviteQr

/** Display-only QR for an already-created one-time invitation. No camera or new permission. */
@Composable
internal fun InviteQrImage(invite: String) {
    val qr = remember(invite) {
        runCatching {
            val pixelsPerSide = 256
            val bits = InviteQr.encode(invite, pixelsPerSide)
            val colors = IntArray(pixelsPerSide * pixelsPerSide) { index ->
                if (bits[index % pixelsPerSide, index / pixelsPerSide]) Color.BLACK else Color.WHITE
            }
            Bitmap.createBitmap(pixelsPerSide, pixelsPerSide, Bitmap.Config.ARGB_8888).apply {
                setPixels(colors, 0, pixelsPerSide, 0, 0, pixelsPerSide, pixelsPerSide)
            }.asImageBitmap()
        }.getOrNull()
    }
    if (qr == null) {
        Text("QR is unavailable. Copy or share the invitation instead.")
    } else {
        Image(
            bitmap = qr,
            contentDescription = "One-time Kenato invitation QR code",
            modifier = Modifier.size(240.dp),
        )
    }
}
