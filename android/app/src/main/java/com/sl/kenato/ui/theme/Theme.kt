package com.sl.kenato.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val ColorWhite = Color.White

private val LightColors = lightColorScheme(
    primary = InkIndigo,
    background = WarmIvory,
    surface = WarmIvory,
    onPrimary = ColorWhite,
    onBackground = TextPrimary,
    onSurface = TextPrimary,
    onSurfaceVariant = TextSecondary,
)

private val DarkColors = darkColorScheme(
    primary = DarkIndigo,
    background = Night950,
    surface = Night900,
    onPrimary = ColorWhite,
    onBackground = DarkTextPrimary,
    onSurface = DarkTextPrimary,
    onSurfaceVariant = DarkTextSecondary,
)

@Composable
fun KenatoTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = KenatoTypography,
        content = content,
    )
}
