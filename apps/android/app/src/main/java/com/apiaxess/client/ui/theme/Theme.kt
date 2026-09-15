package com.apiaxess.client.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

// Dark by default per the identity kit; there is no light variant for this
// operator tool — the surface is always the kit's reversed/dark UI.
private val ApiaxessColors = darkColorScheme(
    primary = Accent,
    onPrimary = Paper,
    secondary = AccentGreen,
    background = Ink,
    onBackground = OnSurface,
    surface = Surface,
    onSurface = OnSurface,
    surfaceVariant = SurfaceElevated,
    outline = Outline,
    error = ErrorRed,
    onError = Ink,
)

@Composable
fun ApiaxessTheme(
    // Accepted for API symmetry; the app is intentionally always dark.
    @Suppress("UNUSED_PARAMETER") darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = ApiaxessColors,
        typography = ApiaxessTypography,
        content = content,
    )
}
