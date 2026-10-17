package io.github.astemo6.mihomo.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import io.github.astemo6.mihomo.data.AppSettings

/** QX-style palette: light grey background with white cards; the dark theme mirrors it. */
@Immutable
data class AppColors(
    val bg: Color,
    val card: Color,
    val cardAlt: Color,
    val text: Color,
    val secondary: Color,
    val separator: Color,
    val good: Color,
    val warn: Color,
    val bad: Color,
    val accent: Color,
)

val LightColors = AppColors(
    bg = Color(0xFFF2F2F7), card = Color.White, cardAlt = Color(0xFFF7F7FA), text = Color(0xFF111114),
    secondary = Color(0xFF8A8A8E), separator = Color(0x1F3C3C43), good = Color(0xFF34C759), warn = Color(0xFFFF9500),
    bad = Color(0xFFFF3B30), accent = Color(0xFF007AFF),
)

val DarkColors = AppColors(
    bg = Color(0xFF000000), card = Color(0xFF1C1C1E), cardAlt = Color(0xFF2C2C2E), text = Color(0xFFF2F2F7),
    secondary = Color(0xFF98989F), separator = Color(0x33FFFFFF), good = Color(0xFF30D158), warn = Color(0xFFFF9F0A),
    bad = Color(0xFFFF453A), accent = Color(0xFF0A84FF),
)

/** Panel strip tile colours (Nodes / Activity / Rules / Rewrite / Logs). */
object PanelColors {
    val nodes = Color(0xFF2F7BF6)
    val activity = Color(0xFF34C759)
    val rules = Color(0xFFFF9500)
    val rewrite = Color(0xFFAF52DE)
    val logs = Color(0xFF5AC8FA)
}

val LocalAppColors = staticCompositionLocalOf { LightColors }

@Composable
fun isDark(theme: AppSettings.Theme): Boolean = when (theme) {
    AppSettings.Theme.SYSTEM -> isSystemInDarkTheme()
    AppSettings.Theme.LIGHT -> false
    AppSettings.Theme.DARK -> true
}

@Composable
fun MihomoTheme(theme: AppSettings.Theme, content: @Composable () -> Unit) {
    val dark = isDark(theme)
    val c = if (dark) DarkColors else LightColors
    val scheme = if (dark) {
        darkColorScheme(primary = c.accent, background = c.bg, surface = c.card, surfaceContainer = c.card,
            surfaceContainerHigh = c.cardAlt, surfaceContainerLow = c.card, onBackground = c.text, onSurface = c.text,
            onSurfaceVariant = c.secondary, outlineVariant = c.separator, error = c.bad)
    } else {
        lightColorScheme(primary = c.accent, background = c.bg, surface = c.card, surfaceContainer = c.card,
            surfaceContainerHigh = c.cardAlt, surfaceContainerLow = c.card, onBackground = c.text, onSurface = c.text,
            onSurfaceVariant = c.secondary, outlineVariant = c.separator, error = c.bad)
    }
    androidx.compose.runtime.CompositionLocalProvider(LocalAppColors provides c) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}
