/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import com.btsec.testtool.R

/**
 * BTSec Test Tool theme configuration.
 *
 * This theme provides a professional security-focused appearance
 * with color coding for vulnerability severities.
 */
private val LightColors = lightColorScheme(
    primary = Color(0xFF1B5E20),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF4C8C52),
    onPrimaryContainer = Color(0xFF003907),
    secondary = Color(0xFF0288D1),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFF4FC3F7),
    onSecondaryContainer = Color(0xFF001F29),
    tertiary = Color(0xFF3A6481),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFBCE6FF),
    onTertiaryContainer = Color(0xFF001F30),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFFFFBFE),
    onBackground = Color(0xFF1A1C1B),
    surface = Color(0xFFFFFBFE),
    onSurface = Color(0xFF1A1C1B),
    surfaceVariant = Color(0xFFDFE4DF),
    onSurfaceVariant = Color(0xFF424940),
    outline = Color(0xFF727972),
    inverseOnSurface = Color(0xFFEFF1EE),
    inverseSurface = Color(0xFF2E3130),
    inversePrimary = Color(0xFF4C8C52),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF4C8C52),
    onPrimary = Color(0xFF003907),
    primaryContainer = Color(0xFF006D1F),
    onPrimaryContainer = Color(0xFF6FE86E),
    secondary = Color(0xFF4FC3F7),
    onSecondary = Color(0xFF001F29),
    secondaryContainer = Color(0xFF004A58),
    onSecondaryContainer = Color(0xFF86E6FF),
    tertiary = Color(0xFFBCE6FF),
    onTertiary = Color(0xFF001F30),
    tertiaryContainer = Color(0xFF004C6D),
    onTertiaryContainer = Color(0xFFC6E8FF),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF1A1C1B),
    onBackground = Color(0xFFE2E2E6),
    surface = Color(0xFF1A1C1B),
    onSurface = Color(0xFFE2E2E6),
    surfaceVariant = Color(0xFF2E3130),
    onSurfaceVariant = Color(0xFFC4C7C5),
    outline = Color(0xFF8D918F),
    inverseOnSurface = Color(0xFF1A1C1B),
    inverseSurface = Color(0xFFE2E2E6),
    inversePrimary = Color(0xFF4C8C52),
)

// Custom colors for vulnerability severities
val CriticalColor = Color(0xFFD32F2F)
val HighColor = Color(0xFFF57C00)
val MediumColor = Color(0xFFFBC02D)
val LowColor = Color(0xFF388E3C)
val InfoColor = Color(0xFF1976D2)

/**
 * Main theme for BTSec Test Tool.
 *
 * Uses Material 3 design with dynamic colors on supported devices.
 */
@Composable
fun BTSecTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.primary.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
