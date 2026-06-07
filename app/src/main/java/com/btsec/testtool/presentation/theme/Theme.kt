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
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// ── Security Tool Custom Palette (#137) ──

// Primary: cyber-teal
private val CyberTeal = Color(0xFF00BFA5)
private val CyberTealDark = Color(0xFF00897B)
private val CyberTealLight = Color(0xFF64FFDA)

// Secondary: amber/orange for warnings
private val Amber = Color(0xFFFFB300)
private val AmberDark = Color(0xFFFF8F00)
private val AmberLight = Color(0xFFFFE082)

// Error: vulnerability red
private val VulnRed = Color(0xFFEF5350)
private val VulnRedDark = Color(0xFFC62828)
private val VulnRedLight = Color(0xFFFFCDD2)

// Backgrounds: deep navy/charcoal
private val DeepNavy = Color(0xFF0D1B2A)
private val NavySurface = Color(0xFF1B2838)
private val NavySurfaceVariant = Color(0xFF243447)

// Light theme backgrounds
private val LightBg = Color(0xFFF5F7FA)
private val LightSurface = Color(0xFFFFFFFF)
private val LightSurfaceVariant = Color(0xFFE8ECF0)

/**
 * Light color scheme with security-tool branding.
 */
private val LightColors = lightColorScheme(
    primary = CyberTealDark,
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFB2DFDB),
    onPrimaryContainer = Color(0xFF003B31),
    secondary = AmberDark,
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFFFE082),
    onSecondaryContainer = Color(0xFF3E2E00),
    tertiary = Color(0xFF3A6481),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFBCE6FF),
    onTertiaryContainer = Color(0xFF001F30),
    error = VulnRedDark,
    onError = Color(0xFFFFFFFF),
    errorContainer = VulnRedLight,
    onErrorContainer = Color(0xFF410002),
    background = LightBg,
    onBackground = Color(0xFF1A1C1E),
    surface = LightSurface,
    onSurface = Color(0xFF1A1C1E),
    surfaceVariant = LightSurfaceVariant,
    onSurfaceVariant = Color(0xFF41484D),
    outline = Color(0xFF727972),
    inverseOnSurface = Color(0xFFF1F0F4),
    inverseSurface = Color(0xFF2E3130),
    inversePrimary = CyberTealLight,
)

/**
 * Dark color scheme with security-tool branding — deep navy background,
 * cyber-teal primary, amber secondary, vulnerability red for errors.
 */
private val DarkColors = darkColorScheme(
    primary = CyberTeal,
    onPrimary = Color(0xFF003B31),
    primaryContainer = Color(0xFF00897B),
    onPrimaryContainer = CyberTealLight,
    secondary = Amber,
    onSecondary = Color(0xFF3E2E00),
    secondaryContainer = AmberDark,
    onSecondaryContainer = AmberLight,
    tertiary = Color(0xFFBCE6FF),
    onTertiary = Color(0xFF001F30),
    tertiaryContainer = Color(0xFF004C6D),
    onTertiaryContainer = Color(0xFFC6E8FF),
    error = VulnRed,
    onError = Color(0xFF690005),
    errorContainer = VulnRedDark,
    onErrorContainer = VulnRedLight,
    background = DeepNavy,
    onBackground = Color(0xFFE2E6EA),
    surface = NavySurface,
    onSurface = Color(0xFFE2E6EA),
    surfaceVariant = NavySurfaceVariant,
    onSurfaceVariant = Color(0xFFC4C8CC),
    outline = Color(0xFF8D918F),
    inverseOnSurface = DeepNavy,
    inverseSurface = Color(0xFFE2E6EA),
    inversePrimary = CyberTealDark,
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
 * Uses the custom security-tool palette for consistent branding
 * across all devices. Dynamic colors are disabled (#176) to
 * preserve the professional security appearance.
 */
@Composable
fun BTSecTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    // #176: Always use custom security palette — dynamic colors disabled
    // to maintain consistent branding for a security tool.
    val colorScheme = if (darkTheme) DarkColors else LightColors

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
        content = content
    )
}
