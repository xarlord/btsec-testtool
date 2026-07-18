/*
 * Bluetooth Security Testing Tool
 * This application may ONLY be used for authorized security testing.
 * See LICENSE for full terms.
 */
package com.btsec.testtool.presentation.theme

import androidx.compose.ui.graphics.Color
import kotlin.math.pow

const val WCAG_NORMAL_TEXT_CONTRAST = 4.5

/** WCAG 2.x contrast ratio for opaque foreground/background colors. */
fun contrastRatio(
    first: Color,
    second: Color,
): Double {
    val lighter = maxOf(relativeLuminance(first), relativeLuminance(second))
    val darker = minOf(relativeLuminance(first), relativeLuminance(second))
    return (lighter + 0.05) / (darker + 0.05)
}

/**
 * Keeps the semantic onSurfaceVariant token when it is readable, otherwise uses
 * onSurface. This protects normal-size card descriptions across dynamic schemes.
 */
fun accessibleDescriptionColor(
    background: Color,
    onSurfaceVariant: Color,
    onSurface: Color,
): Color =
    if (contrastRatio(onSurfaceVariant, background) >= WCAG_NORMAL_TEXT_CONTRAST) {
        onSurfaceVariant
    } else {
        onSurface
    }

/** Selects the system-bar icon appearance from the resolved bar background. */
fun usesLightSystemBarIcons(background: Color): Boolean =
    contrastRatio(Color.White, background) > contrastRatio(Color.Black, background)

private fun relativeLuminance(color: Color): Double {
    fun linearize(channel: Float): Double {
        val value = channel.toDouble()
        return if (value <= 0.04045) value / 12.92 else ((value + 0.055) / 1.055).pow(2.4)
    }

    return (0.2126 * linearize(color.red)) +
        (0.7152 * linearize(color.green)) +
        (0.0722 * linearize(color.blue))
}
