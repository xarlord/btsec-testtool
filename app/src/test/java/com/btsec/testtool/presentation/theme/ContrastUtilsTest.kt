/*
 * Bluetooth Security Testing Tool
 * This application may ONLY be used for authorized security testing.
 * See LICENSE for full terms.
 */
package com.btsec.testtool.presentation.theme

import androidx.compose.ui.graphics.Color
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ContrastUtilsTest {
    @Test
    fun `wcag contrast ratio uses relative luminance`() {
        assertEquals(21.0, contrastRatio(Color.Black, Color.White), 0.01)
    }

    @Test
    fun `description color falls back to onSurface when variant is not readable`() {
        val background = Color(0xFFE8F0F8)
        val onSurface = Color(0xFF17212B)
        val lowContrastVariant = Color(0xFF9AA9B8)

        val selected = accessibleDescriptionColor(background, lowContrastVariant, onSurface)

        assertEquals(onSurface, selected)
        assertTrue(contrastRatio(selected, background) >= WCAG_NORMAL_TEXT_CONTRAST)
    }

    @Test
    fun `description color preserves semantic variant when it meets target`() {
        val background = Color.White
        val variant = Color(0xFF424940)
        val onSurface = Color(0xFF1A1C1B)

        assertEquals(variant, accessibleDescriptionColor(background, variant, onSurface))
        assertTrue(contrastRatio(variant, background) >= WCAG_NORMAL_TEXT_CONTRAST)
    }

    @Test
    fun `system bar icon appearance follows resolved background`() {
        assertTrue(usesLightSystemBarIcons(Color(0xFF121212)))
        assertEquals(false, usesLightSystemBarIcons(Color.White))
    }
}
