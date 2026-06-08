/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNull

@DisplayName("BtSecTypeConverters")
class BtSecTypeConvertersTest {

    private val converters = BtSecTypeConverters()

    @Nested
    @DisplayName("Instant conversion")
    inner class InstantConversion {

        @Test
        @DisplayName("fromInstant converts Instant to epoch millis")
        fun `fromInstant converts Instant to epoch millis`() {
            val instant = Instant.ofEpochMilli(1700000000000L)
            val result = converters.fromInstant(instant)
            assertEquals(1700000000000L, result)
        }

        @Test
        @DisplayName("fromInstant returns null for null input")
        fun fromInstantReturnsNullForNull() {
            val result = converters.fromInstant(null)
            assertNull(result)
        }

        @Test
        @DisplayName("toInstant converts epoch millis to Instant")
        fun toInstantConvertsMillisToInstant() {
            val instant = converters.toInstant(1700000000000L)
            assertEquals(Instant.ofEpochMilli(1700000000000L), instant)
        }

        @Test
        @DisplayName("toInstant returns null for null input")
        fun toInstantReturnsNullForNull() {
            val result = converters.toInstant(null)
            assertNull(result)
        }

        @Test
        @DisplayName("round-trip: Instant -> Long -> Instant preserves value")
        fun roundTripInstantPreservesValue() {
            val original = Instant.ofEpochMilli(1700000000123L)
            val millis = converters.fromInstant(original)
            val restored = converters.toInstant(millis)
            assertEquals(original, restored)
        }
    }
}
