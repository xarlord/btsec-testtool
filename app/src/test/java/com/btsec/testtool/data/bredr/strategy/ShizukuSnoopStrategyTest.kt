/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr.strategy

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [ShizukuSnoopStrategy].
 *
 * Since Shizuku is not available in the test environment, all availability
 * checks should return false. When Shizuku is integrated, these tests should
 * be updated or replaced with integration tests.
 */
@DisplayName("ShizukuSnoopStrategy")
class ShizukuSnoopStrategyTest {
    private lateinit var strategy: ShizukuSnoopStrategy

    @BeforeEach
    fun setup() {
        strategy = ShizukuSnoopStrategy()
    }

    @Test
    fun `getName returns Shizuku`() {
        assertEquals("Shizuku", strategy.getName())
    }

    @Test
    fun `isAvailable returns false when Shizuku APK is not installed`() {
        // Shizuku class won't be available in unit test environment
        assertFalse(strategy.isAvailable())
    }

    @Test
    fun `canReadSnoopLog returns false when Shizuku not available`() {
        assertFalse(strategy.canReadSnoopLog())
    }

    @Test
    fun `readSnoopLog returns failure when Shizuku not available`() {
        val result = strategy.readSnoopLog()
        assertTrue(result.isFailure)
        assertTrue(
            result.exceptionOrNull()!!.message!!.contains("not installed"),
            "Error should mention Shizuku not installed",
        )
    }

    @Test
    fun `readSnoopLog returns UnsupportedOperationException`() {
        val result = strategy.readSnoopLog()
        assertTrue(result.exceptionOrNull() is UnsupportedOperationException)
    }
}
