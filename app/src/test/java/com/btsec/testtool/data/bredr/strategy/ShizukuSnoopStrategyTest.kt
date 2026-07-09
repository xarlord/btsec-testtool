/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr.strategy

import android.content.Context
import android.content.pm.PackageManager
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [ShizukuSnoopStrategy].
 *
 * Since Shizuku is not available in the test environment, all availability
 * checks return false. Tests verify behavior when Shizuku is absent.
 */
@DisplayName("ShizukuSnoopStrategy")
class ShizukuSnoopStrategyTest {
    private lateinit var strategy: ShizukuSnoopStrategy
    private lateinit var mockContext: Context

    @BeforeEach
    fun setup() {
        mockContext = mockk(relaxed = true)
        strategy = ShizukuSnoopStrategy(mockContext)
    }

    @Test
    fun `getName returns Shizuku`() {
        assertEquals("Shizuku", strategy.getName())
    }

    @Test
    fun `isAvailable returns false when Shizuku APK is not installed`() {
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

    @Test
    fun `detectSnoopLogPath returns null when Shizuku not available`() {
        assertNull(strategy.detectSnoopLogPath())
    }

    @Test
    fun `getSnoopLogSize returns negative when Shizuku not available`() {
        assertEquals(-1L, strategy.getSnoopLogSize())
    }

    @Test
    fun `requestPermission does not throw when Shizuku not available`() {
        strategy.requestPermission()
    }

    @Test
    fun `onPermissionResult handles denied`() {
        strategy.onPermissionResult(100, PackageManager.PERMISSION_DENIED)
        assertFalse(strategy.canReadSnoopLog())
    }

    @Test
    fun `onPermissionResult ignores wrong request code`() {
        strategy.onPermissionResult(999, PackageManager.PERMISSION_GRANTED)
        assertFalse(strategy.canReadSnoopLog())
    }

    @Test
    fun `bindUserService returns false when Shizuku not available`() {
        assertFalse(strategy.bindUserService())
    }
}
