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
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [DirectFileSnoopStrategy].
 */
@DisplayName("DirectFileSnoopStrategy")
class DirectFileSnoopStrategyTest {
    private lateinit var strategy: DirectFileSnoopStrategy

    @BeforeEach
    fun setup() {
        strategy = DirectFileSnoopStrategy()
    }

    @Test
    fun `getName returns Direct File`() {
        assertEquals("Direct File", strategy.getName())
    }

    @Test
    fun `isAvailable always returns true`() {
        // The strategy code path is always available, even if the file isn't readable
        assertTrue(strategy.isAvailable())
    }

    @Test
    fun `canReadSnoopLog returns false for nonexistent file`() {
        // /data/misc/bluetooth/logs/btsnoop_hci.log won't exist in test environment
        assertFalse(strategy.canReadSnoopLog())
    }

    @Test
    fun `readSnoopLog returns failure when file not found`() {
        val result = strategy.readSnoopLog()
        assertTrue(result.isFailure)
        assertNotNull(result.exceptionOrNull())
    }

    @Test
    fun `readSnoopLog returns failure with descriptive message`() {
        val result = strategy.readSnoopLog()
        assertTrue(result.isFailure)
        val msg = result.exceptionOrNull()!!.message
        assertTrue(
            msg!!.contains("not found") || msg.contains("Cannot read"),
            "Error message should describe the failure: $msg",
        )
    }

    @Test
    fun `SNOOP_LOG_PATH is correct`() {
        assertEquals(
            "/data/misc/bluetooth/logs/btsnoop_hci.log",
            DirectFileSnoopStrategy.SNOOP_LOG_PATH,
        )
    }
}
