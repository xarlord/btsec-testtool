/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.service

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BluetoothScanServiceTest {
    @Test
    fun `start action is supported without authorization extras`() {
        assertTrue(BluetoothScanService.isSupportedAction(BluetoothScanService.ACTION_START_SCAN))
    }

    @Test
    fun `stop action is supported without authorization extras`() {
        assertTrue(BluetoothScanService.isSupportedAction(BluetoothScanService.ACTION_STOP_SCAN))
    }

    @Test
    fun `null and unknown actions are rejected`() {
        assertFalse(BluetoothScanService.isSupportedAction(null))
        assertFalse(BluetoothScanService.isSupportedAction("com.btsec.testtool.action.UNKNOWN"))
    }
}
