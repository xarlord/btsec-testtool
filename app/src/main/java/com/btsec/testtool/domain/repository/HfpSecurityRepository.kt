/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.HfpTestResult
import com.btsec.testtool.domain.model.HfpTestSuite
import kotlinx.coroutines.flow.Flow

/**
 * Repository for HFP (Hands-Free Profile) security testing operations.
 *
 * Provides capabilities for connecting to HFP, sending AT commands,
 * receiving responses, and persisting test results.
 *
 * All operations require prior AUTHORIZATION.
 */
interface HfpSecurityRepository {

    /**
     * Connect to a device's HFP profile.
     *
     * @param deviceAddress The Bluetooth device address.
     * @return Result.success if connected, Result.failure on error.
     */
    suspend fun connect(deviceAddress: String): Result<Unit>

    /**
     * Disconnect from the current HFP connection.
     */
    suspend fun disconnect()

    /**
     * Send an AT command and wait for the response.
     *
     * @param command The AT command string (e.g. "ATI", "AT+CLCC").
     * @param timeoutMs Response timeout in milliseconds.
     * @return The raw response string, or null on timeout.
     */
    suspend fun sendAtCommand(command: String, timeoutMs: Long = 5000): String?

    /**
     * Get the current call state from the HFP connection.
     *
     * @return Flow of call state updates.
     */
    fun isHfpConnected(): Flow<Boolean>

    /**
     * Save an HFP test suite result.
     *
     * @param suite The completed test suite to persist.
     */
    suspend fun saveTestSuite(suite: HfpTestSuite)

    /**
     * Get saved HFP test results for a device.
     *
     * @param deviceAddress The device address.
     * @return Flow of saved test suites for this device.
     */
    fun getTestSuites(deviceAddress: String): Flow<List<HfpTestSuite>>

    /**
     * Get all saved HFP test results.
     *
     * @return Flow of all saved test suites.
     */
    fun getAllTestSuites(): Flow<List<HfpTestSuite>>
}
