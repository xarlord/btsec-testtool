/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.SapTestReport
import com.btsec.testtool.domain.model.SimApdu
import kotlinx.coroutines.flow.Flow

/**
 * Repository for SAP (SIM Access Profile) security testing.
 *
 * Provides capabilities for connecting to SAP, sending APDU commands,
 * reading SIM data, and testing SIM power control.
 *
 * All operations require prior AUTHORIZATION.
 */
interface SapSecurityRepository {

    /**
     * Connect to a device's SAP profile.
     *
     * @param deviceAddress The Bluetooth device address.
     * @return Result.success if connected, Result.failure on error.
     */
    suspend fun connect(deviceAddress: String): Result<Unit>

    /**
     * Disconnect from the current SAP connection.
     */
    suspend fun disconnect()

    /**
     * Send an APDU command to the SIM card via SAP.
     *
     * @param apdu The APDU command to send.
     * @param timeoutMs Response timeout in milliseconds.
     * @return The response bytes, or null on timeout.
     */
    suspend fun sendApdu(apdu: SimApdu, timeoutMs: Long = 5000): ByteArray?

    /**
     * Request the SIM ATR (Answer to Reset).
     *
     * @return The ATR bytes, or null on failure.
     */
    suspend fun requestAtr(): ByteArray?

    /**
     * Power off the SIM card via SAP.
     *
     * @return Result.success if powered off.
     */
    suspend fun powerSimOff(): Result<Unit>

    /**
     * Power on the SIM card via SAP.
     *
     * @return Result.success if powered on.
     */
    suspend fun powerSimOn(): Result<Unit>

    /**
     * Reset the SIM card via SAP.
     *
     * @return Result.success if reset succeeded.
     */
    suspend fun resetSim(): Result<Unit>

    /**
     * Check whether SAP connection is active.
     *
     * @return Flow of connection state.
     */
    fun isSapConnected(): Flow<Boolean>

    /**
     * Save a SAP test report.
     *
     * @param report The completed test report.
     */
    suspend fun saveTestReport(report: SapTestReport)

    /**
     * Get saved SAP test reports for a device.
     *
     * @param deviceAddress The device address.
     * @return Flow of saved test reports.
     */
    fun getTestReports(deviceAddress: String): Flow<List<SapTestReport>>
}
