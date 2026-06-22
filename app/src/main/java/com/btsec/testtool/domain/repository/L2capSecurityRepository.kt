/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.L2capFixedChannel
import com.btsec.testtool.domain.model.L2capTestReport
import kotlinx.coroutines.flow.Flow

/**
 * Repository for L2CAP security testing.
 *
 * Provides capabilities for L2CAP channel enumeration, signaling
 * command testing, MTU negotiation, and protocol-level fuzzing.
 *
 * All operations require prior AUTHORIZATION.
 */
interface L2capSecurityRepository {
    /**
     * Enumerate fixed L2CAP channels supported by the device.
     *
     * @param deviceAddress The Bluetooth device address.
     * @return List of supported fixed channels.
     */
    suspend fun enumerateFixedChannels(deviceAddress: String): List<L2capFixedChannel>

    /**
     * Send a raw L2CAP signaling command.
     *
     * @param deviceAddress The target device.
     * @param channelId The L2CAP channel ID.
     * @param payload The signaling command payload.
     * @param timeoutMs Response timeout in milliseconds.
     * @return The response payload, or null on timeout.
     */
    suspend fun sendSignalingCommand(
        deviceAddress: String,
        channelId: Int,
        payload: ByteArray,
        timeoutMs: Long = 5000,
    ): ByteArray?

    /**
     * Query device information via L2CAP Information Request.
     *
     * @param deviceAddress The target device.
     * @param infoType The information type to query.
     * @return The information response, or null on failure.
     */
    suspend fun queryInformation(
        deviceAddress: String,
        infoType: Int,
    ): ByteArray?

    /**
     * Check whether an L2CAP connection is active.
     *
     * @return Flow of connection state.
     */
    fun isL2capConnected(): Flow<Boolean>

    /**
     * Save an L2CAP test report.
     *
     * @param report The completed test report.
     */
    suspend fun saveTestReport(report: L2capTestReport)

    /**
     * Get saved L2CAP test reports for a device.
     *
     * @param deviceAddress The device address.
     * @return Flow of saved test reports.
     */
    fun getTestReports(deviceAddress: String): Flow<List<L2capTestReport>>
}
