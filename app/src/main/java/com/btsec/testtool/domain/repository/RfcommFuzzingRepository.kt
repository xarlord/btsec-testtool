/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.RfcommChannel
import com.btsec.testtool.domain.model.RfcommFuzzConfig
import com.btsec.testtool.domain.model.RfcommFuzzResult
import kotlinx.coroutines.flow.Flow

/**
 * Repository for RFCOMM channel fuzzing operations.
 *
 * Provides capabilities for discovering RFCOMM channels, establishing
 * connections, sending fuzzing payloads, and recording results.
 *
 * All operations require prior AUTHORIZATION.
 */
interface RfcommFuzzingRepository {
    /**
     * Discover available RFCOMM channels on a device via SDP.
     *
     * @param deviceAddress The Bluetooth device address.
     * @return List of discovered RFCOMM channels.
     */
    suspend fun discoverChannels(deviceAddress: String): List<RfcommChannel>

    /**
     * Connect to a specific RFCOMM channel.
     *
     * @param deviceAddress The device address.
     * @param channelNumber The RFCOMM channel number (1-30).
     * @return Result.success if connected, Result.failure on error.
     */
    suspend fun connect(
        deviceAddress: String,
        channelNumber: Int,
    ): Result<Unit>

    /**
     * Disconnect from the current RFCOMM channel.
     */
    suspend fun disconnect()

    /**
     * Send raw data on the connected RFCOMM channel.
     *
     * @param data The bytes to send.
     * @return Result with the response bytes, or failure.
     */
    suspend fun send(data: ByteArray): Result<ByteArray?>

    /**
     * Execute a fuzzing session on the connected RFCOMM channel.
     *
     * @param config The fuzzing configuration.
     * @return Flow of progress updates, ending with the final result.
     */
    fun executeFuzzSession(config: RfcommFuzzConfig): Flow<RfcommFuzzResult>

    /**
     * Check whether an RFCOMM connection is currently active.
     *
     * @return Flow of connection state.
     */
    fun isConnected(): Flow<Boolean>

    /**
     * Save fuzzing results for a device.
     *
     * @param result The fuzzing result to persist.
     */
    suspend fun saveFuzzResult(result: RfcommFuzzResult)

    /**
     * Get saved fuzzing results for a device.
     *
     * @param deviceAddress The device address.
     * @return Flow of all fuzzing results for this device.
     */
    fun getFuzzResults(deviceAddress: String): Flow<List<RfcommFuzzResult>>
}
