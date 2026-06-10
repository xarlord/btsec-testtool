/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.SdpScanResult
import com.btsec.testtool.domain.model.SdpService
import kotlinx.coroutines.flow.Flow

/**
 * Repository for SDP (Service Discovery Protocol) enumeration operations.
 *
 * Provides capabilities for discovering Bluetooth services via SDP browsing,
 * querying service attributes, and retrieving cached scan results.
 *
 * All operations require prior AUTHORIZATION.
 */
interface SdpEnumerationRepository {

    /**
     * Start an SDP browse on the connected device.
     * Emits discovered services as they are found.
     *
     * @param deviceAddress The Bluetooth device address to browse.
     * @return Flow of discovered SDP services.
     */
    fun browseServices(deviceAddress: String): Flow<SdpService>

    /**
     * Get cached SDP scan results for a specific device.
     *
     * @param deviceAddress The device address.
     * @return The most recent scan result, or null if none exists.
     */
    suspend fun getCachedScanResult(deviceAddress: String): SdpScanResult?

    /**
     * Get all cached SDP scan results.
     *
     * @return Flow of all saved scan results.
     */
    fun getAllScanResults(): Flow<List<SdpScanResult>>

    /**
     * Save an SDP scan result for later retrieval.
     *
     * @param result The scan result to persist.
     */
    suspend fun saveScanResult(result: SdpScanResult)

    /**
     * Delete a cached scan result.
     *
     * @param deviceAddress The device address whose result to delete.
     */
    suspend fun deleteScanResult(deviceAddress: String)

    /**
     * Check whether SDP browsing is currently in progress.
     *
     * @return Flow of the browsing active state.
     */
    fun isBrowsing(): Flow<Boolean>
}
