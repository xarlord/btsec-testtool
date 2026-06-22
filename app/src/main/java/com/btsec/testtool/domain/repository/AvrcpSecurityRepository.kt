/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.AvrcpMediaItem
import com.btsec.testtool.domain.model.AvrcpTestReport
import kotlinx.coroutines.flow.Flow

/**
 * Repository for AVRCP (Audio/Video Remote Control Profile) security testing.
 *
 * Provides capabilities for connecting to AVRCP, browsing media libraries,
 * testing media controls, and detecting directory traversal vulnerabilities.
 *
 * All operations require prior AUTHORIZATION.
 */
interface AvrcpSecurityRepository {
    /**
     * Connect to a device's AVRCP profile.
     *
     * @param deviceAddress The Bluetooth device address.
     * @return Result.success if connected, Result.failure on error.
     */
    suspend fun connect(deviceAddress: String): Result<Unit>

    /**
     * Disconnect from the current AVRCP connection.
     */
    suspend fun disconnect()

    /**
     * Browse the media library at a given path.
     *
     * @param path The virtual path to browse (e.g. "/", "/Music").
     * @param depth Maximum browsing depth.
     * @return List of media items found.
     */
    suspend fun browseMedia(
        path: String,
        depth: Int = 1,
    ): List<AvrcpMediaItem>

    /**
     * Send a media control command (play, pause, next, previous, etc.).
     *
     * @param command The command string.
     * @return Result.success if command was accepted.
     */
    suspend fun sendMediaCommand(command: String): Result<Unit>

    /**
     * Check whether an AVRCP connection is active.
     *
     * @return Flow of connection state.
     */
    fun isAvrcpConnected(): Flow<Boolean>

    /**
     * Save an AVRCP test report.
     *
     * @param report The completed test report.
     */
    suspend fun saveTestReport(report: AvrcpTestReport)

    /**
     * Get saved AVRCP test reports for a device.
     *
     * @param deviceAddress The device address.
     * @return Flow of saved test reports.
     */
    fun getTestReports(deviceAddress: String): Flow<List<AvrcpTestReport>>
}
