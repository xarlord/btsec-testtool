/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.MapAccessResult
import com.btsec.testtool.domain.model.MapFolder
import com.btsec.testtool.domain.model.PbmapTestReport
import kotlinx.coroutines.flow.Flow

/**
 * Repository for MAP (Message Access Profile) security testing.
 *
 * Provides capabilities for connecting to MAP, accessing message folders,
 * and testing authentication requirements for SMS/email data.
 *
 * All operations require prior AUTHORIZATION.
 */
interface MapSecurityRepository {

    /**
     * Connect to a device's MAP profile.
     *
     * @param deviceAddress The Bluetooth device address.
     * @return Result.success if connected, Result.failure on error.
     */
    suspend fun connect(deviceAddress: String): Result<Unit>

    /**
     * Disconnect from the current MAP connection.
     */
    suspend fun disconnect()

    /**
     * Attempt to access a specific message folder.
     *
     * @param folder The MAP folder to access.
     * @return The access result including messages if accessible.
     */
    suspend fun accessFolder(folder: MapFolder): MapAccessResult

    /**
     * Check whether MAP connection is active.
     *
     * @return Flow of connection state.
     */
    fun isMapConnected(): Flow<Boolean>

    /**
     * Save a MAP test report.
     *
     * @param report The completed test report.
     */
    suspend fun saveTestReport(report: PbmapTestReport)

    /**
     * Get saved MAP test reports for a device.
     *
     * @param deviceAddress The device address.
     * @return Flow of saved test reports.
     */
    fun getTestReports(deviceAddress: String): Flow<List<PbmapTestReport>>
}
