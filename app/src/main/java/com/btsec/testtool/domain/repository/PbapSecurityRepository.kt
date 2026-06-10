/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.PbapAccessResult
import com.btsec.testtool.domain.model.PbmapTestReport
import kotlinx.coroutines.flow.Flow

/**
 * Repository for PBAP (Phone Book Access Profile) security testing.
 *
 * Provides capabilities for connecting to PBAP, accessing phonebooks,
 * and testing authentication requirements for contact data.
 *
 * All operations require prior AUTHORIZATION.
 */
interface PbapSecurityRepository {

    /**
     * Connect to a device's PBAP profile.
     *
     * @param deviceAddress The Bluetooth device address.
     * @return Result.success if connected, Result.failure on error.
     */
    suspend fun connect(deviceAddress: String): Result<Unit>

    /**
     * Disconnect from the current PBAP connection.
     */
    suspend fun disconnect()

    /**
     * Attempt to access a specific phonebook type.
     *
     * @param phonebookType The phonebook to access (contacts, call history, etc.).
     * @return The access result including entries if accessible.
     */
    suspend fun accessPhonebook(phonebookType: com.btsec.testtool.domain.model.PhonebookType): PbapAccessResult

    /**
     * Check whether PBAP connection is active.
     *
     * @return Flow of connection state.
     */
    fun isPbapConnected(): Flow<Boolean>

    /**
     * Save a PBAP test report.
     *
     * @param report The completed test report.
     */
    suspend fun saveTestReport(report: PbmapTestReport)

    /**
     * Get saved PBAP test reports for a device.
     *
     * @param deviceAddress The device address.
     * @return Flow of saved test reports.
     */
    fun getTestReports(deviceAddress: String): Flow<List<PbmapTestReport>>
}
