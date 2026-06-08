/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.Flow

/**
 * Read-only interface for fuzzing operation queries.
 *
 * Provides methods to observe fuzzing status/progress, retrieve results,
 * query findings, list available patterns, observe statistics, check rate
 * limits, and read audit logs — all without mutating state.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only read/observation operations, allowing monitoring dashboards
 * and result review tools to depend on a narrow, query-only contract.
 */
interface FuzzingReader {

    /**
     * Get the current fuzzing status.
     */
    fun getFuzzingStatus(): Flow<FuzzStatus>

    /**
     * Get the current fuzzing progress.
     */
    fun getFuzzingProgress(): Flow<FuzzProgress?>

    /**
     * Get a fuzzing result by ID.
     */
    suspend fun getFuzzingResult(id: String): FuzzResult?

    /**
     * Get all fuzzing results.
     */
    fun getAllFuzzingResults(): Flow<List<FuzzResult>>

    /**
     * Get fuzzing results for a specific device.
     */
    fun getFuzzingResultsForDevice(deviceAddress: String): Flow<List<FuzzResult>>

    /**
     * Get fuzzing results within a date range.
     */
    fun getFuzzingResultsInRange(start: java.time.Instant, end: java.time.Instant): Flow<List<FuzzResult>>

    /**
     * Get findings from a specific fuzzing test.
     */
    fun getFindingsForResult(resultId: String): Flow<List<FuzzFinding>>

    /**
     * Get all findings of a specific severity or higher.
     */
    fun getFindingsBySeverity(minSeverity: VulnerabilitySeverity): Flow<List<FuzzFinding>>

    /**
     * Get findings by category.
     */
    fun getFindingsByCategory(category: FindingCategory): Flow<List<FuzzFinding>>

    /**
     * Get available fuzzing data patterns.
     */
    fun getAvailablePatterns(): Flow<List<FuzzDataPattern>>

    /**
     * Get fuzzing patterns for a specific category.
     */
    suspend fun getPatternsForType(type: PatternType): List<FuzzDataPattern>

    /**
     * Get known exploit patterns from CVE database.
     * These are patterns from known vulnerabilities.
     */
    suspend fun getKnownExploitPatterns(): List<FuzzDataPattern>

    /**
     * Get boundary value patterns for testing.
     */
    suspend fun getBoundaryPatterns(): List<FuzzDataPattern>

    /**
     * Get format string patterns.
     */
    suspend fun getFormatStringPatterns(): List<FuzzDataPattern>

    /**
     * Get buffer overflow patterns.
     */
    suspend fun getBufferOverflowPatterns(): List<FuzzDataPattern>

    /**
     * Get fuzzing statistics summary.
     */
    fun getFuzzingStatistics(): Flow<FuzzingStatistics>

    /**
     * Get statistics for a specific device.
     */
    suspend fun getStatisticsForDevice(deviceAddress: String): DeviceFuzzingStatistics

    /**
     * Check if fuzzing rate complies with authorization limits.
     *
     * @param packetsPerSecond Requested rate
     * @return true if rate is within authorized limits
     */
    suspend fun isRateAllowed(packetsPerSecond: Int): Boolean

    /**
     * Get maximum allowed packets per second from authorization.
     */
    suspend fun getMaxAllowedRate(): Int

    /**
     * Get fuzzing operation logs.
     */
    fun getFuzzingLogs(): Flow<List<FuzzingOperation>>
}
