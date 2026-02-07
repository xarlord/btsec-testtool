/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.Flow

/**
 * Repository for fuzzing operations.
 *
 * Handles Bluetooth protocol fuzzing to discover vulnerabilities.
 * All fuzzing must be authorized before execution.
 */
interface FuzzingRepository {

    // ========== Fuzzing Operations ==========

    /**
     * Start a fuzzing test with the given configuration.
     *
     * @param config Fuzzing configuration
     * @return Flow of fuzzing progress updates
     */
    fun startFuzzing(config: FuzzConfig): Flow<FuzzProgress>

    /**
     * Stop the currently running fuzzing test.
     */
    suspend fun stopFuzzing(): Result<Unit>

    /**
     * Pause the current fuzzing test.
     */
    suspend fun pauseFuzzing(): Result<Unit>

    /**
     * Resume a paused fuzzing test.
     */
    suspend fun resumeFuzzing(): Result<Unit>

    /**
     * Get the current fuzzing status.
     */
    fun getFuzzingStatus(): Flow<FuzzStatus>

    /**
     * Get the current fuzzing progress.
     */
    fun getFuzzingProgress(): Flow<FuzzProgress?>

    // ========== Fuzzing Results ==========

    /**
     * Save a fuzzing result.
     */
    suspend fun saveFuzzingResult(result: FuzzResult): Result<Unit>

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
     * Delete a fuzzing result.
     */
    suspend fun deleteFuzzingResult(id: String): Result<Unit>

    // ========== Fuzzing Findings ==========

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

    // ========== Fuzzing Patterns ==========

    /**
     * Get available fuzzing data patterns.
     */
    fun getAvailablePatterns(): Flow<List<FuzzDataPattern>>

    /**
     * Add a custom fuzzing pattern.
     */
    suspend fun addPattern(pattern: FuzzDataPattern): Result<Unit>

    /**
     * Remove a fuzzing pattern.
     */
    suspend fun removePattern(patternName: String): Result<Unit>

    /**
     * Get fuzzing patterns for a specific category.
     */
    suspend fun getPatternsForType(type: PatternType): List<FuzzDataPattern>

    // ========== Predefined Patterns ==========

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

    // ========== Fuzzing Statistics ==========

    /**
     * Get fuzzing statistics summary.
     */
    fun getFuzzingStatistics(): Flow<FuzzingStatistics>

    /**
     * Get statistics for a specific device.
     */
    suspend fun getStatisticsForDevice(deviceAddress: String): DeviceFuzzingStatistics

    // ========== Rate Limiting ==========

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

    // ========== Logging ==========

    /**
     * Log a fuzzing operation for audit purposes.
     */
    suspend fun logFuzzingOperation(operation: FuzzingOperation)

    /**
     * Get fuzzing operation logs.
     */
    fun getFuzzingLogs(): Flow<List<FuzzingOperation>>
}

/**
 * Fuzzing progress information.
 */
data class FuzzProgress(
    val resultId: String,
    val config: FuzzConfig,
    val status: FuzzStatus,
    val packetsSent: Int,
    val packetsReceived: Int,
    val errors: Int,
    val findings: Int,
    val startTime: java.time.Instant,
    val estimatedCompletionTime: java.time.Instant?,
    val currentPacketNumber: Int,
    val totalPackets: Int,
    val currentError: String? = null
) {
    /**
     * Calculate progress percentage.
     */
    fun getProgressPercentage(): Double {
        return if (totalPackets > 0) {
            (currentPacketNumber.toDouble() / totalPackets.toDouble()) * 100.0
        } else 0.0
    }

    /**
     * Calculate success rate.
     */
    fun getSuccessRate(): Double {
        return if (packetsSent > 0) {
            (packetsReceived.toDouble() / packetsSent.toDouble()) * 100.0
        } else 0.0
    }

    /**
     * Calculate elapsed time.
     */
    fun getElapsedTime(): java.time.Duration {
        return java.time.Duration.between(startTime, java.time.Instant.now())
    }
}

/**
 * Fuzzing statistics summary.
 */
data class FuzzingStatistics(
    val totalTests: Int,
    val totalPacketsSent: Long,
    val totalPacketsReceived: Long,
    val totalErrors: Long,
    val totalFindings: Long,
    val criticalFindings: Int,
    val highFindings: Int,
    val mediumFindings: Int,
    val lowFindings: Int,
    val averageSuccessRate: Double,
    val mostTestedDevice: String?,
    val mostVulnerableDevice: String?,
    val dateRange: DateRange
)

/**
 * Date range for statistics.
 */
data class DateRange(
    val start: java.time.Instant,
    val end: java.time.Instant
)

/**
 * Device-specific fuzzing statistics.
 */
data class DeviceFuzzingStatistics(
    val deviceAddress: String,
    val deviceName: String?,
    val testsPerformed: Int,
    val packetsSent: Long,
    val packetsReceived: Long,
    val findings: Int,
    val lastTestDate: java.time.Instant,
    val vulnerabilitiesDiscovered: List<String>
)

/**
 * Fuzzing operation log entry.
 */
data class FuzzingOperation(
    val id: String,
    val timestamp: java.time.Instant,
    val operationType: FuzzingOperationType,
    val targetDevice: String,
    val resultId: String?,
    val success: Boolean,
    val errorMessage: String?,
    val durationMs: Long?,
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Fuzzing operation types.
 */
enum class FuzzingOperationType {
    START,
    STOP,
    PAUSE,
    RESUME,
    COMPLETE,
    ERROR,
    FINDING_DISCOVERED,
    SAVE_RESULT
}
