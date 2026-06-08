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
 * Composite repository for fuzzing operations.
 *
 * Extends [FuzzingReader] and [FuzzingWriter] to provide the full set of
 * fuzzing capabilities while adhering to the Interface Segregation Principle
 * (ISP). Existing implementations remain compatible since this interface
 * inherits all methods from its parent interfaces.
 *
 * Handles Bluetooth protocol fuzzing to discover vulnerabilities.
 * All fuzzing must be authorized before execution.
 *
 * @see FuzzingReader
 * @see FuzzingWriter
 */
interface FuzzingRepository : FuzzingReader, FuzzingWriter

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
