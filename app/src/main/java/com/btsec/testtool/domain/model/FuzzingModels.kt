/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import java.time.Instant

/**
 * Fuzzing configuration.
 */
data class FuzzConfig(
    val targetDevice: BluetoothDevice,
    val targetService: BleService?,    // Service to fuzz (null = all)
    val targetCharacteristic: BleCharacteristic?,  // Characteristic to fuzz
    val fuzzMethod: FuzzMethod,        // Fuzzing strategy
    val packetCount: Int,              // Number of packets to send
    val packetsPerSecond: Int,         // Rate limiting
    val randomSeed: Long?,             // Seed for reproducibility
    val dataPatterns: List<FuzzDataPattern>,  // Data patterns to use
    val durationSeconds: Int?,         // Max duration (null = count-based)
    val stopOnError: Boolean = true,   // Stop on device error
    val stopOnDisconnect: Boolean = true,  // Stop on disconnect
    val capturePackets: Boolean = true,  // Capture packets
    val captureNotifications: Boolean = true  // Capture notifications
)

/**
 * Fuzzing methods.
 */
enum class FuzzMethod {
    BIT_FLIP,              // Flip individual bits
    BYTE_FLIP,             // Flip entire bytes
    RANDOM,                // Random bytes
    SEQUENTIAL,            // Sequential patterns
    LENGTH_FUZZING,        // Vary length (buffer overflow)
    BOUNDARY_CASE,         // Boundary values
    FORMAT_STRING,         // Format string patterns
    INJECTION,             // Injection patterns
    MUTATION,              // Mutate valid packets
    PROTOCOL_STATE,        // State machine abuse
    REPLAY,                // Replay captured packets
    DELAY                  // Timing-based fuzzing
}

/**
 * Fuzzing data patterns.
 */
data class FuzzDataPattern(
    val name: String,
    val description: String,
    val patternType: PatternType,
    val data: ByteArray,
    val length: Int = data.size
)

/**
 * Pattern types for fuzzing.
 */
enum class PatternType {
    MALFORMED,         // Malformed data
    OVERLONG,          // Excessively long data
    UNDERSIZED,        // Too short data
    NULL_BYTES,        // Contains null bytes
    SPECIAL_CHARS,     // Special characters
    EDGE_CASE,         // Boundary values
    RANDOM,            // Random data
    VALID_MUTATED,     // Valid data with mutations
    KNOWN_EXPLOIT      // Known exploit patterns
}

/**
 * Fuzzing test result.
 */
data class FuzzResult(
    val id: String,
    val config: FuzzConfig,
    val startTime: Instant,
    val endTime: Instant?,
    val status: FuzzStatus,
    val packetsSent: Int,
    val packetsReceived: Int,
    val errors: List<FuzzError>,
    val findings: List<FuzzFinding>,
    val captureFile: String?,          // Path to packet capture
    val reportGenerated: Boolean = false
) {
    /**
     * Get duration of fuzzing test.
     */
    fun getDuration(): java.time.Duration? {
        return if (endTime != null) {
            java.time.Duration.between(startTime, endTime)
        } else null
    }

    /**
     * Get success rate (received/sent * 100).
     */
    fun getSuccessRate(): Double {
        return if (packetsSent > 0) {
            (packetsReceived.toDouble() / packetsSent.toDouble()) * 100.0
        } else 0.0
    }
}

/**
 * Fuzzing status.
 */
enum class FuzzStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    STOPPED,
    ERROR
}

/**
 * Fuzzing error record.
 */
data class FuzzError(
    val timestamp: Instant,
    val packetNumber: Int,
    val errorCode: Int?,              // Android/error code
    val errorMessage: String,
    val severity: ErrorSeverity,
    val packetData: ByteArray? = null  // Problematic packet
)

/**
 * Error severity levels.
 */
enum class ErrorSeverity {
    CRITICAL,     // Device crashed/rebooted
    HIGH,         // Device disconnected/error state
    MEDIUM,       // Operation failed
    LOW,          // Non-fatal error
    INFO          // Informational
}

/**
 * Fuzzing finding (potential vulnerability).
 */
data class FuzzFinding(
    val timestamp: Instant,
    val packetNumber: Int,
    val description: String,
    val severity: VulnerabilitySeverity,
    val packetData: ByteArray?,
    val response: ByteArray?,
    val category: FindingCategory,
    val reproducible: Boolean = false,
    val additionalNotes: String? = null
)

/**
 * Finding categories from fuzzing.
 */
enum class FindingCategory {
    CRASH,              // Device/service crash
    HANG,               // Device/service hang
    MEMORY_CORRUPTION,  // Memory corruption detected
    UNEXPECTED_RESPONSE,  // Unexpected response
    NO_RESPONSE,        // No response (DoS)
    DELAYED_RESPONSE,   // Abnormally delayed response
    STATE_ERROR,        // State machine error
    BUFFER_OVERFLOW,    // Potential buffer overflow
    INFORMATION_LEAK,   // Information disclosure
    BYPASS              // Security bypass
}
