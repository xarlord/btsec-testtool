/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.Contextual
import java.time.Instant

/**
 * Fuzzing configuration.
 */
@Serializable
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
@Serializable
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
@Serializable
data class FuzzDataPattern(
    val name: String,
    val description: String,
    val patternType: PatternType,
    @Serializable(with = ByteArraySerializer::class)
    val data: ByteArray,
    val length: Int = data.size
)

/**
 * Pattern types for fuzzing.
 */
@Serializable
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
@Serializable
data class FuzzResult(
    val id: String,
    val config: FuzzConfig,
    @Serializable(with = InstantSerializer::class)
    val startTime: @Contextual Instant,
    @Serializable(with = InstantSerializer::class)
    val endTime: @Contextual Instant?,
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
@Serializable
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
@Serializable
data class FuzzError(
    @Serializable(with = InstantSerializer::class)
    val timestamp: @Contextual Instant,
    val packetNumber: Int,
    val errorCode: Int?,              // Android/error code
    val errorMessage: String,
    val severity: ErrorSeverity,
    @Serializable(with = ByteArraySerializer::class)
    val packetData: ByteArray? = null  // Problematic packet
)

/**
 * Error severity levels.
 */
@Serializable
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
@Serializable
data class FuzzFinding(
    @Serializable(with = InstantSerializer::class)
    val timestamp: @Contextual Instant,
    val packetNumber: Int,
    val description: String,
    val severity: VulnerabilitySeverity,
    @Serializable(with = ByteArraySerializer::class)
    val packetData: ByteArray?,
    @Serializable(with = ByteArraySerializer::class)
    val response: ByteArray?,
    val category: FindingCategory,
    val reproducible: Boolean = false,
    val additionalNotes: String? = null
)

/**
 * Finding categories from fuzzing.
 */
@Serializable
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
