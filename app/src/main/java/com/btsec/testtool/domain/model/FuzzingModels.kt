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
import java.time.Instant

/**
 * Fuzzing configuration.
 */
@Serializable
data class FuzzConfig(
    val targetDevice: BluetoothDevice,
    // Service to fuzz (null = all)
    val targetService: BleService? = null,
    // Characteristic to fuzz
    val targetCharacteristic: BleCharacteristic? = null,
    // Fuzzing strategy
    val fuzzMethod: FuzzMethod = FuzzMethod.RANDOM,
    // Number of packets to send
    val packetCount: Int = 100,
    // Rate limiting
    val packetsPerSecond: Int = 10,
    // Seed for reproducibility
    val randomSeed: Long? = null,
    // Data patterns to use
    val dataPatterns: List<FuzzDataPattern> = emptyList(),
    // Max duration (null = count-based)
    val durationSeconds: Int? = null,
    // Stop on device error
    val stopOnError: Boolean = true,
    // Stop on disconnect
    val stopOnDisconnect: Boolean = true,
    // Capture packets
    val capturePackets: Boolean = true,
    // Capture notifications
    val captureNotifications: Boolean = true,
)

/**
 * Fuzzing methods.
 */
@Serializable
enum class FuzzMethod {
    BIT_FLIP, // Flip individual bits
    BYTE_FLIP, // Flip entire bytes
    RANDOM, // Random bytes
    SEQUENTIAL, // Sequential patterns
    LENGTH_FUZZING, // Vary length (buffer overflow)
    BOUNDARY_CASE, // Boundary values
    FORMAT_STRING, // Format string patterns
    INJECTION, // Injection patterns
    MUTATION, // Mutate valid packets
    PROTOCOL_STATE, // State machine abuse
    REPLAY, // Replay captured packets
    DELAY, // Timing-based fuzzing
}

/**
 * Fuzzing data patterns.
 */
@Serializable
data class FuzzDataPattern(
    val name: String,
    val description: String,
    val patternType: PatternType = PatternType.RANDOM,
    val data: ByteArray = byteArrayOf(),
    val length: Int = data.size,
)

/**
 * Pattern types for fuzzing.
 */
@Serializable
enum class PatternType {
    MALFORMED, // Malformed data
    OVERLONG, // Excessively long data
    UNDERSIZED, // Too short data
    NULL_BYTES, // Contains null bytes
    SPECIAL_CHARS, // Special characters
    EDGE_CASE, // Boundary values
    RANDOM, // Random data
    VALID_MUTATED, // Valid data with mutations
    KNOWN_EXPLOIT, // Known exploit patterns
}

/**
 * Fuzzing test result.
 */
@Serializable
data class FuzzResult(
    val id: String,
    val config: FuzzConfig,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val startTime: Instant,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val endTime: Instant? = null,
    val status: FuzzStatus = FuzzStatus.PENDING,
    val packetsSent: Int = 0,
    val packetsReceived: Int = 0,
    val errors: List<FuzzError> = emptyList(),
    val findings: List<FuzzFinding> = emptyList(),
    // Path to packet capture
    val captureFile: String? = null,
    val reportGenerated: Boolean = false,
) {
    /**
     * Get duration of fuzzing test.
     */
    fun getDuration(): java.time.Duration? {
        return if (endTime != null) {
            java.time.Duration.between(startTime, endTime)
        } else {
            null
        }
    }

    /**
     * Get success rate (received/sent * 100).
     */
    fun getSuccessRate(): Double {
        return if (packetsSent > 0) {
            (packetsReceived.toDouble() / packetsSent.toDouble()) * 100.0
        } else {
            0.0
        }
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
    ERROR,
}

/**
 * Fuzzing error record.
 */
@Serializable
data class FuzzError(
    @Serializable(with = InstantAsEpochMillisSerializer::class) val timestamp: Instant,
    val packetNumber: Int = 0,
    // Android/error code
    val errorCode: Int? = null,
    val errorMessage: String = "",
    val severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    // Problematic packet
    val packetData: ByteArray? = null,
)

/**
 * Error severity levels.
 */
@Serializable
enum class ErrorSeverity {
    CRITICAL, // Device crashed/rebooted
    HIGH, // Device disconnected/error state
    MEDIUM, // Operation failed
    LOW, // Non-fatal error
    INFO, // Informational
}

/**
 * Fuzzing finding (potential vulnerability).
 */
@Serializable
data class FuzzFinding(
    @Serializable(with = InstantAsEpochMillisSerializer::class) val timestamp: Instant,
    val packetNumber: Int = 0,
    val description: String = "",
    val severity: VulnerabilitySeverity = VulnerabilitySeverity.LOW,
    val packetData: ByteArray? = null,
    val response: ByteArray? = null,
    val category: FindingCategory = FindingCategory.UNEXPECTED_RESPONSE,
    val reproducible: Boolean = false,
    val additionalNotes: String? = null,
)

/**
 * Finding categories from fuzzing.
 */
@Serializable
enum class FindingCategory {
    CRASH, // Device/service crash
    HANG, // Device/service hang
    MEMORY_CORRUPTION, // Memory corruption detected
    UNEXPECTED_RESPONSE, // Unexpected response
    NO_RESPONSE, // No response (DoS)
    DELAYED_RESPONSE, // Abnormally delayed response
    STATE_ERROR, // State machine error
    BUFFER_OVERFLOW, // Potential buffer overflow
    INFORMATION_LEAK, // Information disclosure
    BYPASS, // Security bypass
}

/**
 * Structured fuzzing pattern for profile-specific (HFP, etc.) injection testing.
 *
 * Describes a named, categorized fuzzing payload with an associated severity,
 * human-readable description, concrete payload strings, and optional CVE
 * references. Used by [com.btsec.testtool.data.fuzzing.HfpFuzzingPatterns].
 */
data class FuzzingPattern(
    val id: String,
    val name: String,
    val category: FuzzingCategory,
    val severity: FuzzingSeverity,
    val description: String,
    val payloads: List<String>,
    val cveReferences: List<String> = emptyList(),
)

/**
 * Categories of structured fuzzing patterns.
 *
 * Each entry targets a distinct class of vulnerability that may be present in
 * a Bluetooth profile parser (e.g. HFP AT-command handler).
 */
enum class FuzzingCategory {
    AT_INJECTION,
    BUFFER_OVERFLOW,
    COMMAND_INJECTION,
    INTEGER_OVERFLOW,
    HFP_COMMAND,
    FORMAT_STRING,
}

/**
 * Severity levels for structured fuzzing patterns.
 */
enum class FuzzingSeverity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
}
