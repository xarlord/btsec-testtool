/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

/**
 * HFP (Hands-Free Profile) security testing models.
 *
 * These models support AT command injection testing, call manipulation
 * detection, and vulnerability assessment for Bluetooth HFP connections.
 * All testing requires explicit authorization.
 */

/**
 * Categories of HFP security tests.
 */
enum class HfpTestCategory(val description: String) {
    CALL_MANIPULATION("Can originate/hangup calls"),
    AUDIO_ROUTING("Can route audio without consent"),
    FORMAT_STRING("Format string vulnerabilities"),
    BUFFER_OVERFLOW("Buffer overflow via oversized AT commands"),
    INFORMATION_DISCLOSURE("Device info, network, signal leak"),
    PHONEBOOK_ACCESS("Phonebook read without auth"),
    SMS_ACCESS("SMS read/send without auth"),
    AUTHENTICATION_BYPASS("Connect to HFP without pairing"),
    DOS("Denial of service (call flood, audio hog)"),
    INJECTION("Command injection / chaining"),
}

/**
 * Severity levels for HFP test findings.
 */
enum class HfpSeverity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
}

/**
 * Result of a single HFP security test.
 */
data class HfpTestResult(
    val category: HfpTestCategory,
    val testName: String,
    val command: String,
    val response: String?,
    val vulnerable: Boolean,
    // 0.0-1.0
    val confidence: Double,
    val evidence: String,
    val severity: HfpSeverity,
    val recommendation: String,
)

/**
 * Complete HFP test suite result for a device.
 */
data class HfpTestSuite(
    val deviceAddress: String,
    val deviceName: String?,
    val results: List<HfpTestResult>,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val infoCount: Int,
    val overallRisk: HfpSeverity,
    val testDurationMs: Long,
)

/**
 * Current call state observed on the HFP connection.
 */
data class HfpCallState(
    val hasActiveCall: Boolean,
    val callNumber: String?,
    // "incoming", "outgoing", "missed"
    val callType: String?,
    val callDuration: Int?,
)
