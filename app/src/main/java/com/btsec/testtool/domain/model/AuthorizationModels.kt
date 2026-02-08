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
 * Represents authorization for security testing.
 *
 * This is the core authorization model that grants permission
 * to perform security testing on specific targets within defined scope.
 *
 * @property authId Unique identifier (format: BTSEC-YYYYMMDD-XXXXXXXX)
 * @property issuedTo Person or organization authorized to test
 * @property issuedBy Organization issuing the authorization
 * @property issuedAt Date when authorization was issued
 * @property expiresAt Date when authorization expires
 * @property authorizedActions Set of actions permitted
 * @property scope Testing scope definition
 * @property signature Digital signature for verification
 */
data class Authorization(
    val authId: String,
    val issuedTo: String,
    val issuedBy: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val authorizedActions: Set<TestAction>,
    val scope: TestScope,
    val signature: String,
    val terms: List<String> = emptyList()
)

/**
 * Types of testing actions that can be authorized.
 */
enum class TestAction {
    SCAN_DEVICES,
    CONNECT_DEVICE,
    START_FUZZING,
    EXTRACT_KEYS,
    SCAN_VULNERABILITIES,
    GENERATE_REPORT,
    EXPORT_DATA,
    PACKET_CAPTURE
}

/**
 * Testing scope definition.
 *
 * Defines what targets may be tested, what actions are allowed,
 * and time/other constraints.
 */
data class TestScope(
    val authId: String,
    val authorizedTargets: List<TargetDevice>,
    val allowedActions: Set<TestAction>,
    val validFrom: Instant,
    val validUntil: Instant,
    val maxPacketsPerSecond: Int = 100,
    val requiresReport: Boolean = true,
    val disclosureDeadline: Instant,
    val locationConstraints: String? = null,
    val requiresSupervision: Boolean = false,
    val excludedTargets: List<String> = emptyList()
) {
    /**
     * Check if a target device is within scope.
     */
    fun isTargetInScope(target: TargetDevice): Boolean {
        return authorizedTargets.any { authorizedTarget ->
            matchesPattern(authorizedTarget.identifier, target.identifier)
        }
    }

    /**
     * Check if an action is allowed within this scope.
     */
    fun isActionAllowed(action: TestAction): Boolean {
        return allowedActions.contains(action)
    }

    /**
     * Check if current time is within the valid window.
     */
    fun isWithinValidWindow(): Boolean {
        val now = Instant.now()
        return now in validFrom..validUntil
    }

    private fun matchesPattern(pattern: String, target: String): Boolean {
        // Support wildcard patterns
        return when {
            pattern.endsWith("*") -> {
                val prefix = pattern.dropLast(1)
                target.startsWith(prefix)
            }
            pattern.contains("?") -> {
                // Simple wildcard matching
                val regex = pattern.replace("?", ".")
                target.matches(Regex(regex))
            }
            else -> target == pattern
        }
    }
}

/**
 * Represents a target device for testing.
 */
data class TargetDevice(
    val identifier: String,      // MAC address or pattern
    val deviceType: DeviceType,
    val owner: String?,
    val location: String?,
    val notes: String? = null
)

/**
 * Device types for testing classification.
 */
enum class DeviceType {
    PHONE,
    TABLET,
    COMPUTER,
    AUDIO_DEVICE,
    WEARABLE,
    VEHICLE,
    IOT_DEVICE,
    UNKNOWN
}

/**
 * Consent record for tracking user consent.
 */
data class ConsentRecord(
    val id: String,
    val authId: String,
    val action: String,
    val timestamp: Instant,
    val authorized: Boolean,
    val deviceInfo: DeviceInfo,
    val userSignature: String? = null
)

/**
 * Device information for logging.
 */
data class DeviceInfo(
    val platform: String,
    val model: String,
    val androidVersion: String,
    val appVersion: String,
    val bluetoothAddress: String
)
