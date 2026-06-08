/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.time.Instant

/** Serializer for java.time.Instant as epoch milliseconds (Long). */
object InstantAsEpochMillisSerializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Instant", PrimitiveKind.LONG)
    override fun serialize(encoder: Encoder, value: Instant) = encoder.encodeLong(value.toEpochMilli())
    override fun deserialize(decoder: Decoder): Instant = Instant.ofEpochMilli(decoder.decodeLong())
}

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
@Serializable
data class Authorization(
    val authId: String,
    val issuedTo: String,
    val issuedBy: String,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val issuedAt: Instant,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val expiresAt: Instant,
    val authorizedActions: Set<TestAction> = emptySet(),
    val scope: TestScope,
    val signature: String,
    val terms: List<String> = emptyList()
)

/**
 * Types of testing actions that can be authorized.
 */
@Serializable
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
@Serializable
data class TestScope(
    val authId: String,
    val authorizedTargets: List<TargetDevice> = emptyList(),
    val allowedActions: Set<TestAction> = emptySet(),
    @Serializable(with = InstantAsEpochMillisSerializer::class) val validFrom: Instant,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val validUntil: Instant,
    val maxPacketsPerSecond: Int = 100,
    val requiresReport: Boolean = true,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val disclosureDeadline: Instant,
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
@Serializable
data class TargetDevice(
    val identifier: String,      // MAC address or pattern
    val deviceType: DeviceType = DeviceType.UNKNOWN,
    val owner: String? = null,
    val location: String? = null,
    val notes: String? = null
)

/**
 * Device types for testing classification.
 */
@Serializable
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
@Serializable
data class ConsentRecord(
    val id: String,
    val authId: String,
    val action: String,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val timestamp: Instant,
    val authorized: Boolean,
    val deviceInfo: DeviceInfo,
    val userSignature: String? = null
)

/**
 * Device information for logging.
 */
@Serializable
data class DeviceInfo(
    val platform: String,
    val model: String,
    val androidVersion: String,
    val appVersion: String,
    val bluetoothAddress: String
)
