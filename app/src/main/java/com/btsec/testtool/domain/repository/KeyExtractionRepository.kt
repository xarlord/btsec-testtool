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

/**
 * Composite repository for Bluetooth key extraction operations.
 *
 * Extends [KeyExtractionReader] and [KeyExtractionWriter] to provide the full
 * set of key extraction capabilities while adhering to the Interface
 * Segregation Principle (ISP). Existing implementations remain compatible
 * since this interface inherits all methods from its parent interfaces.
 *
 * Handles analysis and extraction of Bluetooth encryption keys.
 * This is for AUTHORIZED security testing only.
 *
 * Supported key types:
 * - LTK (Long Term Key) - BLE encryption key
 * - IRK (Identity Resolving Key) - BLE privacy key
 * - CSRK (Connection Signature Resolving Key) - BLE signing key
 * - Link Key - Classic Bluetooth pairing key
 *
 * All operations require explicit authorization.
 *
 * @see KeyExtractionReader
 * @see KeyExtractionWriter
 */
interface KeyExtractionRepository : KeyExtractionReader, KeyExtractionWriter

/**
 * Key extraction progress information.
 */
data class ExtractionProgress(
    val extractionId: String,
    val targetDevice: BluetoothDevice,
    val keyType: KeyType,
    val method: ExtractionMethod,
    val status: ExtractionStatus,
    val progressPercentage: Int,
    val currentStep: ExtractionStep,
    val estimatedCompletionTime: java.time.Instant?,
    val error: String? = null,
)

/**
 * Extraction status enumeration.
 */
enum class ExtractionStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED,
}

/**
 * Extraction step enumeration.
 */
enum class ExtractionStep {
    INITIALIZING,
    CONNECTING,
    NEGOTIATING,
    MONITORING,
    ANALYZING,
    EXTRACTING,
    VERIFYING,
    COMPLETED,
}

/**
 * Key security analysis result.
 */
data class KeySecurityAnalysis(
    val deviceAddress: String,
    val deviceName: String?,
    val analysisDate: java.time.Instant,
    val overallScore: SecurityScore,
    val findings: List<KeySecurityFinding>,
    val extractedKeys: List<KeyType>,
    val encryptionStrength: EncryptionStrength,
    val recommendations: List<String>,
)

/**
 * Security score levels.
 */
enum class SecurityScore {
    EXCELLENT,
    GOOD,
    FAIR,
    POOR,
    CRITICAL,
}

/**
 * Encryption strength levels.
 */
enum class EncryptionStrength {
    NONE, // No encryption
    WEAK, // Weak encryption (e.g., short keys)
    STANDARD, // Standard encryption (128-bit)
    STRONG, // Strong encryption (with additional security)
    UNKNOWN, // Could not determine
}

/**
 * Key security finding.
 */
data class KeySecurityFinding(
    val severity: VulnerabilitySeverity,
    val category: KeyFindingCategory,
    val description: String,
    val affectedKey: KeyType?,
    val recommendation: String,
)

/**
 * Key finding categories.
 */
enum class KeyFindingCategory {
    WEAK_ENCRYPTION,
    DEFAULT_KEY,
    REUSED_KEY,
    KEY_EXPOSURE,
    PROTOCOL_WEAKNESS,
    IMPLEMENTATION_FLAW,
    MISSING_SECURE_CONNECTIONS,
    SHORT_KEY_LENGTH,
}

/**
 * Weak key finding.
 */
data class WeakKeyFinding(
    val keyType: KeyType,
    val weaknessType: WeaknessType,
    val description: String,
    val severity: VulnerabilitySeverity,
)

/**
 * Types of key weaknesses.
 */
enum class WeaknessType {
    DEFAULT_KEY,
    SHORT_LENGTH,
    LOW_ENTROPY,
    PREDICTABLE_PATTERN,
    REUSED_ACROSS_DEVICES,
    KNOWN_COMPROMISED,
    IMPLEMENTATION_BUG,
}

/**
 * Default key information.
 */
data class DefaultKeyInfo(
    val keyType: KeyType,
    val vendor: String,
    val deviceModel: String,
    val description: String,
    val reference: String?,
)

/**
 * Pairing capture from passive monitoring.
 */
data class PairingCapture(
    val id: String,
    val timestamp: java.time.Instant,
    val deviceAddress: String,
    val pairingMethod: PairingMethod,
    val capturedKeyMaterial: List<CapturedKeyMaterial>,
    val secureConnection: Boolean,
    val encryptionKeySize: Int?,
)

/**
 * Pairing methods.
 */
enum class PairingMethod {
    LEGACY_PAIRING, // Legacy pairing (vulnerable)
    SECURE_CONNECTIONS, // LE Secure Connections (secure)
    JUST_WORKS, // Just Works (no authentication)
    PASSKEY_ENTRY, // Passkey entry
    OOB, // Out of Band
    NUMERIC_COMPARISON, // Numeric comparison
}

/**
 * Captured key material.
 */
data class CapturedKeyMaterial(
    val keyType: KeyType,
    val captured: Boolean,
    val confidence: ExtractionConfidence,
    val data: ByteArray?,
    val notes: String? = null,
)

/**
 * Encryption analysis result.
 */
data class EncryptionAnalysis(
    val deviceAddress: String,
    val encryptionEnabled: Boolean,
    val encryptionKeySize: Int?,
    val supportsSecureConnections: Boolean,
    val usingSecureConnections: Boolean,
    val pairingMethod: PairingMethod?,
    val encryptionMode: EncryptionMode?,
    val findings: List<String>,
)

/**
 * Encryption modes.
 */
enum class EncryptionMode {
    NONE,
    LEGACY,
    SECURE_CONNECTIONS,
    UNKNOWN,
}

/**
 * Key extraction statistics.
 */
data class KeyExtractionStatistics(
    val totalExtractions: Int,
    val successfulExtractions: Int,
    val failedExtractions: Int,
    val successRate: Double,
    val extractionsByType: Map<KeyType, Int>,
    val extractionsByMethod: Map<ExtractionMethod, Int>,
    val mostExtractedDevice: String?,
    val dateRange: DateRange,
)

/**
 * Device-specific key statistics.
 */
data class DeviceKeyStatistics(
    val deviceAddress: String,
    val deviceName: String?,
    val totalExtractions: Int,
    val successfulExtractions: Int,
    val extractedKeyTypes: List<KeyType>,
    val lastExtractionDate: java.time.Instant,
)

/**
 * Key extraction operation log entry.
 */
data class KeyExtractionOperation(
    val id: String,
    val timestamp: java.time.Instant,
    val operationType: ExtractionOperationType,
    val targetDevice: String,
    val keyType: KeyType?,
    val method: ExtractionMethod?,
    val success: Boolean,
    val errorMessage: String?,
    val durationMs: Long?,
    val metadata: Map<String, String> = emptyMap(),
)

/**
 * Key extraction operation types.
 */
enum class ExtractionOperationType {
    START,
    CANCEL,
    COMPLETE,
    FAIL,
    PAIRING_CAPTURE,
    KEY_FOUND,
    SAVE_RESULT,
    VERIFY_KEY,
}
