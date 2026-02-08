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
 * Repository for Bluetooth key extraction operations.
 *
 * Handles analysis and extraction of Bluetooth encryption keys.
 * This is for authorized security testing only.
 *
 * Supported key types:
 * - LTK (Long Term Key) - BLE encryption key
 * - IRK (Identity Resolving Key) - BLE privacy key
 * - CSRK (Connection Signature Resolving Key) - BLE signing key
 * - Link Key - Classic Bluetooth pairing key
 *
 * All operations require explicit authorization.
 */
interface KeyExtractionRepository {

    // ========== Key Extraction Operations ==========

    /**
     * Attempt to extract a specific key type from a device.
     *
     * @param device Target device
     * @param keyType Type of key to extract
     * @param method Extraction method to use
     * @return Flow of extraction progress updates
     */
    fun extractKey(
        device: BluetoothDevice,
        keyType: KeyType,
        method: ExtractionMethod
    ): Flow<ExtractionProgress>

    /**
     * Attempt to extract all possible keys from a device.
     *
     * @param device Target device
     * @return Flow of extraction progress updates for each key type
     */
    fun extractAllKeys(device: BluetoothDevice): Flow<ExtractionProgress>

    /**
     * Cancel the current extraction operation.
     */
    suspend fun cancelExtraction(): Result<Unit>

    /**
     * Get current extraction status.
     */
    fun getExtractionStatus(): Flow<ExtractionStatus>

    // ========== Key Extraction Results ==========

    /**
     * Save an extraction result.
     * Keys are encrypted before storage.
     */
    suspend fun saveExtractionResult(result: KeyExtractionResult): Result<Unit>

    /**
     * Get extraction result by ID.
     */
    suspend fun getExtractionResult(id: String): KeyExtractionResult?

    /**
     * Get all extraction results.
     */
    fun getAllExtractionResults(): Flow<List<KeyExtractionResult>>

    /**
     * Get extraction results for a specific device.
     */
    fun getExtractionResultsForDevice(deviceAddress: String): Flow<List<KeyExtractionResult>>

    /**
     * Get extraction results by key type.
     */
    fun getExtractionResultsByKeyType(keyType: KeyType): Flow<List<KeyExtractionResult>>

    /**
     * Get successful extractions only.
     */
    fun getSuccessfulExtractions(): Flow<List<KeyExtractionResult>>

    /**
     * Delete an extraction result.
     */
    suspend fun deleteExtractionResult(id: String): Result<Unit>

    // ========== Key Analysis ==========

    /**
     * Analyze a device's key security posture.
     *
     * @param device Target device
     * @return Key security analysis
     */
    suspend fun analyzeKeySecurity(device: BluetoothDevice): KeySecurityAnalysis

    /**
     * Check if a device uses known weak keys.
     *
     * @param device Target device
     * @return List of weak key findings
     */
    suspend fun checkForWeakKeys(device: BluetoothDevice): List<WeakKeyFinding>

    /**
     * Verify if an extracted key is valid.
     *
     * @param keyType Type of key
     * @param keyValue Key value to verify
     * @param device Device the key belongs to
     * @return true if key is valid
     */
    suspend fun verifyKey(
        keyType: KeyType,
        keyValue: ByteArray,
        device: BluetoothDevice
    ): Boolean

    /**
     * Derive additional keys from extracted key material.
     *
     * @param extractedKey Already extracted key
     * @param targetKeyType Type of key to derive
     * @return Derived key or null if not possible
     */
    suspend fun deriveKey(
        extractedKey: KeyExtractionResult,
        targetKeyType: KeyType
    ): ByteArray?

    // ========== Passive Monitoring ==========

    /**
     * Start monitoring for pairing traffic to capture keys.
     *
     * This passively monitors Bluetooth pairing to capture
     * key exchange traffic for analysis.
     *
     * @return Flow of captured key material
     */
    fun startPairingMonitor(): Flow<PairingCapture>

    /**
     * Stop pairing monitoring.
     */
    suspend fun stopPairingMonitor(): Result<Unit>

    /**
     * Get pairing monitor status.
     */
    fun isPairingMonitorActive(): Flow<Boolean>

    // ========== Key Databases ==========

    /**
     * Check if a key matches known default/test keys.
     *
     * @param keyType Type of key
     * @param keyValue Key value to check
     * @return true if key matches a known default
     */
    suspend fun isKnownDefaultKey(keyType: KeyType, keyValue: ByteArray): Boolean

    /**
     * Get information about a known default key.
     */
    suspend fun getDefaultKeyInfo(keyValue: ByteArray): DefaultKeyInfo?

    /**
     * Add a key to the extracted key database.
     */
    suspend fun addToKeyDatabase(deviceAddress: String, keyType: KeyType, keyValue: ByteArray): Result<Unit>

    /**
     * Look up a device's key in the database.
     */
    suspend fun lookupKeyInDatabase(deviceAddress: String, keyType: KeyType): ByteArray?

    // ========== Encryption Analysis ==========

    /**
     * Analyze BLE encryption strength.
     *
     * @param device Target device
     * @return Encryption analysis
     */
    suspend fun analyzeEncryptionStrength(device: BluetoothDevice): EncryptionAnalysis

    /**
     * Test if device supports Secure Connections (LESC).
     *
     * @param device Target device
     * @return true if LESC is supported
     */
    suspend fun supportsSecureConnections(device: BluetoothDevice): Boolean

    /**
     * Get the encryption key size for a device.
     *
     * @param device Target device
     * @return Key size in bits (typically 128)
     */
    suspend fun getEncryptionKeySize(device: BluetoothDevice): Int?

    // ========== Statistics ==========

    /**
     * Get key extraction statistics.
     */
    fun getKeyExtractionStatistics(): Flow<KeyExtractionStatistics>

    /**
     * Get statistics for a specific device.
     */
    suspend fun getStatisticsForDevice(deviceAddress: String): DeviceKeyStatistics

    // ========== Logging ==========

    /**
     * Log a key extraction operation for audit purposes.
     */
    suspend fun logExtractionOperation(operation: KeyExtractionOperation)

    /**
     * Get extraction operation logs.
     */
    fun getExtractionLogs(): Flow<List<KeyExtractionOperation>>
}

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
    val error: String? = null
)

/**
 * Extraction status enumeration.
 */
enum class ExtractionStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED
}

/**
 * Extraction step enumeration.
 */
enum class ExtractionStep {
    INITIALIZING,
    CONNECTING,
    MONITORING,
    ANALYZING,
    EXTRACTING,
    VERIFYING,
    COMPLETED
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
    val recommendations: List<String>
)

/**
 * Security score levels.
 */
enum class SecurityScore {
    EXCELLENT,
    GOOD,
    FAIR,
    POOR,
    CRITICAL
}

/**
 * Encryption strength levels.
 */
enum class EncryptionStrength {
    NONE,           // No encryption
    WEAK,           // Weak encryption (e.g., short keys)
    STANDARD,       // Standard encryption (128-bit)
    STRONG,         // Strong encryption (with additional security)
    UNKNOWN         // Could not determine
}

/**
 * Key security finding.
 */
data class KeySecurityFinding(
    val severity: VulnerabilitySeverity,
    val category: KeyFindingCategory,
    val description: String,
    val affectedKey: KeyType?,
    val recommendation: String
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
    SHORT_KEY_LENGTH
}

/**
 * Weak key finding.
 */
data class WeakKeyFinding(
    val keyType: KeyType,
    val weaknessType: WeaknessType,
    val description: String,
    val severity: VulnerabilitySeverity
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
    IMPLEMENTATION_BUG
}

/**
 * Default key information.
 */
data class DefaultKeyInfo(
    val keyType: KeyType,
    val vendor: String,
    val deviceModel: String,
    val description: String,
    val reference: String?
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
    val encryptionKeySize: Int?
)

/**
 * Pairing methods.
 */
enum class PairingMethod {
    LEGACY_PAIRING,      // Legacy pairing (vulnerable)
    SECURE_CONNECTIONS,  // LE Secure Connections (secure)
    JUST_WORKS,          // Just Works (no authentication)
    PASSKEY_ENTRY,       // Passkey entry
    OOB,                 // Out of Band
    NUMERIC_COMPARISON   // Numeric comparison
}

/**
 * Captured key material.
 */
data class CapturedKeyMaterial(
    val keyType: KeyType,
    val captured: Boolean,
    val confidence: ExtractionConfidence,
    val data: ByteArray?,
    val notes: String? = null
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
    val findings: List<String>
)

/**
 * Encryption modes.
 */
enum class EncryptionMode {
    NONE,
    LEGACY,
    SECURE_CONNECTIONS,
    UNKNOWN
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
    val dateRange: DateRange
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
    val lastExtractionDate: java.time.Instant
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
    val metadata: Map<String, String> = emptyMap()
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
    VERIFY_KEY
}
