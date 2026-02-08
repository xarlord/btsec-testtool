/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject

/**
 * Use case for Bluetooth key extraction operations.
 *
 * Handles analysis and extraction of Bluetooth encryption keys.
 * ALL key extraction operations require explicit authorization and consent.
 *
 * WARNING: Key extraction is sensitive - all operations are logged.
 */
class KeyExtractionUseCase @Inject constructor(
    private val keyExtractionRepository: KeyExtractionRepository,
    private val authorizationUseCase: AuthorizationUseCase,
    private val consentRepository: ConsentRepository
) {

    /**
     * Extract a specific key type from a device.
     *
     * @param device Target device
     * @param keyType Type of key to extract
     * @param method Extraction method
     * @return Result of extraction start
     */
    suspend fun extractKey(
        device: BluetoothDevice,
        keyType: KeyType,
        method: ExtractionMethod
    ): KeyExtractionStartResult {
        // Verify authorization for key extraction
        val authResult = authorizationUseCase.requestActionAuthorization(
            TestAction.EXTRACT_KEYS,
            getDeviceInfo()
        )

        when (authResult) {
            is ActionAuthorizationResult.Authorized -> {
                // Check device in scope
                if (!authorizationUseCase.isTargetInScope(device.address)) {
                    return KeyExtractionStartResult.DeviceNotInScope
                }

                // Start extraction
                keyExtractionRepository.extractKey(device, keyType, method)
                return KeyExtractionStartResult.Started
            }
            is ActionAuthorizationResult.ConsentDenied -> {
                return KeyExtractionStartResult.ConsentRequired
            }
            else -> {
                return KeyExtractionStartResult.NotAuthorized
            }
        }
    }

    /**
     * Extract all possible keys from a device.
     *
     * @param device Target device
     * @return Result of extraction start
     */
    suspend fun extractAllKeys(device: BluetoothDevice): KeyExtractionStartResult {
        // Verify authorization for key extraction
        val authResult = authorizationUseCase.requestActionAuthorization(
            TestAction.EXTRACT_KEYS,
            getDeviceInfo()
        )

        when (authResult) {
            is ActionAuthorizationResult.Authorized -> {
                // Check device in scope
                if (!authorizationUseCase.isTargetInScope(device.address)) {
                    return KeyExtractionStartResult.DeviceNotInScope
                }

                // Start extraction
                keyExtractionRepository.extractAllKeys(device)
                return KeyExtractionStartResult.Started
            }
            is ActionAuthorizationResult.ConsentDenied -> {
                return KeyExtractionStartResult.ConsentRequired
            }
            else -> {
                return KeyExtractionStartResult.NotAuthorized
            }
        }
    }

    /**
     * Cancel current extraction.
     */
    suspend fun cancelExtraction(): Result<Unit> {
        return keyExtractionRepository.cancelExtraction()
    }

    /**
     * Get extraction status.
     */
    fun getExtractionStatus(): Flow<ExtractionStatus> {
        return keyExtractionRepository.getExtractionStatus()
    }

    /**
     * Get extraction progress.
     * Returns the extraction status which includes progress information.
     */
    fun getExtractionProgress(): Flow<ExtractionStatus> {
        return keyExtractionRepository.getExtractionStatus()
    }

    /**
     * Get all extraction results.
     */
    fun getAllExtractionResults(): Flow<List<KeyExtractionResult>> {
        return keyExtractionRepository.getAllExtractionResults()
    }

    /**
     * Get extraction results for a device.
     */
    fun getExtractionResultsForDevice(deviceAddress: String): Flow<List<KeyExtractionResult>> {
        return keyExtractionRepository.getExtractionResultsForDevice(deviceAddress)
    }

    /**
     * Get successful extractions only.
     */
    fun getSuccessfulExtractions(): Flow<List<KeyExtractionResult>> {
        return keyExtractionRepository.getSuccessfulExtractions()
    }

    /**
     * Get extractions by key type.
     */
    fun getExtractionsByKeyType(keyType: KeyType): Flow<List<KeyExtractionResult>> {
        return keyExtractionRepository.getExtractionResultsByKeyType(keyType)
    }

    /**
     * Analyze key security for a device.
     *
     * @param device Target device
     * @return Key security analysis
     */
    suspend fun analyzeKeySecurity(device: BluetoothDevice): KeySecurityAnalysis {
        // Verify authorization
        val authResult = authorizationUseCase.requestActionAuthorization(
            TestAction.EXTRACT_KEYS,
            getDeviceInfo()
        )

        return when (authResult) {
            is ActionAuthorizationResult.Authorized -> {
                if (!authorizationUseCase.isTargetInScope(device.address)) {
                    createAnalysisError("Device not in scope")
                } else {
                    keyExtractionRepository.analyzeKeySecurity(device)
                }
            }
            else -> {
                createAnalysisError("Authorization required")
            }
        }
    }

    /**
     * Check for weak keys on a device.
     *
     * @param device Target device
     * @return List of weak key findings
     */
    suspend fun checkForWeakKeys(device: BluetoothDevice): List<WeakKeyFinding> {
        // Verify authorization
        val authResult = authorizationUseCase.requestActionAuthorization(
            TestAction.EXTRACT_KEYS,
            getDeviceInfo()
        )

        return when (authResult) {
            is ActionAuthorizationResult.Authorized -> {
                if (authorizationUseCase.isTargetInScope(device.address)) {
                    keyExtractionRepository.checkForWeakKeys(device)
                } else {
                    emptyList()
                }
            }
            else -> {
                emptyList()
            }
        }
    }

    /**
     * Verify if an extracted key is valid.
     *
     * @param keyType Type of key
     * @param keyValue Key value
     * @param device Device the key belongs to
     * @return true if key is valid
     */
    suspend fun verifyKey(
        keyType: KeyType,
        keyValue: ByteArray,
        device: BluetoothDevice
    ): Boolean {
        return keyExtractionRepository.verifyKey(keyType, keyValue, device)
    }

    /**
     * Start monitoring for pairing traffic.
     *
     * @return Flow of captured key material
     */
    fun startPairingMonitor(): Flow<PairingCapture> {
        return keyExtractionRepository.startPairingMonitor()
    }

    /**
     * Stop pairing monitor.
     */
    suspend fun stopPairingMonitor(): Result<Unit> {
        return keyExtractionRepository.stopPairingMonitor()
    }

    /**
     * Get pairing monitor status.
     */
    fun isPairingMonitorActive(): Flow<Boolean> {
        return keyExtractionRepository.isPairingMonitorActive()
    }

    /**
     * Analyze encryption strength for a device.
     *
     * @param device Target device
     * @return Encryption analysis
     */
    suspend fun analyzeEncryptionStrength(device: BluetoothDevice): EncryptionAnalysis {
        // Verify authorization
        val authResult = authorizationUseCase.requestActionAuthorization(
            TestAction.SCAN_VULNERABILITIES,
            getDeviceInfo()
        )

        return when (authResult) {
            is ActionAuthorizationResult.Authorized -> {
                if (!authorizationUseCase.isTargetInScope(device.address)) {
                    createEncryptionError("Device not in scope")
                } else {
                    keyExtractionRepository.analyzeEncryptionStrength(device)
                }
            }
            else -> {
                createEncryptionError("Authorization required")
            }
        }
    }

    /**
     * Check if device supports Secure Connections.
     *
     * @param device Target device
     * @return true if LESC is supported
     */
    suspend fun supportsSecureConnections(device: BluetoothDevice): Boolean {
        // Verify authorization
        val authResult = authorizationUseCase.requestActionAuthorization(
            TestAction.SCAN_VULNERABILITIES,
            getDeviceInfo()
        )

        return when (authResult) {
            is ActionAuthorizationResult.Authorized -> {
                authorizationUseCase.isTargetInScope(device.address) &&
                keyExtractionRepository.supportsSecureConnections(device)
            }
            else -> {
                false
            }
        }
    }

    /**
     * Get key extraction statistics.
     */
    fun getKeyExtractionStatistics(): Flow<KeyExtractionStatistics> {
        return keyExtractionRepository.getKeyExtractionStatistics()
    }

    /**
     * Get device key summary.
     */
    suspend fun getDeviceKeySummary(deviceAddress: String): DeviceKeySummary {
        val extractions = keyExtractionRepository.getExtractionResultsForDevice(deviceAddress).first()
        val stats = keyExtractionRepository.getStatisticsForDevice(deviceAddress)

        return DeviceKeySummary(
            deviceAddress = deviceAddress,
            totalExtractions = stats.totalExtractions,
            successfulExtractions = stats.successfulExtractions,
            extractedKeyTypes = stats.extractedKeyTypes,
            lastExtractionDate = stats.lastExtractionDate,
            keysByType = extractions.filter { it.extracted }.groupBy { it.keyType }
                .mapValues { it.value.size }
        )
    }

    private fun createAnalysisError(message: String): KeySecurityAnalysis {
        return KeySecurityAnalysis(
            deviceAddress = "unknown",
            deviceName = null,
            analysisDate = java.time.Instant.now(),
            overallScore = SecurityScore.CRITICAL,
            findings = listOf(
                KeySecurityFinding(
                    severity = VulnerabilitySeverity.CRITICAL,
                    category = KeyFindingCategory.IMPLEMENTATION_FLAW,
                    description = message,
                    affectedKey = null,
                    recommendation = "Ensure proper authorization before key analysis"
                )
            ),
            extractedKeys = emptyList(),
            encryptionStrength = EncryptionStrength.UNKNOWN,
            recommendations = listOf(message)
        )
    }

    private fun createEncryptionError(message: String): EncryptionAnalysis {
        return EncryptionAnalysis(
            deviceAddress = "unknown",
            encryptionEnabled = false,
            encryptionKeySize = null,
            supportsSecureConnections = false,
            usingSecureConnections = false,
            pairingMethod = null,
            encryptionMode = EncryptionMode.UNKNOWN,
            findings = listOf(message)
        )
    }

    private fun getDeviceInfo(): DeviceInfo {
        return DeviceInfo(
            platform = android.os.Build.MANUFACTURER,
            model = android.os.Build.MODEL,
            androidVersion = android.os.Build.VERSION.RELEASE,
            appVersion = "1.0.0",
            bluetoothAddress = "TESTING"
        )
    }
}

/**
 * Result of key extraction start request.
 */
sealed class KeyExtractionStartResult {
    data object Started : KeyExtractionStartResult()
    data object ConsentRequired : KeyExtractionStartResult()
    data object NotAuthorized : KeyExtractionStartResult()
    data object DeviceNotInScope : KeyExtractionStartResult()
    data class Error(val message: String) : KeyExtractionStartResult()
}

/**
 * Device key summary.
 */
data class DeviceKeySummary(
    val deviceAddress: String,
    val totalExtractions: Int,
    val successfulExtractions: Int,
    val extractedKeyTypes: List<KeyType>,
    val lastExtractionDate: java.time.Instant,
    val keysByType: Map<KeyType, Int>
)
