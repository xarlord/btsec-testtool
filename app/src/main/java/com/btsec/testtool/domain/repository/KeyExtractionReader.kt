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
import kotlinx.coroutines.flow.Flow

/**
 * Read-only interface for Bluetooth key extraction operations.
 *
 * Provides query and observation methods for extraction results,
 * key analysis, monitoring status, statistics, and audit logs.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only read operations, allowing clients that only need to
 * observe extraction state to depend on a narrower contract.
 *
 * Supported key types:
 * - LTK (Long Term Key) - BLE encryption key
 * - IRK (Identity Resolving Key) - BLE privacy key
 * - CSRK (Connection Signature Resolving Key) - BLE signing key
 * - Link Key - Classic Bluetooth pairing key
 *
 * All operations require explicit authorization.
 */
interface KeyExtractionReader {
    /**
     * Get current extraction status.
     */
    fun getExtractionStatus(): Flow<ExtractionStatus>

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
        device: BluetoothDevice,
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
        targetKeyType: KeyType,
    ): ByteArray?

    /**
     * Get pairing monitor status.
     */
    fun isPairingMonitorActive(): Flow<Boolean>

    /**
     * Check if a key matches known default/test keys.
     *
     * @param keyType Type of key
     * @param keyValue Key value to check
     * @return true if key matches a known default
     */
    suspend fun isKnownDefaultKey(
        keyType: KeyType,
        keyValue: ByteArray,
    ): Boolean

    /**
     * Get information about a known default key.
     */
    suspend fun getDefaultKeyInfo(keyValue: ByteArray): DefaultKeyInfo?

    /**
     * Look up a device's key in the database.
     */
    suspend fun lookupKeyInDatabase(
        deviceAddress: String,
        keyType: KeyType,
    ): ByteArray?

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

    /**
     * Get key extraction statistics.
     */
    fun getKeyExtractionStatistics(): Flow<KeyExtractionStatistics>

    /**
     * Get statistics for a specific device.
     */
    suspend fun getStatisticsForDevice(deviceAddress: String): DeviceKeyStatistics

    /**
     * Get extraction operation logs.
     */
    fun getExtractionLogs(): Flow<List<KeyExtractionOperation>>
}
