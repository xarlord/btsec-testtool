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
 * Write-only interface for Bluetooth key extraction operations.
 *
 * Provides mutation methods for starting/stopping extractions,
 * saving results, managing passive monitoring, updating the key
 * database, and writing audit logs.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only write/mutation operations, allowing clients that only
 * need to trigger or modify extraction state to depend on a narrower
 * contract.
 *
 * All operations require explicit authorization.
 */
interface KeyExtractionWriter {
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
        method: ExtractionMethod,
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
     * Save an extraction result.
     * Keys are encrypted before storage.
     */
    suspend fun saveExtractionResult(result: KeyExtractionResult): Result<Unit>

    /**
     * Delete an extraction result.
     */
    suspend fun deleteExtractionResult(id: String): Result<Unit>

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
     * Add a key to the extracted key database.
     */
    suspend fun addToKeyDatabase(
        deviceAddress: String,
        keyType: KeyType,
        keyValue: ByteArray,
    ): Result<Unit>

    /**
     * Log a key extraction operation for audit purposes.
     */
    suspend fun logExtractionOperation(operation: KeyExtractionOperation)
}
