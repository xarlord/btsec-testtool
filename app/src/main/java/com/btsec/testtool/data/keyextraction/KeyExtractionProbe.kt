/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.keyextraction

/**
 * Probe interface for performing real BLE key negotiation testing (KNOB attack).
 *
 * Implementations connect to a target device via BLE and attempt to negotiate
 * low-entropy encryption keys to detect KNOB vulnerability.
 *
 * This interface is for AUTHORIZED security testing only.
 */
interface KeyExtractionProbe {
    /**
     * Attempt to negotiate encryption with the specified key size (bytes).
     * Returns the negotiation result indicating acceptance, rejection, or error.
     */
    suspend fun negotiateKeySize(keySizeBytes: Int): KeyNegotiationResult

    /**
     * Read a GATT characteristic value.
     * Returns the characteristic bytes on success, or null on failure.
     */
    suspend fun readCharacteristic(
        serviceUuid: String,
        charUuid: String,
    ): ByteArray?

    /**
     * Get the current connection encryption info, or null if not connected.
     */
    fun getEncryptionInfo(): EncryptionInfo?

    /**
     * Check if the device is currently bonded.
     */
    fun isBonded(): Boolean

    /**
     * Release resources held by this probe.
     */
    fun close()
}

/**
 * Result of a key size negotiation attempt.
 */
sealed class KeyNegotiationResult {
    /** The device accepted the proposed key size. */
    data class Accepted(val acceptedKeySize: Int) : KeyNegotiationResult()

    /** The device rejected the proposed key size and reports its minimum. */
    data class Rejected(val minimumKeySize: Int) : KeyNegotiationResult()

    /** An error occurred during negotiation. */
    data class Error(val message: String) : KeyNegotiationResult()

    /** Key negotiation probing is not available on this platform/connection. */
    data object Unavailable : KeyNegotiationResult()
}

/**
 * Information about the encryption state of a BLE connection.
 */
data class EncryptionInfo(
    val keySize: Int,
    // "AES-CCM", "E0", etc.
    val encryptionType: String,
    val isSecureConnection: Boolean,
)
