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
 * Encryption level for local storage of test results and sensitive data.
 *
 * All testing must be performed on AUTHORIZED devices with proper consent.
 */

/** Encryption strength for the SQLCipher-protected Room database. */
enum class StorageEncryptionLevel {
    NONE, // No encryption (for debug builds)
    STANDARD, // SQLCipher with user-derived key
    MILITARY_GRADE, // SQLCipher with hardware-backed keystore
}

/** Configuration for encrypted local storage. */
data class StorageConfig(
    val encryptionLevel: StorageEncryptionLevel,
    val keyDerivationIterations: Int = 10000,
    // 5 minutes
    val autoLockTimeoutMs: Long = 300000,
    val biometricUnlockEnabled: Boolean = false,
    val databaseSizeBytes: Long = 0,
    val lastBackupTime: Long? = null,
)

/** An immutable record of a storage-layer action for audit logging. */
data class StorageAuditEntry(
    val id: Long,
    val timestamp: Long,
    val action: StorageAction,
    val dataType: String,
    val recordCount: Int,
    val success: Boolean,
)

/** Actions that can be recorded in the storage audit log. */
enum class StorageAction {
    READ,
    WRITE,
    DELETE,
    EXPORT,
    BACKUP,
    RESTORE,
    KEY_ROTATION,
    LOCK,
    UNLOCK,
}

/** Aggregate statistics about the encrypted storage. */
data class StorageStats(
    val totalScanResults: Int,
    val totalVulnerabilityReports: Int,
    val totalFuzzingSessions: Int,
    val databaseSizeBytes: Long,
    val encryptionLevel: StorageEncryptionLevel,
    val lastModified: Long?,
)
