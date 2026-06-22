/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.StorageAction
import com.btsec.testtool.domain.model.StorageAuditEntry
import com.btsec.testtool.domain.model.StorageConfig
import com.btsec.testtool.domain.model.StorageEncryptionLevel
import com.btsec.testtool.domain.model.StorageStats
import org.json.JSONObject
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for encrypted local storage operations.
 *
 * Provides PBKDF2 key derivation, passphrase validation, audit logging,
 * auto-lock detection, and backup metadata generation for the SQLCipher-
 * protected Room database.
 *
 * All testing must be performed on AUTHORIZED devices with proper consent.
 */
@Singleton
class EncryptedStorageUseCase
    @Inject
    constructor() {
        private val auditIdCounter = AtomicLong(0)

        companion object {
            private const val KEY_ALGORITHM = "PBKDF2WithHmacSHA256"
            private const val KEY_LENGTH_BITS = 256
            private const val SALT_LENGTH_BYTES = 32
        }

        /**
         * Derive a 256-bit encryption key from a passphrase using PBKDF2WithHmacSHA256.
         *
         * @param passphrase  User-supplied passphrase.
         * @param salt        Cryptographic salt (32 bytes recommended).
         * @param iterations  Number of PBKDF2 iterations (default 10 000).
         * @return 32-byte derived key material.
         */
        fun deriveKey(
            passphrase: String,
            salt: ByteArray,
            iterations: Int = 10000,
        ): ByteArray {
            val spec = PBEKeySpec(passphrase.toCharArray(), salt, iterations, KEY_LENGTH_BITS)
            val factory = SecretKeyFactory.getInstance(KEY_ALGORITHM)
            return factory.generateSecret(spec).encoded
        }

        /**
         * Generate a cryptographically random 32-byte salt.
         */
        fun generateSalt(): ByteArray {
            val salt = ByteArray(SALT_LENGTH_BYTES)
            SecureRandom().nextBytes(salt)
            return salt
        }

        /**
         * Validate that a passphrase meets minimum strength requirements:
         * - At least 8 characters
         * - Contains at least one uppercase letter
         * - Contains at least one lowercase letter
         * - Contains at least one digit
         */
        fun validatePassphrase(passphrase: String): Boolean {
            if (passphrase.length < 8) return false
            val hasUppercase = passphrase.any { it.isUpperCase() }
            val hasLowercase = passphrase.any { it.isLowerCase() }
            val hasDigit = passphrase.any { it.isDigit() }
            return hasUppercase && hasLowercase && hasDigit
        }

        /**
         * Compute aggregate statistics about the encrypted storage.
         */
        fun computeStorageStats(
            scanResults: Int,
            vulnerabilityReports: Int,
            fuzzingSessions: Int,
            dbSize: Long,
            encryptionLevel: StorageEncryptionLevel,
        ): StorageStats {
            return StorageStats(
                totalScanResults = scanResults,
                totalVulnerabilityReports = vulnerabilityReports,
                totalFuzzingSessions = fuzzingSessions,
                databaseSizeBytes = dbSize,
                encryptionLevel = encryptionLevel,
                lastModified = System.currentTimeMillis(),
            )
        }

        /**
         * Create an audit entry for the given storage action.
         */
        fun auditLog(
            action: StorageAction,
            dataType: String,
            recordCount: Int,
            success: Boolean,
        ): StorageAuditEntry {
            return StorageAuditEntry(
                id = auditIdCounter.incrementAndGet(),
                timestamp = System.currentTimeMillis(),
                action = action,
                dataType = dataType,
                recordCount = recordCount,
                success = success,
            )
        }

        /**
         * Determine whether the storage should auto-lock based on inactivity.
         *
         * @return true if the elapsed time since [lastActivityTime] exceeds [timeoutMs].
         */
        fun shouldAutoLock(
            lastActivityTime: Long,
            timeoutMs: Long,
        ): Boolean {
            val elapsed = System.currentTimeMillis() - lastActivityTime
            return elapsed > timeoutMs
        }

        /**
         * Recommend an encryption level based on data sensitivity.
         */
        fun getEncryptionRecommendation(sensitivity: DataSensitivity): StorageEncryptionLevel {
            return when (sensitivity) {
                DataSensitivity.LOW -> StorageEncryptionLevel.STANDARD
                DataSensitivity.MEDIUM -> StorageEncryptionLevel.STANDARD
                DataSensitivity.HIGH -> StorageEncryptionLevel.MILITARY_GRADE
            }
        }

        /**
         * Generate JSON metadata for a backup file.
         */
        fun generateBackupMetadata(
            config: StorageConfig,
            stats: StorageStats,
        ): String {
            val json = JSONObject()
            json.put("encryptionLevel", config.encryptionLevel.name)
            json.put("keyDerivationIterations", config.keyDerivationIterations)
            json.put("autoLockTimeoutMs", config.autoLockTimeoutMs)
            json.put("biometricUnlockEnabled", config.biometricUnlockEnabled)
            json.put("databaseSizeBytes", config.databaseSizeBytes)
            config.lastBackupTime?.let { json.put("lastBackupTime", it) }
            json.put("totalScanResults", stats.totalScanResults)
            json.put("totalVulnerabilityReports", stats.totalVulnerabilityReports)
            json.put("totalFuzzingSessions", stats.totalFuzzingSessions)
            stats.lastModified?.let { json.put("lastModified", it) }
            return json.toString(2)
        }
    }

/** Sensitivity classification for stored data. */
enum class DataSensitivity { LOW, MEDIUM, HIGH }
