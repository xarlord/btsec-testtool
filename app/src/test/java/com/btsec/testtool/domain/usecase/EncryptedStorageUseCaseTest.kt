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
import com.btsec.testtool.domain.model.StorageConfig
import com.btsec.testtool.domain.model.StorageEncryptionLevel
import com.google.common.truth.Truth.assertThat
import org.json.JSONObject
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Unit tests for [EncryptedStorageUseCase].
 *
 * Validates key derivation, salt generation, passphrase validation,
 * storage stats, audit logging, auto-lock, encryption recommendations,
 * and backup metadata generation.
 *
 * All testing must be performed on AUTHORIZED devices with proper consent.
 */
@DisplayName("EncryptedStorageUseCase Tests")
class EncryptedStorageUseCaseTest {
    private lateinit var useCase: EncryptedStorageUseCase

    @BeforeEach
    fun setUp() {
        useCase = EncryptedStorageUseCase()
    }

    // ---- Key derivation --------------------------------------------------

    @Nested
    @DisplayName("deriveKey")
    inner class DeriveKeyTests {
        @Test
        @DisplayName("returns a 32-byte (256-bit) key")
        fun testDeriveKey_correctLength() {
            val salt = useCase.generateSalt()
            val key = useCase.deriveKey("Passw0rd!", salt)
            assertThat(key).hasLength(32)
        }

        @Test
        @DisplayName("different passphrases produce different keys")
        fun testDeriveKey_differentPassphrasesDifferentKeys() {
            val salt = useCase.generateSalt()
            val key1 = useCase.deriveKey("Passw0rd!", salt)
            val key2 = useCase.deriveKey("Different1!", salt)
            assertThat(key1).isNotEqualTo(key2)
        }

        @Test
        @DisplayName("same inputs produce the same key (deterministic)")
        fun testDeriveKey_sameInputsSameKey() {
            val salt = ByteArray(32) { 0x42 } // fixed salt
            val key1 = useCase.deriveKey("Passw0rd!", salt, 1000)
            val key2 = useCase.deriveKey("Passw0rd!", salt, 1000)
            assertThat(key1).isEqualTo(key2)
        }
    }

    // ---- Salt generation -------------------------------------------------

    @Nested
    @DisplayName("generateSalt")
    inner class GenerateSaltTests {
        @Test
        @DisplayName("returns a 32-byte salt")
        fun testGenerateSalt_correctLength() {
            val salt = useCase.generateSalt()
            assertThat(salt).hasLength(32)
        }

        @Test
        @DisplayName("generates different salts on each call")
        fun testGenerateSalt_differentEachTime() {
            val salt1 = useCase.generateSalt()
            val salt2 = useCase.generateSalt()
            assertThat(salt1).isNotEqualTo(salt2)
        }
    }

    // ---- Passphrase validation -------------------------------------------

    @Nested
    @DisplayName("validatePassphrase")
    inner class ValidatePassphraseTests {
        @Test
        @DisplayName("accepts a valid passphrase")
        fun testValidatePassphrase_validPassword() {
            assertThat(useCase.validatePassphrase("Passw0rd!")).isTrue()
        }

        @Test
        @DisplayName("rejects a passphrase shorter than 8 characters")
        fun testValidatePassphrase_tooShort() {
            assertThat(useCase.validatePassphrase("Ab1")).isFalse()
        }

        @Test
        @DisplayName("rejects a passphrase without uppercase letter")
        fun testValidatePassphrase_noUppercase() {
            assertThat(useCase.validatePassphrase("password1")).isFalse()
        }

        @Test
        @DisplayName("rejects a passphrase without digit")
        fun testValidatePassphrase_noDigit() {
            assertThat(useCase.validatePassphrase("Password!")).isFalse()
        }

        @Test
        @DisplayName("rejects a passphrase without lowercase letter")
        fun testValidatePassphrase_noLowercase() {
            assertThat(useCase.validatePassphrase("PASSWORD1")).isFalse()
        }
    }

    // ---- Storage stats ---------------------------------------------------

    @Nested
    @DisplayName("computeStorageStats")
    inner class ComputeStorageStatsTests {
        @Test
        @DisplayName("returns correct counts and encryption level")
        fun testComputeStorageStats_correctCounts() {
            val stats =
                useCase.computeStorageStats(
                    scanResults = 10,
                    vulnerabilityReports = 3,
                    fuzzingSessions = 2,
                    dbSize = 4096L,
                    encryptionLevel = StorageEncryptionLevel.STANDARD,
                )
            assertThat(stats.totalScanResults).isEqualTo(10)
            assertThat(stats.totalVulnerabilityReports).isEqualTo(3)
            assertThat(stats.totalFuzzingSessions).isEqualTo(2)
            assertThat(stats.databaseSizeBytes).isEqualTo(4096L)
            assertThat(stats.encryptionLevel).isEqualTo(StorageEncryptionLevel.STANDARD)
            assertThat(stats.lastModified).isNotNull()
        }
    }

    // ---- Audit logging ---------------------------------------------------

    @Nested
    @DisplayName("auditLog")
    inner class AuditLogTests {
        @Test
        @DisplayName("creates an entry with correct fields")
        fun testAuditLog_correctFields() {
            val entry =
                useCase.auditLog(
                    action = StorageAction.WRITE,
                    dataType = "scan_result",
                    recordCount = 5,
                    success = true,
                )
            assertThat(entry.action).isEqualTo(StorageAction.WRITE)
            assertThat(entry.dataType).isEqualTo("scan_result")
            assertThat(entry.recordCount).isEqualTo(5)
            assertThat(entry.success).isTrue()
            assertThat(entry.timestamp).isGreaterThan(0L)
        }

        @Test
        @DisplayName("auto-increments the id")
        fun testAuditLog_autoIncrement() {
            val entry1 = useCase.auditLog(StorageAction.READ, "data", 1, true)
            val entry2 = useCase.auditLog(StorageAction.READ, "data", 1, true)
            assertThat(entry2.id).isGreaterThan(entry1.id)
        }
    }

    // ---- Auto-lock -------------------------------------------------------

    @Nested
    @DisplayName("shouldAutoLock")
    inner class ShouldAutoLockTests {
        @Test
        @DisplayName("returns true when timeout has expired")
        fun testShouldAutoLock_expired() {
            val fiveMinutesAgo = System.currentTimeMillis() - 600_000L // 10 min
            assertThat(useCase.shouldAutoLock(fiveMinutesAgo, 300_000L)).isTrue()
        }

        @Test
        @DisplayName("returns false when timeout has not expired")
        fun testShouldAutoLock_notExpired() {
            val justNow = System.currentTimeMillis() - 1_000L // 1 second ago
            assertThat(useCase.shouldAutoLock(justNow, 300_000L)).isFalse()
        }
    }

    // ---- Encryption recommendation ----------------------------------------

    @Nested
    @DisplayName("getEncryptionRecommendation")
    inner class EncryptionRecommendationTests {
        @Test
        @DisplayName("HIGH sensitivity recommends MILITARY_GRADE")
        fun testGetEncryptionRecommendation_high() {
            assertThat(useCase.getEncryptionRecommendation(DataSensitivity.HIGH))
                .isEqualTo(StorageEncryptionLevel.MILITARY_GRADE)
        }

        @Test
        @DisplayName("LOW sensitivity recommends STANDARD")
        fun testGetEncryptionRecommendation_low() {
            assertThat(useCase.getEncryptionRecommendation(DataSensitivity.LOW))
                .isEqualTo(StorageEncryptionLevel.STANDARD)
        }

        @Test
        @DisplayName("MEDIUM sensitivity recommends STANDARD")
        fun testGetEncryptionRecommendation_medium() {
            assertThat(useCase.getEncryptionRecommendation(DataSensitivity.MEDIUM))
                .isEqualTo(StorageEncryptionLevel.STANDARD)
        }
    }

    // ---- Backup metadata --------------------------------------------------

    @Nested
    @DisplayName("generateBackupMetadata")
    inner class BackupMetadataTests {
        @Test
        @DisplayName("produces valid JSON with expected fields")
        fun testGenerateBackupMetadata_validJson() {
            val config =
                StorageConfig(
                    encryptionLevel = StorageEncryptionLevel.STANDARD,
                    keyDerivationIterations = 10000,
                    autoLockTimeoutMs = 300000L,
                    biometricUnlockEnabled = true,
                    databaseSizeBytes = 8192L,
                    lastBackupTime = 1700000000000L,
                )
            val stats =
                useCase.computeStorageStats(
                    scanResults = 42,
                    vulnerabilityReports = 7,
                    fuzzingSessions = 3,
                    dbSize = 8192L,
                    encryptionLevel = StorageEncryptionLevel.STANDARD,
                )
            val json = useCase.generateBackupMetadata(config, stats)

            // Should not throw
            val parsed = JSONObject(json)
            assertThat(parsed.getString("encryptionLevel")).isEqualTo("STANDARD")
            assertThat(parsed.getInt("totalScanResults")).isEqualTo(42)
            assertThat(parsed.getInt("totalVulnerabilityReports")).isEqualTo(7)
            assertThat(parsed.getInt("totalFuzzingSessions")).isEqualTo(3)
            assertThat(parsed.getBoolean("biometricUnlockEnabled")).isTrue()
            assertThat(parsed.getLong("lastBackupTime")).isEqualTo(1700000000000L)
        }
    }
}
