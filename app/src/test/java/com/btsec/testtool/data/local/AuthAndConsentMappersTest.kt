/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import com.btsec.testtool.data.local.entity.AuditLogEntity
import com.btsec.testtool.data.local.entity.AuthorizationEntity
import com.btsec.testtool.data.local.entity.BtOperationEntity
import com.btsec.testtool.data.local.entity.ConsentRecordEntity
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.AuditLogEntry
import com.btsec.testtool.domain.repository.BluetoothOperation
import com.btsec.testtool.domain.repository.OperationType
import com.google.common.truth.Truth.assertThat
import kotlinx.serialization.encodeToString
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant

/**
 * Unit tests for AuthAndConsentMappers.kt — pure function mappers for
 * authorization, consent, audit-log, and Bluetooth-operation entities.
 */
class AuthAndConsentMappersTest {

    // ---- Shared test fixtures ----

    private val testInstant = Instant.ofEpochMilli(1_700_000_000_000L)
    private val testScope = TestScope(
        authId = "BTSEC-20260101-ABCD1234",
        authorizedTargets = listOf(TargetDevice("AA:BB:CC:DD:EE:FF")),
        allowedActions = setOf(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE),
        validFrom = testInstant,
        validUntil = testInstant.plusSeconds(86_400),
        disclosureDeadline = testInstant.plusSeconds(86_400 * 30)
    )
    private val testDeviceInfo = DeviceInfo(
        platform = "Android",
        model = "Pixel 8",
        androidVersion = "14",
        appVersion = "1.0.0",
        bluetoothAddress = "11:22:33:44:55:66"
    )

    // ========================================================
    // AuthorizationEntity <-> Authorization
    // ========================================================

    @Nested
    @DisplayName("AuthorizationEntity.toDomain()")
    inner class AuthorizationToDomain {

        private fun sampleAuthEntity(
            authorizedActions: String = "SCAN_DEVICES,CONNECT_DEVICE",
            scope: String = mapperJson.encodeToString(testScope),
            terms: String = """["term1","term2"]"""
        ): AuthorizationEntity = AuthorizationEntity(
            authId = "BTSEC-20260101-ABCD1234",
            issuedTo = "researcher",
            issuedBy = "BTSecOrg",
            issuedAt = testInstant.toEpochMilli(),
            expiresAt = testInstant.plusSeconds(86_400).toEpochMilli(),
            authorizedActions = authorizedActions,
            scope = scope,
            signature = "sig123",
            terms = terms
        )

        @Test
        fun `maps all fields correctly`() {
            val entity = sampleAuthEntity()
            val domain = entity.toDomain()

            assertThat(domain.authId).isEqualTo("BTSEC-20260101-ABCD1234")
            assertThat(domain.issuedTo).isEqualTo("researcher")
            assertThat(domain.issuedBy).isEqualTo("BTSecOrg")
            assertThat(domain.issuedAt).isEqualTo(testInstant)
            assertThat(domain.expiresAt).isEqualTo(testInstant.plusSeconds(86_400))
            assertThat(domain.authorizedActions).containsExactly(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE)
            assertThat(domain.signature).isEqualTo("sig123")
            assertThat(domain.terms).containsExactly("term1", "term2").inOrder()
        }

        @Test
        fun `parses actions with extra whitespace`() {
            val entity = sampleAuthEntity(authorizedActions = " SCAN_DEVICES , CONNECT_DEVICE ")
            val domain = entity.toDomain()
            assertThat(domain.authorizedActions).containsExactly(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE)
        }

        @Test
        fun `ignores unknown action names`() {
            val entity = sampleAuthEntity(authorizedActions = "SCAN_DEVICES,INVALID_ACTION")
            val domain = entity.toDomain()
            assertThat(domain.authorizedActions).containsExactly(TestAction.SCAN_DEVICES)
        }

        @Test
        fun `empty authorizedActions string yields empty set`() {
            val entity = sampleAuthEntity(authorizedActions = "")
            val domain = entity.toDomain()
            assertThat(domain.authorizedActions).isEmpty()
        }

        @Test
        fun `malformed scope JSON falls back to constructed TestScope`() {
            val entity = sampleAuthEntity(scope = "not-json")
            val domain = entity.toDomain()
            assertThat(domain.scope.authId).isEqualTo("BTSEC-20260101-ABCD1234")
            assertThat(domain.scope.authorizedTargets).isEmpty()
        }

        @Test
        fun `malformed terms JSON yields empty list`() {
            val entity = sampleAuthEntity(terms = "not-json")
            val domain = entity.toDomain()
            assertThat(domain.terms).isEmpty()
        }
    }

    @Nested
    @DisplayName("Authorization.toEntity()")
    inner class AuthorizationToEntity {

        @Test
        fun `maps all fields correctly`() {
            val domain = Authorization(
                authId = "BTSEC-20260101-ABCD1234",
                issuedTo = "researcher",
                issuedBy = "BTSecOrg",
                issuedAt = testInstant,
                expiresAt = testInstant.plusSeconds(86_400),
                authorizedActions = setOf(TestAction.SCAN_DEVICES),
                scope = testScope,
                signature = "sig123",
                terms = listOf("term1")
            )
            val entity = domain.toEntity()

            assertThat(entity.authId).isEqualTo("BTSEC-20260101-ABCD1234")
            assertThat(entity.issuedTo).isEqualTo("researcher")
            assertThat(entity.issuedBy).isEqualTo("BTSecOrg")
            assertThat(entity.issuedAt).isEqualTo(testInstant.toEpochMilli())
            assertThat(entity.expiresAt).isEqualTo(testInstant.plusSeconds(86_400).toEpochMilli())
            assertThat(entity.authorizedActions).isEqualTo("SCAN_DEVICES")
            assertThat(entity.signature).isEqualTo("sig123")
        }

        @Test
        fun `serializes multiple actions as comma-separated`() {
            val domain = Authorization(
                authId = "id",
                issuedTo = "a",
                issuedBy = "b",
                issuedAt = testInstant,
                expiresAt = testInstant,
                authorizedActions = setOf(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE),
                scope = testScope,
                signature = "",
                terms = emptyList()
            )
            val entity = domain.toEntity()
            assertThat(entity.authorizedActions).contains("SCAN_DEVICES")
            assertThat(entity.authorizedActions).contains("CONNECT_DEVICE")
        }

        @Test
        fun `empty actions set serializes to empty string`() {
            val domain = Authorization(
                authId = "id",
                issuedTo = "a",
                issuedBy = "b",
                issuedAt = testInstant,
                expiresAt = testInstant,
                authorizedActions = emptySet(),
                scope = testScope,
                signature = "",
                terms = emptyList()
            )
            assertThat(domain.toEntity().authorizedActions).isEmpty()
        }
    }

    // ========================================================
    // ConsentRecordEntity <-> ConsentRecord
    // ========================================================

    @Nested
    @DisplayName("ConsentRecordEntity.toDomain()")
    inner class ConsentToDomain {

        private fun sampleConsentEntity(
            deviceInfo: String = mapperJson.encodeToString(testDeviceInfo)
        ): ConsentRecordEntity = ConsentRecordEntity(
            id = "consent-1",
            authId = "BTSEC-20260101-ABCD1234",
            action = "SCAN_DEVICES",
            timestamp = testInstant.toEpochMilli(),
            authorized = true,
            deviceInfo = deviceInfo,
            userSignature = "userSig"
        )

        @Test
        fun `maps all fields correctly`() {
            val entity = sampleConsentEntity()
            val domain = entity.toDomain()

            assertThat(domain.id).isEqualTo("consent-1")
            assertThat(domain.authId).isEqualTo("BTSEC-20260101-ABCD1234")
            assertThat(domain.action).isEqualTo("SCAN_DEVICES")
            assertThat(domain.timestamp).isEqualTo(testInstant)
            assertThat(domain.authorized).isTrue()
            assertThat(domain.deviceInfo).isEqualTo(testDeviceInfo)
            assertThat(domain.userSignature).isEqualTo("userSig")
        }

        @Test
        fun `null userSignature maps to null`() {
            val entity = sampleConsentEntity().copy(userSignature = null)
            assertThat(entity.toDomain().userSignature).isNull()
        }

        @Test
        fun `malformed deviceInfo JSON falls back to empty DeviceInfo`() {
            val entity = sampleConsentEntity(deviceInfo = "not-json")
            val domain = entity.toDomain()
            assertThat(domain.deviceInfo.platform).isEmpty()
            assertThat(domain.deviceInfo.model).isEmpty()
        }
    }

    @Nested
    @DisplayName("ConsentRecord.toEntity()")
    inner class ConsentToEntity {

        @Test
        fun `maps all fields correctly`() {
            val domain = ConsentRecord(
                id = "consent-1",
                authId = "auth-1",
                action = "CONNECT",
                timestamp = testInstant,
                authorized = false,
                deviceInfo = testDeviceInfo,
                userSignature = null
            )
            val entity = domain.toEntity()

            assertThat(entity.id).isEqualTo("consent-1")
            assertThat(entity.authId).isEqualTo("auth-1")
            assertThat(entity.action).isEqualTo("CONNECT")
            assertThat(entity.timestamp).isEqualTo(testInstant.toEpochMilli())
            assertThat(entity.authorized).isFalse()
            assertThat(entity.userSignature).isNull()
        }
    }

    // ========================================================
    // AuditLogEntity <-> AuditLogEntry
    // ========================================================

    @Nested
    @DisplayName("AuditLogEntity.toDomain()")
    inner class AuditLogToDomain {

        private fun sampleAuditEntity(
            deviceInfo: String = mapperJson.encodeToString(testDeviceInfo),
            metadata: String = """{"key":"value"}"""
        ): AuditLogEntity = AuditLogEntity(
            id = "audit-1",
            authId = "auth-1",
            timestamp = testInstant.toEpochMilli(),
            operation = "SCAN",
            success = true,
            errorMessage = null,
            deviceInfo = deviceInfo,
            durationMs = 150L,
            metadata = metadata
        )

        @Test
        fun `maps all fields correctly`() {
            val entity = sampleAuditEntity()
            val domain = entity.toDomain()

            assertThat(domain.id).isEqualTo("audit-1")
            assertThat(domain.authId).isEqualTo("auth-1")
            assertThat(domain.timestamp).isEqualTo(testInstant)
            assertThat(domain.operation).isEqualTo("SCAN")
            assertThat(domain.success).isTrue()
            assertThat(domain.errorMessage).isNull()
            assertThat(domain.deviceInfo).isEqualTo(testDeviceInfo)
            assertThat(domain.durationMs).isEqualTo(150L)
            assertThat(domain.metadata).containsEntry("key", "value")
        }

        @Test
        fun `malformed metadata JSON yields empty map`() {
            val entity = sampleAuditEntity(metadata = "not-json")
            assertThat(entity.toDomain().metadata).isEmpty()
        }

        @Test
        fun `malformed deviceInfo JSON yields empty DeviceInfo`() {
            val entity = sampleAuditEntity(deviceInfo = "not-json")
            val domain = entity.toDomain()
            assertThat(domain.deviceInfo.platform).isEmpty()
        }

        @Test
        fun `null errorMessage maps to null`() {
            val entity = sampleAuditEntity().copy(errorMessage = null)
            assertThat(entity.toDomain().errorMessage).isNull()
        }

        @Test
        fun `non-null errorMessage maps correctly`() {
            val entity = sampleAuditEntity().copy(errorMessage = "Something failed")
            assertThat(entity.toDomain().errorMessage).isEqualTo("Something failed")
        }

        @Test
        fun `null durationMs maps to null`() {
            val entity = sampleAuditEntity().copy(durationMs = null)
            assertThat(entity.toDomain().durationMs).isNull()
        }
    }

    @Nested
    @DisplayName("AuditLogEntry.toEntity()")
    inner class AuditLogToEntity {

        @Test
        fun `maps all fields correctly`() {
            val domain = AuditLogEntry(
                id = "audit-2",
                authId = "auth-2",
                timestamp = testInstant,
                operation = "CONNECT",
                success = false,
                errorMessage = "timeout",
                deviceInfo = testDeviceInfo,
                durationMs = 3000L,
                metadata = mapOf("retry" to "true")
            )
            val entity = domain.toEntity()

            assertThat(entity.id).isEqualTo("audit-2")
            assertThat(entity.authId).isEqualTo("auth-2")
            assertThat(entity.timestamp).isEqualTo(testInstant.toEpochMilli())
            assertThat(entity.operation).isEqualTo("CONNECT")
            assertThat(entity.success).isFalse()
            assertThat(entity.errorMessage).isEqualTo("timeout")
            assertThat(entity.durationMs).isEqualTo(3000L)
        }
    }

    // ========================================================
    // BtOperationEntity <-> BluetoothOperation
    // ========================================================

    @Nested
    @DisplayName("BtOperationEntity.toDomain()")
    inner class BtOperationToDomain {

        private fun sampleOpEntity(
            metadata: String = """{"source":"scanner"}"""
        ): BtOperationEntity = BtOperationEntity(
            id = "op-1",
            timestamp = testInstant.toEpochMilli(),
            operationType = "SCAN_START",
            deviceAddress = "AA:BB:CC:DD:EE:FF",
            success = true,
            errorMessage = null,
            durationMs = 42L,
            metadata = metadata
        )

        @Test
        fun `maps all fields correctly`() {
            val entity = sampleOpEntity()
            val domain = entity.toDomain()

            assertThat(domain.id).isEqualTo("op-1")
            assertThat(domain.timestamp).isEqualTo(testInstant)
            assertThat(domain.operationType).isEqualTo(OperationType.SCAN_START)
            assertThat(domain.deviceAddress).isEqualTo("AA:BB:CC:DD:EE:FF")
            assertThat(domain.success).isTrue()
            assertThat(domain.errorMessage).isNull()
            assertThat(domain.durationMs).isEqualTo(42L)
            assertThat(domain.metadata).containsEntry("source", "scanner")
        }

        @Test
        fun `malformed metadata JSON yields empty map`() {
            val entity = sampleOpEntity(metadata = "not-json")
            assertThat(entity.toDomain().metadata).isEmpty()
        }

        @Test
        fun `unknown operationType falls back to SCAN_START`() {
            val entity = sampleOpEntity().copy(operationType = "GARBAGE")
            assertThat(entity.toDomain().operationType).isEqualTo(OperationType.SCAN_START)
        }

        @Test
        fun `null deviceAddress maps to null`() {
            val entity = sampleOpEntity().copy(deviceAddress = null)
            assertThat(entity.toDomain().deviceAddress).isNull()
        }

        @Test
        fun `null durationMs maps to null`() {
            val entity = sampleOpEntity().copy(durationMs = null)
            assertThat(entity.toDomain().durationMs).isNull()
        }
    }

    @Nested
    @DisplayName("BluetoothOperation.toEntity()")
    inner class BtOperationToEntity {

        @Test
        fun `maps all fields correctly`() {
            val domain = BluetoothOperation(
                id = "op-2",
                timestamp = testInstant,
                operationType = OperationType.CONNECT,
                deviceAddress = "11:22:33:44:55:66",
                success = false,
                errorMessage = "refused",
                durationMs = 500L,
                metadata = mapOf("attempt" to "2")
            )
            val entity = domain.toEntity()

            assertThat(entity.id).isEqualTo("op-2")
            assertThat(entity.timestamp).isEqualTo(testInstant.toEpochMilli())
            assertThat(entity.operationType).isEqualTo("CONNECT")
            assertThat(entity.deviceAddress).isEqualTo("11:22:33:44:55:66")
            assertThat(entity.success).isFalse()
            assertThat(entity.errorMessage).isEqualTo("refused")
            assertThat(entity.durationMs).isEqualTo(500L)
        }
    }

    // ========================================================
    // Collection mappers
    // ========================================================

    @Nested
    @DisplayName("Collection mappers")
    inner class CollectionMappers {

        @Test
        fun `toDomainAuthorizations maps empty list`() {
            assertThat(emptyList<AuthorizationEntity>().toDomainAuthorizations()).isEmpty()
        }

        @Test
        fun `toDomainAuthorizations maps multiple items`() {
            val entities = listOf(
                AuthorizationEntity("a1", "to", "by", 0L, 0L, "SCAN_DEVICES",
                    mapperJson.encodeToString(testScope), "sig", """["t"]"""),
                AuthorizationEntity("a2", "to2", "by2", 0L, 0L, "CONNECT_DEVICE",
                    mapperJson.encodeToString(testScope), "sig2", "[]")
            )
            val result = entities.toDomainAuthorizations()
            assertThat(result).hasSize(2)
            assertThat(result[0].authId).isEqualTo("a1")
            assertThat(result[1].authId).isEqualTo("a2")
        }

        @Test
        fun `toDomainConsentRecords maps empty list`() {
            assertThat(emptyList<ConsentRecordEntity>().toDomainConsentRecords()).isEmpty()
        }

        @Test
        fun `toDomainConsentRecords maps items`() {
            val entities = listOf(
                ConsentRecordEntity("c1", "a1", "SCAN", 0L, true,
                    mapperJson.encodeToString(testDeviceInfo), null)
            )
            val result = entities.toDomainConsentRecords()
            assertThat(result).hasSize(1)
            assertThat(result[0].id).isEqualTo("c1")
        }

        @Test
        fun `toDomainAuditLogEntries maps empty list`() {
            assertThat(emptyList<AuditLogEntity>().toDomainAuditLogEntries()).isEmpty()
        }

        @Test
        fun `toDomainAuditLogEntries maps items`() {
            val entities = listOf(
                AuditLogEntity("al1", "a1", 0L, "SCAN", true, null,
                    mapperJson.encodeToString(testDeviceInfo), 10L, "{}")
            )
            val result = entities.toDomainAuditLogEntries()
            assertThat(result).hasSize(1)
            assertThat(result[0].id).isEqualTo("al1")
        }

        @Test
        fun `toDomainOperations maps empty list`() {
            assertThat(emptyList<BtOperationEntity>().toDomainOperations()).isEmpty()
        }

        @Test
        fun `toDomainOperations maps items`() {
            val entities = listOf(
                BtOperationEntity("op1", 0L, "SCAN_START", "AA:BB:CC:DD:EE:FF",
                    true, null, 5L, "{}")
            )
            val result = entities.toDomainOperations()
            assertThat(result).hasSize(1)
            assertThat(result[0].id).isEqualTo("op1")
        }
    }
}
