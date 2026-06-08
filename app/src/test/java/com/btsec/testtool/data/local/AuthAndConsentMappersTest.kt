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
import kotlinx.serialization.encodeToString
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@DisplayName("AuthAndConsentMappers")
class AuthAndConsentMappersTest {

    private val testInstant = Instant.ofEpochMilli(1700000000000L)

    // ========== AuthorizationEntity <-> Authorization ==========

    @Nested
    @DisplayName("AuthorizationEntity.toDomain()")
    inner class AuthorizationEntityToDomain {

        @Test
        @DisplayName("maps basic fields correctly")
        fun mapsBasicFields() {
            val scope = TestScope(
                authId = "AUTH-001",
                authorizedTargets = emptyList(),
                allowedActions = setOf(TestAction.SCAN_DEVICES),
                validFrom = testInstant,
                validUntil = testInstant.plusSeconds(3600),
                disclosureDeadline = testInstant.plusSeconds(7200)
            )
            val scopeJson = mapperJson.encodeToString(scope)
            val entity = AuthorizationEntity(
                authId = "AUTH-001",
                issuedTo = "Tester",
                issuedBy = "Admin",
                issuedAt = testInstant.toEpochMilli(),
                expiresAt = testInstant.plusSeconds(3600).toEpochMilli(),
                authorizedActions = "SCAN_DEVICES,CONNECT_DEVICE",
                scope = scopeJson,
                signature = "sig123",
                terms = """["term1","term2"]"""
            )

            val domain = entity.toDomain()

            assertEquals("AUTH-001", domain.authId)
            assertEquals("Tester", domain.issuedTo)
            assertEquals("Admin", domain.issuedBy)
            assertEquals(testInstant, domain.issuedAt)
            assertEquals(testInstant.plusSeconds(3600), domain.expiresAt)
            assertEquals("sig123", domain.signature)
            assertEquals(listOf("term1", "term2"), domain.terms)
        }

        @Test
        @DisplayName("parses comma-separated actions into Set")
        fun parsesActions() {
            val scope = TestScope(
                authId = "AUTH-001",
                authorizedTargets = emptyList(),
                allowedActions = emptySet(),
                validFrom = testInstant,
                validUntil = testInstant.plusSeconds(3600),
                disclosureDeadline = testInstant.plusSeconds(7200)
            )
            val entity = AuthorizationEntity(
                authId = "AUTH-001",
                issuedTo = "Tester",
                issuedBy = "Admin",
                issuedAt = testInstant.toEpochMilli(),
                expiresAt = testInstant.plusSeconds(3600).toEpochMilli(),
                authorizedActions = "SCAN_DEVICES,START_FUZZING,GENERATE_REPORT",
                scope = mapperJson.encodeToString(scope),
                signature = "sig",
                terms = "[]"
            )

            val domain = entity.toDomain()

            assertEquals(setOf(TestAction.SCAN_DEVICES, TestAction.START_FUZZING, TestAction.GENERATE_REPORT), domain.authorizedActions)
        }

        @Test
        @DisplayName("filters blank and invalid actions")
        fun filtersInvalidActions() {
            val scope = TestScope(
                authId = "AUTH-001",
                authorizedTargets = emptyList(),
                allowedActions = emptySet(),
                validFrom = testInstant,
                validUntil = testInstant.plusSeconds(3600),
                disclosureDeadline = testInstant.plusSeconds(7200)
            )
            val entity = AuthorizationEntity(
                authId = "AUTH-001",
                issuedTo = "Tester",
                issuedBy = "Admin",
                issuedAt = testInstant.toEpochMilli(),
                expiresAt = testInstant.plusSeconds(3600).toEpochMilli(),
                authorizedActions = "SCAN_DEVICES,,INVALID_ACTION,CONNECT_DEVICE",
                scope = mapperJson.encodeToString(scope),
                signature = "sig",
                terms = "[]"
            )

            val domain = entity.toDomain()

            assertEquals(setOf(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE), domain.authorizedActions)
        }

        @Test
        @DisplayName("returns empty terms for malformed JSON")
        fun returnsEmptyTermsForMalformed() {
            val scope = TestScope(
                authId = "AUTH-001",
                authorizedTargets = emptyList(),
                allowedActions = emptySet(),
                validFrom = testInstant,
                validUntil = testInstant.plusSeconds(3600),
                disclosureDeadline = testInstant.plusSeconds(7200)
            )
            val entity = AuthorizationEntity(
                authId = "AUTH-001",
                issuedTo = "Tester",
                issuedBy = "Admin",
                issuedAt = testInstant.toEpochMilli(),
                expiresAt = testInstant.plusSeconds(3600).toEpochMilli(),
                authorizedActions = "",
                scope = mapperJson.encodeToString(scope),
                signature = "sig",
                terms = "not json"
            )

            val domain = entity.toDomain()

            assertEquals(emptyList(), domain.terms)
        }

        @Test
        @DisplayName("creates fallback scope when scope JSON is malformed")
        fun createsFallbackScope() {
            val entity = AuthorizationEntity(
                authId = "AUTH-001",
                issuedTo = "Tester",
                issuedBy = "Admin",
                issuedAt = testInstant.toEpochMilli(),
                expiresAt = testInstant.plusSeconds(3600).toEpochMilli(),
                authorizedActions = "SCAN_DEVICES",
                scope = "not valid json",
                signature = "sig",
                terms = "[]"
            )

            val domain = entity.toDomain()

            assertNotNull(domain.scope)
            assertEquals("AUTH-001", domain.scope.authId)
        }
    }

    @Nested
    @DisplayName("Authorization.toEntity()")
    inner class AuthorizationToEntity {

        @Test
        @DisplayName("maps all fields correctly")
        fun mapsAllFields() {
            val scope = TestScope(
                authId = "AUTH-001",
                authorizedTargets = emptyList(),
                allowedActions = setOf(TestAction.SCAN_DEVICES),
                validFrom = testInstant,
                validUntil = testInstant.plusSeconds(3600),
                disclosureDeadline = testInstant.plusSeconds(7200)
            )
            val domain = Authorization(
                authId = "AUTH-001",
                issuedTo = "Tester",
                issuedBy = "Admin",
                issuedAt = testInstant,
                expiresAt = testInstant.plusSeconds(3600),
                authorizedActions = setOf(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE),
                scope = scope,
                signature = "sig",
                terms = listOf("term1")
            )

            val entity = domain.toEntity()

            assertEquals("AUTH-001", entity.authId)
            assertEquals("Tester", entity.issuedTo)
            assertEquals("Admin", entity.issuedBy)
            assertEquals(testInstant.toEpochMilli(), entity.issuedAt)
            assertEquals(testInstant.plusSeconds(3600).toEpochMilli(), entity.expiresAt)
            assertTrue(entity.authorizedActions.contains("SCAN_DEVICES"))
            assertTrue(entity.authorizedActions.contains("CONNECT_DEVICE"))
            assertEquals("sig", entity.signature)
        }
    }

    // ========== ConsentRecordEntity <-> ConsentRecord ==========

    @Nested
    @DisplayName("ConsentRecordEntity.toDomain()")
    inner class ConsentEntityToDomain {

        @Test
        @DisplayName("maps all fields correctly")
        fun mapsAllFields() {
            val deviceInfo = DeviceInfo("Android", "Pixel 8", "14", "1.0.0", "AA:BB:CC:DD:EE:FF")
            val entity = ConsentRecordEntity(
                id = "consent-1",
                authId = "AUTH-001",
                action = "SCAN_DEVICES",
                timestamp = testInstant.toEpochMilli(),
                authorized = true,
                deviceInfo = mapperJson.encodeToString(deviceInfo),
                userSignature = "sig"
            )

            val domain = entity.toDomain()

            assertEquals("consent-1", domain.id)
            assertEquals("AUTH-001", domain.authId)
            assertEquals("SCAN_DEVICES", domain.action)
            assertEquals(testInstant, domain.timestamp)
            assertEquals(true, domain.authorized)
            assertEquals("sig", domain.userSignature)
            assertEquals("Android", domain.deviceInfo.platform)
            assertEquals("Pixel 8", domain.deviceInfo.model)
        }

        @Test
        @DisplayName("creates fallback DeviceInfo for malformed JSON")
        fun createsFallbackDeviceInfo() {
            val entity = ConsentRecordEntity(
                id = "consent-1",
                authId = "AUTH-001",
                action = "SCAN_DEVICES",
                timestamp = testInstant.toEpochMilli(),
                authorized = true,
                deviceInfo = "not valid json",
                userSignature = null
            )

            val domain = entity.toDomain()

            assertNotNull(domain.deviceInfo)
            assertEquals("", domain.deviceInfo.platform)
            assertNull(domain.userSignature)
        }
    }

    @Nested
    @DisplayName("ConsentRecord.toEntity()")
    inner class ConsentDomainToEntity {

        @Test
        @DisplayName("maps all fields correctly")
        fun mapsAllFields() {
            val deviceInfo = DeviceInfo("Android", "Pixel 8", "14", "1.0.0", "AA:BB:CC:DD:EE:FF")
            val domain = ConsentRecord(
                id = "consent-1",
                authId = "AUTH-001",
                action = "SCAN_DEVICES",
                timestamp = testInstant,
                authorized = true,
                deviceInfo = deviceInfo,
                userSignature = "sig"
            )

            val entity = domain.toEntity()

            assertEquals("consent-1", entity.id)
            assertEquals("AUTH-001", entity.authId)
            assertEquals("SCAN_DEVICES", entity.action)
            assertEquals(testInstant.toEpochMilli(), entity.timestamp)
            assertEquals(true, entity.authorized)
            assertEquals("sig", entity.userSignature)
            assertTrue(entity.deviceInfo.contains("Android"))
        }
    }

    // ========== AuditLogEntity <-> AuditLogEntry ==========

    @Nested
    @DisplayName("AuditLogEntity.toDomain()")
    inner class AuditLogEntityToDomain {

        @Test
        @DisplayName("maps all fields correctly")
        fun mapsAllFields() {
            val deviceInfo = DeviceInfo("Android", "Pixel 8", "14", "1.0.0", "AA:BB:CC:DD:EE:FF")
            val entity = AuditLogEntity(
                id = "log-1",
                authId = "AUTH-001",
                timestamp = testInstant.toEpochMilli(),
                operation = "SCAN",
                success = true,
                errorMessage = null,
                deviceInfo = mapperJson.encodeToString(deviceInfo),
                durationMs = 1500L,
                metadata = """{"key":"value"}"""
            )

            val domain = entity.toDomain()

            assertEquals("log-1", domain.id)
            assertEquals("AUTH-001", domain.authId)
            assertEquals(testInstant, domain.timestamp)
            assertEquals("SCAN", domain.operation)
            assertEquals(true, domain.success)
            assertNull(domain.errorMessage)
            assertEquals(1500L, domain.durationMs)
            assertEquals("value", domain.metadata["key"])
            assertEquals("Android", domain.deviceInfo.platform)
        }

        @Test
        @DisplayName("returns empty metadata for malformed JSON")
        fun returnsEmptyMetadataForMalformed() {
            val entity = AuditLogEntity(
                id = "log-1",
                authId = "AUTH-001",
                timestamp = testInstant.toEpochMilli(),
                operation = "SCAN",
                success = true,
                errorMessage = null,
                deviceInfo = """{"platform":"","model":"","androidVersion":"","appVersion":"","bluetoothAddress":""}""",
                durationMs = null,
                metadata = "not json"
            )

            val domain = entity.toDomain()

            assertEquals(emptyMap(), domain.metadata)
            assertNull(domain.durationMs)
        }
    }

    @Nested
    @DisplayName("AuditLogEntry.toEntity()")
    inner class AuditLogDomainToEntity {

        @Test
        @DisplayName("maps all fields correctly")
        fun mapsAllFields() {
            val deviceInfo = DeviceInfo("Android", "Pixel 8", "14", "1.0.0", "AA:BB:CC:DD:EE:FF")
            val domain = AuditLogEntry(
                id = "log-1",
                authId = "AUTH-001",
                timestamp = testInstant,
                operation = "SCAN",
                success = false,
                errorMessage = "Connection failed",
                deviceInfo = deviceInfo,
                durationMs = 200L,
                metadata = mapOf("attempt" to "3")
            )

            val entity = domain.toEntity()

            assertEquals("log-1", entity.id)
            assertEquals("AUTH-001", entity.authId)
            assertEquals(testInstant.toEpochMilli(), entity.timestamp)
            assertEquals("SCAN", entity.operation)
            assertEquals(false, entity.success)
            assertEquals("Connection failed", entity.errorMessage)
            assertEquals(200L, entity.durationMs)
            assertTrue(entity.metadata.contains("attempt"))
        }
    }

    // ========== BtOperationEntity <-> BluetoothOperation ==========

    @Nested
    @DisplayName("BtOperationEntity.toDomain()")
    inner class BtOperationEntityToDomain {

        @Test
        @DisplayName("maps all fields correctly")
        fun mapsAllFields() {
            val entity = BtOperationEntity(
                id = "op-1",
                timestamp = testInstant.toEpochMilli(),
                operationType = "CONNECT",
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                success = true,
                errorMessage = null,
                durationMs = 100L,
                metadata = """{"mtu":"512"}"""
            )

            val domain = entity.toDomain()

            assertEquals("op-1", domain.id)
            assertEquals(testInstant, domain.timestamp)
            assertEquals(OperationType.CONNECT, domain.operationType)
            assertEquals("AA:BB:CC:DD:EE:FF", domain.deviceAddress)
            assertEquals(true, domain.success)
            assertNull(domain.errorMessage)
            assertEquals(100L, domain.durationMs)
            assertEquals("512", domain.metadata["mtu"])
        }

        @Test
        @DisplayName("defaults to SCAN_START for invalid operation type")
        fun defaultsToScanStart() {
            val entity = BtOperationEntity(
                id = "op-1",
                timestamp = testInstant.toEpochMilli(),
                operationType = "INVALID",
                deviceAddress = null,
                success = false,
                errorMessage = "error",
                durationMs = null,
                metadata = "not json"
            )

            val domain = entity.toDomain()

            assertEquals(OperationType.SCAN_START, domain.operationType)
            assertNull(domain.deviceAddress)
            assertEquals(emptyMap(), domain.metadata)
        }
    }

    @Nested
    @DisplayName("BluetoothOperation.toEntity()")
    inner class BtOperationDomainToEntity {

        @Test
        @DisplayName("maps all fields correctly")
        fun mapsAllFields() {
            val domain = BluetoothOperation(
                id = "op-1",
                timestamp = testInstant,
                operationType = OperationType.DISCONNECT,
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                success = true,
                errorMessage = null,
                durationMs = 50L,
                metadata = mapOf("reason" to "user")
            )

            val entity = domain.toEntity()

            assertEquals("op-1", entity.id)
            assertEquals(testInstant.toEpochMilli(), entity.timestamp)
            assertEquals("DISCONNECT", entity.operationType)
            assertEquals("AA:BB:CC:DD:EE:FF", entity.deviceAddress)
            assertEquals(true, entity.success)
            assertNull(entity.errorMessage)
            assertEquals(50L, entity.durationMs)
            assertTrue(entity.metadata.contains("reason"))
        }
    }

    // ========== Collection mappers ==========

    @Nested
    @DisplayName("Collection mappers")
    inner class CollectionMappers {

        @Test
        @DisplayName("toDomainAuthorizations maps list correctly")
        fun mapsAuthorizationList() {
            val scope = TestScope(
                authId = "AUTH-001",
                authorizedTargets = emptyList(),
                allowedActions = emptySet(),
                validFrom = testInstant,
                validUntil = testInstant.plusSeconds(3600),
                disclosureDeadline = testInstant.plusSeconds(7200)
            )
            val entities = listOf(
                AuthorizationEntity("A1", "to", "by", 0L, 1L, "", mapperJson.encodeToString(scope), "sig", "[]"),
                AuthorizationEntity("A2", "to", "by", 0L, 1L, "", mapperJson.encodeToString(scope), "sig", "[]")
            )
            val domain = entities.toDomainAuthorizations()

            assertEquals(2, domain.size)
            assertEquals("A1", domain[0].authId)
            assertEquals("A2", domain[1].authId)
        }

        @Test
        @DisplayName("toDomainConsentRecords maps list correctly")
        fun mapsConsentRecordList() {
            val di = """{"platform":"","model":"","androidVersion":"","appVersion":"","bluetoothAddress":""}"""
            val entities = listOf(
                ConsentRecordEntity("c1", "a", "act", 0L, true, di, null),
                ConsentRecordEntity("c2", "a", "act", 0L, false, di, "sig")
            )
            val domain = entities.toDomainConsentRecords()

            assertEquals(2, domain.size)
            assertEquals("c1", domain[0].id)
            assertEquals("c2", domain[1].id)
        }

        @Test
        @DisplayName("toDomainOperations maps list correctly")
        fun mapsOperationList() {
            val entities = listOf(
                BtOperationEntity("op1", 0L, "SCAN_START", null, true, null, null, "{}"),
                BtOperationEntity("op2", 0L, "CONNECT", "AA:BB", true, null, 100L, "{}")
            )
            val domain = entities.toDomainOperations()

            assertEquals(2, domain.size)
            assertEquals(OperationType.SCAN_START, domain[0].operationType)
            assertEquals(OperationType.CONNECT, domain[1].operationType)
        }
    }
}
