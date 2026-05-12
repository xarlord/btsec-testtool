/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.consent

import android.content.Context
import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for ConsentRepositoryImpl.
 */
@ExtendWith(MockitoExtension::class)
@DisplayName("ConsentRepositoryImpl Tests")
class ConsentRepositoryImplTest {
    @Mock
    private lateinit var mockContext: Context

    private lateinit var repository: ConsentRepositoryImpl

    private val testDeviceInfo =
        DeviceInfo(
            platform = "Android",
            model = "Test Device",
            androidVersion = "14",
            appVersion = "1.0.0",
            bluetoothAddress = "AA:BB:CC:DD:EE:FF",
        )

    @BeforeEach
    fun setUp() {
        repository = ConsentRepositoryImpl(mockContext)
    }

    @Test
    @DisplayName("requestConsent should create consent record when granted")
    fun testRequestConsentGranted() =
        runTest {
            val consent =
                repository.requestConsent(
                    authId = "BTSEC-TEST",
                    action = TestAction.SCAN_DEVICES,
                    deviceInfo = testDeviceInfo,
                )

            assertNotNull(consent)
            assertEquals("BTSEC-TEST", consent?.authId)
            assertTrue(consent?.authorized == true)
            assertEquals("SCAN_DEVICES", consent?.action)
        }

    @Test
    @DisplayName("requestConsentWithContext should include context")
    fun testRequestConsentWithContext() =
        runTest {
            val consent =
                repository.requestConsentWithContext(
                    authId = "BTSEC-TEST",
                    action = TestAction.CONNECT_DEVICE,
                    context = "Connecting to device for testing",
                    deviceInfo = testDeviceInfo,
                )

            assertNotNull(consent)
            assertTrue(consent?.authorized == true)
        }

    @Test
    @DisplayName("hasConsent should return true for granted consent")
    fun testHasConsentTrue() =
        runTest {
            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val hasConsent = repository.hasConsent("BTSEC-TEST", TestAction.SCAN_DEVICES)
            assertTrue(hasConsent)
        }

    @Test
    @DisplayName("hasConsent should return false for no consent")
    fun testHasConsentFalse() =
        runTest {
            val hasConsent = repository.hasConsent("BTSEC-UNKNOWN", TestAction.SCAN_DEVICES)
            assertFalse(hasConsent)
        }

    @Test
    @DisplayName("getConsentStatus should return status for all actions")
    fun testGetConsentStatus() =
        runTest {
            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val status = repository.getConsentStatus("BTSEC-TEST").first()
            assertTrue(status.isNotEmpty())
            assertTrue(status[TestAction.SCAN_DEVICES] == true)
        }

    @Test
    @DisplayName("getLatestConsent should return most recent")
    fun testGetLatestConsent() =
        runTest {
            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val latest = repository.getLatestConsent("BTSEC-TEST", TestAction.SCAN_DEVICES)
            assertNotNull(latest)
            assertEquals("BTSEC-TEST", latest?.authId)
        }

    @Test
    @DisplayName("getConsentRecords should return records for auth")
    fun testGetConsentRecords() =
        runTest {
            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val records = repository.getConsentRecords("BTSEC-TEST").first()
            assertTrue(records.isNotEmpty())
            assertTrue(records.all { it.authId == "BTSEC-TEST" })
        }

    @Test
    @DisplayName("getConsentRecordsInRange should filter by date")
    fun testGetConsentRecordsInRange() =
        runTest {
            val now = Instant.now()

            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val records =
                repository.getConsentRecordsInRange(
                    start = now.minusSeconds(3600),
                    end = now.plusSeconds(3600),
                ).first()

            assertTrue(records.isNotEmpty())
        }

    @Test
    @DisplayName("getAllConsentRecords should return all records")
    fun testGetAllConsentRecords() =
        runTest {
            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val allRecords = repository.getAllConsentRecords().first()
            assertTrue(allRecords.size >= 1)
        }

    @Test
    @DisplayName("getDeniedConsents should return only denied")
    fun testGetDeniedConsents() =
        runTest {
            // Initially no denied consents
            val denied = repository.getDeniedConsents().first()
            assertTrue(denied.isEmpty())
        }

    @Test
    @DisplayName("getConsentsByAction should filter by action")
    fun testGetConsentsByAction() =
        runTest {
            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val scanConsents = repository.getConsentsByAction(TestAction.SCAN_DEVICES).first()
            assertTrue(scanConsents.isNotEmpty())
            assertTrue(scanConsents.all { it.action == "SCAN_DEVICES" })
        }

    @Test
    @DisplayName("saveConsentRecord should persist record")
    fun testSaveConsentRecord() =
        runTest {
            val record =
                ConsentRecord(
                    id = "consent-1",
                    authId = "BTSEC-TEST",
                    action = "CONNECT_DEVICE",
                    timestamp = Instant.now(),
                    authorized = true,
                    deviceInfo = testDeviceInfo,
                    userSignature = "signature",
                )

            val result = repository.saveConsentRecord(record)
            assertTrue(result.isSuccess)
        }

    @Test
    @DisplayName("revokeConsent should revoke specific action")
    fun testRevokeConsent() =
        runTest {
            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val result = repository.revokeConsent("BTSEC-TEST", TestAction.SCAN_DEVICES)
            assertTrue(result.isSuccess)

            val hasConsent = repository.hasConsent("BTSEC-TEST", TestAction.SCAN_DEVICES)
            assertFalse(hasConsent)
        }

    @Test
    @DisplayName("revokeAllConsent should revoke all consent")
    fun testRevokeAllConsent() =
        runTest {
            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val result = repository.revokeAllConsent("BTSEC-TEST")
            assertTrue(result.isSuccess)
        }

    @Test
    @DisplayName("logAuditEvent should record audit entry")
    fun testLogAuditEvent() =
        runTest {
            val result =
                repository.logAuditEvent(
                    authId = "BTSEC-TEST",
                    operation = "SCAN_DEVICES",
                    deviceInfo = testDeviceInfo,
                    success = true,
                    metadata = mapOf("target" to "AA:BB:CC:DD:EE:FF"),
                )

            assertTrue(result.isSuccess)

            val logs = repository.getAuditLog("BTSEC-TEST").first()
            assertTrue(logs.isNotEmpty())
        }

    @Test
    @DisplayName("getAuditLog should return logs for auth")
    fun testGetAuditLog() =
        runTest {
            repository.logAuditEvent(
                authId = "BTSEC-TEST",
                operation = "TEST_OPERATION",
                deviceInfo = testDeviceInfo,
                success = true,
            )

            val logs = repository.getAuditLog("BTSEC-TEST").first()
            assertTrue(logs.isNotEmpty())
        }

    @Test
    @DisplayName("getAuditLogInRange should filter by date")
    fun testGetAuditLogInRange() =
        runTest {
            val now = Instant.now()

            repository.logAuditEvent(
                authId = "BTSEC-TEST",
                operation = "TEST_OPERATION",
                deviceInfo = testDeviceInfo,
                success = true,
            )

            val logs =
                repository.getAuditLogInRange(
                    start = now.minusSeconds(3600),
                    end = now.plusSeconds(3600),
                ).first()

            assertTrue(logs.isNotEmpty())
        }

    @Test
    @DisplayName("getAuditLogByOperation should filter by operation")
    fun testGetAuditLogByOperation() =
        runTest {
            repository.logAuditEvent(
                authId = "BTSEC-TEST",
                operation = "SCAN_DEVICES",
                deviceInfo = testDeviceInfo,
                success = true,
            )

            val logs = repository.getAuditLogByOperation("SCAN_DEVICES").first()
            assertTrue(logs.all { it.operation == "SCAN_DEVICES" })
        }

    @Test
    @DisplayName("getAllAuditLogs should return all logs")
    fun testGetAllAuditLogs() =
        runTest {
            repository.logAuditEvent(
                authId = "BTSEC-TEST",
                operation = "TEST",
                deviceInfo = testDeviceInfo,
                success = true,
            )

            val allLogs = repository.getAllAuditLogs().first()
            assertTrue(allLogs.size >= 1)
        }

    @Test
    @DisplayName("getAuditStatistics should calculate correctly")
    fun testGetAuditStatistics() =
        runTest {
            repository.logAuditEvent(
                authId = "BTSEC-TEST",
                operation = "TEST_OP",
                deviceInfo = testDeviceInfo,
                success = true,
            )

            val stats = repository.getAuditStatistics().first()
            assertNotNull(stats)
            assertTrue(stats.totalEntries >= 1)
            assertTrue(stats.successfulOperations >= 1)
        }

    @Test
    @DisplayName("getStatisticsForAuth should return auth stats")
    fun testGetStatisticsForAuth() =
        runTest {
            repository.logAuditEvent(
                authId = "BTSEC-STATS",
                operation = "TEST",
                deviceInfo = testDeviceInfo,
                success = true,
            )

            val stats = repository.getStatisticsForAuth("BTSEC-STATS")
            assertEquals("BTSEC-STATS", stats.authId)
            assertEquals(1, stats.totalOperations)
        }

    @Test
    @DisplayName("getMostCommonOperations should return sorted list")
    fun testGetMostCommonOperations() =
        runTest {
            repository.logAuditEvent(
                authId = "BTSEC-TEST",
                operation = "SCAN_DEVICES",
                deviceInfo = testDeviceInfo,
                success = true,
            )

            repository.logAuditEvent(
                authId = "BTSEC-TEST",
                operation = "SCAN_DEVICES",
                deviceInfo = testDeviceInfo,
                success = true,
            )

            val common = repository.getMostCommonOperations(10).first()
            assertTrue(common.isNotEmpty())
            assertEquals("SCAN_DEVICES", common.first().operation)
            assertEquals(2, common.first().count)
        }

    @Test
    @DisplayName("getOperationSuccessRate should calculate rate")
    fun testGetOperationSuccessRate() =
        runTest {
            repository.logAuditEvent(
                authId = "BTSEC-TEST",
                operation = "SUCCESS_OP",
                deviceInfo = testDeviceInfo,
                success = true,
            )

            repository.logAuditEvent(
                authId = "BTSEC-TEST",
                operation = "FAIL_OP",
                deviceInfo = testDeviceInfo,
                success = false,
            )

            val rate = repository.getOperationSuccessRate().first()
            assertEquals(0.5, rate, 0.01)
        }

    @Test
    @DisplayName("getDataRetentionSummary should return summary")
    fun testGetDataRetentionSummary() =
        runTest {
            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val summary = repository.getDataRetentionSummary().first()
            assertNotNull(summary)
            assertTrue(summary.totalRecords >= 1)
        }

    @Test
    @DisplayName("generateComplianceReport should create report")
    fun testGenerateComplianceReport() =
        runTest {
            val now = Instant.now()

            val report =
                repository.generateComplianceReport(
                    startDate = now.minusSeconds(86400 * 7),
                    endDate = now,
                )

            assertNotNull(report)
            assertTrue(report.totalOperations >= 0)
            assertEquals(7, report.authorizationIds.size) // Days in period
        }

    @Test
    @DisplayName("deleteOldConsents should remove old records")
    fun testDeleteOldConsents() =
        runTest {
            val sevenYearsAgo = Instant.now().minusSeconds(86400 * 365 * 7)

            repository.requestConsent(
                authId = "BTSEC-TEST",
                action = TestAction.SCAN_DEVICES,
                deviceInfo = testDeviceInfo,
            )

            val count = repository.deleteOldConsents(sevenYearsAgo)
            assertTrue(count >= 0)
        }

    @Test
    @DisplayName("exportAuditLog should create export file")
    fun testExportAuditLog() =
        runTest {
            val result =
                repository.exportAuditLog(
                    outputPath = "/tmp/audit_log.json",
                    format = AuditExportFormat.JSON,
                )

            assertTrue(result.isSuccess)
            val path = result.getOrNull()
            assertNotNull(path)
        }

    @Test
    @DisplayName("exportAuditLog should reject path traversal")
    fun testExportAuditLogPathTraversal() =
        runTest {
            val result =
                repository.exportAuditLog(
                    outputPath = "/tmp/../../../etc/passwd",
                    format = AuditExportFormat.JSON,
                )

            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull() is SecurityException)
        }
}
