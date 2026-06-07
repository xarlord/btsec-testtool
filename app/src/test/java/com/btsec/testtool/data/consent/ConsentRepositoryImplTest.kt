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
import app.cash.turbine.test
import com.btsec.testtool.data.local.dao.ConsentDao
import com.btsec.testtool.data.local.entity.AuditLogEntity
import com.btsec.testtool.data.local.entity.ConsentRecordEntity
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import com.google.common.truth.Truth.assertThat
import io.mockk.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.time.Instant

@OptIn(ExperimentalCoroutinesApi::class)
class ConsentRepositoryImplTest {

    private lateinit var context: Context
    private lateinit var consentDao: ConsentDao
    private lateinit var repository: ConsentRepositoryImpl

    private val testDeviceInfo = DeviceInfo(
        platform = "Android",
        model = "Pixel 8",
        androidVersion = "14",
        appVersion = "1.0.0",
        bluetoothAddress = "AA:BB:CC:DD:EE:FF"
    )

    private val testInstant = Instant.parse("2026-01-15T10:30:00Z")

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        consentDao = mockk(relaxed = true)
        repository = ConsentRepositoryImpl(context, consentDao)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // ========== requestConsent ==========

    @Test
    fun `requestConsent inserts record and returns ConsentRecord`() = runTest {
        coEvery { consentDao.insertConsentRecord(any()) } just Runs

        val result = repository.requestConsent(
            authId = "AUTH-001",
            action = TestAction.SCAN_DEVICES,
            deviceInfo = testDeviceInfo
        )

        assertThat(result).isNotNull()
        assertThat(result!!.authId).isEqualTo("AUTH-001")
        assertThat(result.action).isEqualTo(TestAction.SCAN_DEVICES.name)
        assertThat(result.authorized).isTrue()
        assertThat(result.deviceInfo).isEqualTo(testDeviceInfo)

        coVerify(exactly = 1) { consentDao.insertConsentRecord(any()) }
    }

    @Test
    fun `requestConsent returns null when DAO throws`() = runTest {
        coEvery { consentDao.insertConsentRecord(any()) } throws RuntimeException("DB error")

        val result = repository.requestConsent(
            authId = "AUTH-001",
            action = TestAction.SCAN_DEVICES,
            deviceInfo = testDeviceInfo
        )

        assertThat(result).isNull()
    }

    // ========== requestConsentWithContext ==========

    @Test
    fun `requestConsentWithContext delegates to requestConsent`() = runTest {
        coEvery { consentDao.insertConsentRecord(any()) } just Runs

        val result = repository.requestConsentWithContext(
            authId = "AUTH-002",
            action = TestAction.CONNECT_DEVICE,
            context = "Testing device connection",
            deviceInfo = testDeviceInfo
        )

        assertThat(result).isNotNull()
        assertThat(result!!.authId).isEqualTo("AUTH-002")
        assertThat(result.action).isEqualTo(TestAction.CONNECT_DEVICE.name)
    }

    // ========== hasConsent ==========

    @Test
    fun `hasConsent returns true when DAO confirms consent exists`() = runTest {
        coEvery { consentDao.hasConsent("AUTH-001", "SCAN_DEVICES") } returns true

        val result = repository.hasConsent("AUTH-001", TestAction.SCAN_DEVICES)

        assertThat(result).isTrue()
    }

    @Test
    fun `hasConsent returns false when no consent exists`() = runTest {
        coEvery { consentDao.hasConsent("AUTH-001", "SCAN_DEVICES") } returns false

        val result = repository.hasConsent("AUTH-001", TestAction.SCAN_DEVICES)

        assertThat(result).isFalse()
    }

    @Test
    fun `hasConsent returns false on DAO exception`() = runTest {
        coEvery { consentDao.hasConsent(any(), any()) } throws RuntimeException("DB error")

        val result = repository.hasConsent("AUTH-001", TestAction.SCAN_DEVICES)

        assertThat(result).isFalse()
    }

    // ========== getLatestConsent ==========

    @Test
    fun `getLatestConsent returns mapped domain record`() = runTest {
        val entity = ConsentRecordEntity(
            id = "rec-1",
            authId = "AUTH-001",
            action = "SCAN_DEVICES",
            timestamp = testInstant.toEpochMilli(),
            authorized = true,
            deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
            userSignature = null
        )
        coEvery { consentDao.getLatestConsentForAction("AUTH-001", "SCAN_DEVICES") } returns entity

        val result = repository.getLatestConsent("AUTH-001", TestAction.SCAN_DEVICES)

        assertThat(result).isNotNull()
        assertThat(result!!.id).isEqualTo("rec-1")
        assertThat(result.authId).isEqualTo("AUTH-001")
        assertThat(result.action).isEqualTo("SCAN_DEVICES")
    }

    @Test
    fun `getLatestConsent returns null when no record found`() = runTest {
        coEvery { consentDao.getLatestConsentForAction("AUTH-001", "SCAN_DEVICES") } returns null

        val result = repository.getLatestConsent("AUTH-001", TestAction.SCAN_DEVICES)

        assertThat(result).isNull()
    }

    @Test
    fun `getLatestConsent returns null on DAO exception`() = runTest {
        coEvery { consentDao.getLatestConsentForAction(any(), any()) } throws RuntimeException("DB error")

        val result = repository.getLatestConsent("AUTH-001", TestAction.SCAN_DEVICES)

        assertThat(result).isNull()
    }

    // ========== saveConsentRecord ==========

    @Test
    fun `saveConsentRecord returns success on valid insert`() = runTest {
        coEvery { consentDao.insertConsentRecord(any()) } just Runs

        val record = ConsentRecord(
            id = "rec-save",
            authId = "AUTH-001",
            action = TestAction.START_FUZZING.name,
            timestamp = testInstant,
            authorized = true,
            deviceInfo = testDeviceInfo
        )

        val result = repository.saveConsentRecord(record)

        assertThat(result.isSuccess).isTrue()
        coVerify(exactly = 1) { consentDao.insertConsentRecord(any()) }
    }

    @Test
    fun `saveConsentRecord returns failure on DAO exception`() = runTest {
        coEvery { consentDao.insertConsentRecord(any()) } throws RuntimeException("DB error")

        val record = ConsentRecord(
            id = "rec-save-fail",
            authId = "AUTH-001",
            action = TestAction.START_FUZZING.name,
            timestamp = testInstant,
            authorized = true,
            deviceInfo = testDeviceInfo
        )

        val result = repository.saveConsentRecord(record)

        assertThat(result.isFailure).isTrue()
    }

    // ========== revokeConsent ==========

    @Test
    fun `revokeConsent returns success when DAO deletes`() = runTest {
        coEvery { consentDao.deleteConsentsByAuthId("AUTH-001") } just Runs

        val result = repository.revokeConsent("AUTH-001", TestAction.SCAN_DEVICES)

        assertThat(result.isSuccess).isTrue()
        coVerify { consentDao.deleteConsentsByAuthId("AUTH-001") }
    }

    @Test
    fun `revokeConsent returns failure on DAO exception`() = runTest {
        coEvery { consentDao.deleteConsentsByAuthId(any()) } throws RuntimeException("DB error")

        val result = repository.revokeConsent("AUTH-001", TestAction.SCAN_DEVICES)

        assertThat(result.isFailure).isTrue()
    }

    // ========== revokeAllConsent ==========

    @Test
    fun `revokeAllConsent returns success`() = runTest {
        coEvery { consentDao.deleteConsentsByAuthId("AUTH-001") } just Runs

        val result = repository.revokeAllConsent("AUTH-001")

        assertThat(result.isSuccess).isTrue()
    }

    // ========== deleteOldConsents ==========

    @Test
    fun `deleteOldConsents returns deleted count on success`() = runTest {
        coEvery { consentDao.deleteConsentsOlderThan(any()) } returns 5

        val result = repository.deleteOldConsents(testInstant)

        assertThat(result.isSuccess).isTrue()
        assertThat(result.getOrNull()).isEqualTo(5)
    }

    @Test
    fun `deleteOldConsents returns failure on DAO exception`() = runTest {
        coEvery { consentDao.deleteConsentsOlderThan(any()) } throws RuntimeException("DB error")

        val result = repository.deleteOldConsents(testInstant)

        assertThat(result.isFailure).isTrue()
    }

    // ========== logAuditEvent ==========

    @Test
    fun `logAuditEvent returns success and inserts audit log`() = runTest {
        coEvery { consentDao.insertAuditLog(any()) } just Runs

        val result = repository.logAuditEvent(
            authId = "AUTH-001",
            operation = "SCAN",
            deviceInfo = testDeviceInfo,
            success = true,
            metadata = mapOf("key" to "value")
        )

        assertThat(result.isSuccess).isTrue()
        coVerify(exactly = 1) { consentDao.insertAuditLog(any()) }
    }

    @Test
    fun `logAuditEvent returns failure on DAO exception`() = runTest {
        coEvery { consentDao.insertAuditLog(any()) } throws RuntimeException("DB error")

        val result = repository.logAuditEvent(
            authId = "AUTH-001",
            operation = "SCAN",
            deviceInfo = testDeviceInfo,
            success = false
        )

        assertThat(result.isFailure).isTrue()
    }

    // ========== getConsentRecords ==========

    @Test
    fun `getConsentRecords returns mapped flow from DAO`() = runTest {
        val entities = listOf(
            ConsentRecordEntity(
                id = "rec-1",
                authId = "AUTH-001",
                action = "SCAN_DEVICES",
                timestamp = testInstant.toEpochMilli(),
                authorized = true,
                deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
                userSignature = null
            )
        )
        every { consentDao.getConsentRecordsByAuthId("AUTH-001") } returns flowOf(entities)

        val records = repository.getConsentRecords("AUTH-001").first()

        assertThat(records).hasSize(1)
        assertThat(records[0].id).isEqualTo("rec-1")
    }

    // ========== getConsentStatus ==========

    @Test
    fun `getConsentStatus maps all TestActions with consent state`() = runTest {
        val entities = listOf(
            ConsentRecordEntity(
                id = "rec-1",
                authId = "AUTH-001",
                action = "SCAN_DEVICES",
                timestamp = testInstant.toEpochMilli(),
                authorized = true,
                deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
                userSignature = null
            )
        )
        every { consentDao.getConsentRecordsByAuthId("AUTH-001") } returns flowOf(entities)

        val statusMap = repository.getConsentStatus("AUTH-001").first()

        assertThat(statusMap[TestAction.SCAN_DEVICES]).isTrue()
        // Other actions should have no matching consent → false
        assertThat(statusMap[TestAction.EXTRACT_KEYS]).isFalse()
    }

    // ========== getAuditStatistics ==========

    @Test
    fun `getAuditStatistics returns computed statistics`() = runTest {
        coEvery { consentDao.getAuditLogCount() } returns 10
        coEvery { consentDao.getSuccessfulOperationCount() } returns 8
        coEvery { consentDao.getFailedOperationCount() } returns 2

        val stats = repository.getAuditStatistics().first()

        assertThat(stats.totalEntries).isEqualTo(10)
        assertThat(stats.successfulOperations).isEqualTo(8)
        assertThat(stats.failedOperations).isEqualTo(2)
        assertThat(stats.successRate).isWithin(0.01).of(0.8)
    }

    @Test
    fun `getAuditStatistics returns zeros on DAO exception`() = runTest {
        coEvery { consentDao.getAuditLogCount() } throws RuntimeException("DB error")

        val stats = repository.getAuditStatistics().first()

        assertThat(stats.totalEntries).isEqualTo(0)
        assertThat(stats.successRate).isEqualTo(0.0)
    }

    // ========== getStatisticsForAuth ==========

    @Test
    fun `getStatisticsForAuth returns computed auth stats`() = runTest {
        coEvery { consentDao.getAuditLogCount() } returns 15
        coEvery { consentDao.getSuccessfulOperationCount() } returns 12
        coEvery { consentDao.getFailedOperationCount() } returns 3

        val stats = repository.getStatisticsForAuth("AUTH-001")

        assertThat(stats.authId).isEqualTo("AUTH-001")
        assertThat(stats.totalOperations).isEqualTo(15)
        assertThat(stats.successfulOperations).isEqualTo(12)
        assertThat(stats.failedOperations).isEqualTo(3)
    }

    @Test
    fun `getStatisticsForAuth returns zeros on DAO exception`() = runTest {
        coEvery { consentDao.getAuditLogCount() } throws RuntimeException("DB error")

        val stats = repository.getStatisticsForAuth("AUTH-001")

        assertThat(stats.totalOperations).isEqualTo(0)
        assertThat(stats.authId).isEqualTo("AUTH-001")
    }

    // ========== generateComplianceReport ==========

    @Test
    fun `generateComplianceReport returns report with DAO counts`() = runTest {
        coEvery { consentDao.getConsentCount() } returns 20
        coEvery { consentDao.getAuditLogCount() } returns 50

        val report = repository.generateComplianceReport(
            startDate = testInstant,
            endDate = testInstant.plusSeconds(86400)
        )

        assertThat(report.totalOperations).isEqualTo(50)
        assertThat(report.consentRecords).isEqualTo(20)
        assertThat(report.reportId).isNotEmpty()
    }

    @Test
    fun `generateComplianceReport returns empty report on DAO exception`() = runTest {
        coEvery { consentDao.getConsentCount() } throws RuntimeException("DB error")

        val report = repository.generateComplianceReport(
            startDate = testInstant,
            endDate = testInstant.plusSeconds(86400)
        )

        assertThat(report.totalOperations).isEqualTo(0)
        assertThat(report.consentRecords).isEqualTo(0)
    }

    // ========== getMostCommonOperations ==========

    @Test
    fun `getMostCommonOperations returns sorted operation counts`() = runTest {
        val entities = listOf(
            AuditLogEntity(
                id = "1", authId = "A", timestamp = 1000L, operation = "SCAN",
                success = true, errorMessage = null,
                deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
                durationMs = 100L, metadata = "{}"
            ),
            AuditLogEntity(
                id = "2", authId = "A", timestamp = 2000L, operation = "SCAN",
                success = true, errorMessage = null,
                deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
                durationMs = 200L, metadata = "{}"
            ),
            AuditLogEntity(
                id = "3", authId = "A", timestamp = 3000L, operation = "FUZZ",
                success = true, errorMessage = null,
                deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
                durationMs = 300L, metadata = "{}"
            )
        )
        every { consentDao.getAllAuditLogs() } returns flowOf(entities)

        val operations = repository.getMostCommonOperations(limit = 5).first()

        assertThat(operations).hasSize(2)
        assertThat(operations[0].operation).isEqualTo("SCAN")
        assertThat(operations[0].count).isEqualTo(2)
        assertThat(operations[1].operation).isEqualTo("FUZZ")
        assertThat(operations[1].count).isEqualTo(1)
    }

    // ========== getOperationSuccessRate ==========

    @Test
    fun `getOperationSuccessRate computes correct rate`() = runTest {
        val entities = listOf(
            AuditLogEntity(
                id = "1", authId = "A", timestamp = 1000L, operation = "SCAN",
                success = true, errorMessage = null,
                deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
                durationMs = 100L, metadata = "{}"
            ),
            AuditLogEntity(
                id = "2", authId = "A", timestamp = 2000L, operation = "SCAN",
                success = false, errorMessage = "timeout",
                deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
                durationMs = 200L, metadata = "{}"
            ),
            AuditLogEntity(
                id = "3", authId = "A", timestamp = 3000L, operation = "SCAN",
                success = true, errorMessage = null,
                deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
                durationMs = 300L, metadata = "{}"
            )
        )
        every { consentDao.getAllAuditLogs() } returns flowOf(entities)

        val rate = repository.getOperationSuccessRate().first()

        assertThat(rate).isWithin(0.01).of(2.0 / 3.0)
    }

    @Test
    fun `getOperationSuccessRate returns 0 when no logs`() = runTest {
        every { consentDao.getAllAuditLogs() } returns flowOf(emptyList())

        val rate = repository.getOperationSuccessRate().first()

        assertThat(rate).isEqualTo(0.0)
    }

    // ========== getRecordsEligibleForDeletion ==========

    @Test
    fun `getRecordsEligibleForDeletion returns 0 on success`() = runTest {
        coEvery { consentDao.deleteConsentsOlderThan(any()) } returns 0

        val result = repository.getRecordsEligibleForDeletion()

        assertThat(result).isEqualTo(0)
    }

    @Test
    fun `getRecordsEligibleForDeletion returns 0 on exception`() = runTest {
        coEvery { consentDao.deleteConsentsOlderThan(any()) } throws RuntimeException("DB error")

        val result = repository.getRecordsEligibleForDeletion()

        assertThat(result).isEqualTo(0)
    }

    // ========== getDataRetentionSummary ==========

    @Test
    fun `getDataRetentionSummary computes age buckets`() = runTest {
        val recentRecord = ConsentRecordEntity(
            id = "recent", authId = "A", action = "SCAN",
            timestamp = Instant.now().toEpochMilli(),
            authorized = true,
            deviceInfo = """{"platform":"Android","model":"Pixel 8","androidVersion":"14","appVersion":"1.0.0","bluetoothAddress":"AA:BB:CC:DD:EE:FF"}""",
            userSignature = null
        )
        every { consentDao.getAllConsentRecords() } returns flowOf(listOf(recentRecord))

        val summary = repository.getDataRetentionSummary().first()

        assertThat(summary.totalRecords).isEqualTo(1)
        assertThat(summary.recordsUnderOneYear).isEqualTo(1)
        assertThat(summary.recordsOverSevenYears).isEqualTo(0)
    }
}
