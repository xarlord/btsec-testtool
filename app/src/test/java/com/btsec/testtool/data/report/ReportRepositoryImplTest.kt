/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.report

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
import java.io.File
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for ReportRepositoryImpl.
 */
@ExtendWith(MockitoExtension::class)
@DisplayName("ReportRepositoryImpl Tests")
class ReportRepositoryImplTest {

    @Mock
    private lateinit var mockContext: Context

    private lateinit var repository: ReportRepositoryImpl

    @BeforeEach
    fun setUp() {
        repository = ReportRepositoryImpl(mockContext)
    }

    @Test
    @DisplayName("generateReport should emit progress updates")
    fun testGenerateReportEmitsProgress() = runTest {
        val config = ReportConfig(
            title = "Test Report",
            includeVulnerabilities = true,
            includeFuzzingResults = true,
            includeKeyExtraction = true
        )

        val progressUpdates = mutableListOf<ReportGenerationProgress>()

        repository.generateReport("BTSEC-TEST", config).collect { progress ->
            progressUpdates.add(progress)
        }

        assertTrue(progressUpdates.isNotEmpty())
        assertEquals(ReportGenerationStatus.COMPLETED, progressUpdates.lastOrNull()?.status)
    }

    @Test
    @DisplayName("generateSummaryReport should create report")
    fun testGenerateSummaryReport() = runTest {
        val result = repository.generateSummaryReport("BTSEC-TEST")

        assertTrue(result.isSuccess)
        val report = result.getOrNull()
        assertNotNull(report)
        assertEquals("Security Assessment Summary", report?.title)
    }

    @Test
    @DisplayName("generateVulnerabilityReport should include vulnerabilities")
    fun testGenerateVulnerabilityReport() = runTest {
        val vulnerabilities = listOf(
            createTestVulnerability("CVE-2019-9506"),
            createTestVulnerability("CVE-2020-10135")
        )

        val result = repository.generateVulnerabilityReport("BTSEC-TEST", vulnerabilities)

        assertTrue(result.isSuccess)
        val report = result.getOrNull()
        assertNotNull(report)
        assertEquals(2, report?.vulnerabilities?.size)
    }

    @Test
    @DisplayName("generateFuzzingReport should include fuzzing results")
    fun testGenerateFuzzingReport() = runTest {
        val fuzzingResults = listOf(
            createTestFuzzResult("fuzz-1"),
            createTestFuzzResult("fuzz-2")
        )

        val result = repository.generateFuzzingReport("BTSEC-TEST", fuzzingResults)

        assertTrue(result.isSuccess)
        val report = result.getOrNull()
        assertNotNull(report)
        assertEquals(2, report?.fuzzingResults?.size)
    }

    @Test
    @DisplayName("generateKeyExtractionReport should include extraction results")
    fun testGenerateKeyExtractionReport() = runTest {
        val extractionResults = listOf(
            createTestKeyExtractionResult("key-1"),
            createTestKeyExtractionResult("key-2")
        )

        val result = repository.generateKeyExtractionReport("BTSEC-TEST", extractionResults)

        assertTrue(result.isSuccess)
        val report = result.getOrNull()
        assertNotNull(report)
        assertEquals(2, report?.keyExtractionResults?.size)
    }

    @Test
    @DisplayName("saveReport should persist report")
    fun testSaveReport() = runTest {
        val report = createTestReport("report-1")

        val result = repository.saveReport(report)
        assertTrue(result.isSuccess)

        val retrieved = repository.getReportById("report-1")
        assertNotNull(retrieved)
        assertEquals("report-1", retrieved?.id)
    }

    @Test
    @DisplayName("getAllReports should return all reports")
    fun testGetAllReports() = runTest {
        val report1 = createTestReport("report-1")
        val report2 = createTestReport("report-2")

        repository.saveReport(report1)
        repository.saveReport(report2)

        val reports = repository.getAllReports().first()
        assertTrue(reports.size >= 2)
    }

    @Test
    @DisplayName("getReportsByAuthId should filter by auth ID")
    fun testGetReportsByAuthId() = runTest {
        val report1 = createTestReport("report-1", "BTSEC-AUTH-1")
        val report2 = createTestReport("report-2", "BTSEC-AUTH-2")

        repository.saveReport(report1)
        repository.saveReport(report2)

        val auth1Reports = repository.getReportsByAuthId("BTSEC-AUTH-1").first()
        assertTrue(auth1Reports.all { it.authId == "BTSEC-AUTH-1" })
    }

    @Test
    @DisplayName("getReportsByStatus should filter by status")
    fun testGetReportsByStatus() = runTest {
        val draftReport = createTestReport("draft-1", status = ReportStatus.DRAFT)
        val finalReport = createTestReport("final-1", status = ReportStatus.FINAL)

        repository.saveReport(draftReport)
        repository.saveReport(finalReport)

        val draftReports = repository.getReportsByStatus(ReportStatus.DRAFT).first()
        assertTrue(draftReports.all { it.status == ReportStatus.DRAFT })

        val finalReports = repository.getReportsByStatus(ReportStatus.FINAL).first()
        assertTrue(finalReports.all { it.status == ReportStatus.FINAL })
    }

    @Test
    @DisplayName("deleteReport should remove report")
    fun testDeleteReport() = runTest {
        val report = createTestReport("to-delete")

        repository.saveReport(report)
        val result = repository.deleteReport("to-delete")

        assertTrue(result.isSuccess)
        val retrieved = repository.getReportById("to-delete")
        assertNull(retrieved)
    }

    @Test
    @DisplayName("archiveReport should change status to archived")
    fun testArchiveReport() = runTest {
        val report = createTestReport("archive-me", status = ReportStatus.DRAFT)

        repository.saveReport(report)
        val result = repository.archiveReport("archive-me")

        assertTrue(result.isSuccess)

        val archived = repository.getReportById("archive-me")
        assertEquals(ReportStatus.ARCHIVED, archived?.status)
    }

    @Test
    @DisplayName("exportToJson should create JSON file")
    fun testExportToJson() = runTest {
        val report = createTestReport("json-export")

        repository.saveReport(report)
        val outputPath = "/tmp/test_export.json"

        val result = repository.exportToJson("json-export", outputPath)

        assertTrue(result.isSuccess)
        val file = result.getOrNull()
        assertTrue(file?.exists() == true)
    }

    @Test
    @DisplayName("exportToHtml should create HTML file")
    fun testExportToHtml() = runTest {
        val report = createTestReport("html-export")

        repository.saveReport(report)
        val outputPath = "/tmp/test_export.html"

        val result = repository.exportToHtml("html-export", outputPath)

        assertTrue(result.isSuccess)
        val file = result.getOrNull()
        assertTrue(file?.exists() == true)
    }

    @Test
    @DisplayName("getAvailableExportFormats should return supported formats")
    fun testGetAvailableExportFormats() {
        val formats = repository.getAvailableExportFormats()

        assertTrue(formats.contains(ExportFormat.PDF))
        assertTrue(formats.contains(ExportFormat.HTML))
        assertTrue(formats.contains(ExportFormat.JSON))
        assertTrue(formats.contains(ExportFormat.CSV))
        assertTrue(formats.contains(ExportFormat.MARKDOWN))
    }

    @Test
    @DisplayName("getReportStatistics should calculate correctly")
    fun testGetReportStatistics() = runTest {
        val report = createTestReport("stats-report")

        repository.saveReport(report)

        val stats = repository.getReportStatistics().first()
        assertNotNull(stats)
        assertTrue(stats.totalReports >= 1)
    }

    @Test
    @DisplayName("getReportsSummary should return summary")
    fun testGetReportsSummary() = runTest {
        val report = createTestReport("summary-report")

        repository.saveReport(report)

        val summary = repository.getReportsSummary().first()
        assertNotNull(summary)
        assertTrue(summary.totalReports >= 1)
    }

    @Test
    @DisplayName("createTemplate should add new template")
    fun testCreateTemplate() = runTest {
        val template = ReportTemplate(
            id = "template-1",
            name = "Custom Template",
            description = "Custom report template",
            format = ExportFormat.PDF,
            includeExecutiveSummary = true,
            includeVulnerabilities = true,
            includeFuzzingResults = false,
            includeKeyExtraction = false,
            includeRecommendations = true,
            includeAppendix = false,
            isDefault = false
        )

        val result = repository.createTemplate(template)
        assertTrue(result.isSuccess)

        val templates = repository.getAvailableTemplates().first()
        assertTrue(templates.any { it.id == "template-1" })
    }

    @Test
    @DisplayName("updateTemplate should modify template")
    fun testUpdateTemplate() = runTest {
        val template = ReportTemplate(
            id = "template-update",
            name = "Original Name",
            description = "Original description",
            format = ExportFormat.PDF,
            includeExecutiveSummary = true,
            includeVulnerabilities = true,
            includeFuzzingResults = true,
            includeKeyExtraction = true,
            includeRecommendations = true,
            includeAppendix = true,
            isDefault = false
        )

        repository.createTemplate(template)

        val updated = template.copy(name = "Updated Name")

        val result = repository.updateTemplate(updated)
        assertTrue(result.isSuccess)
    }

    @Test
    @DisplayName("deleteTemplate should remove template")
    fun testDeleteTemplate() = runTest {
        val template = ReportTemplate(
            id = "template-delete",
            name = "Delete Me",
            description = "Template to delete",
            format = ExportFormat.HTML,
            includeExecutiveSummary = false,
            includeVulnerabilities = false,
            includeFuzzingResults = false,
            includeKeyExtraction = false,
            includeRecommendations = false,
            includeAppendix = false,
            isDefault = false
        )

        repository.createTemplate(template)
        val result = repository.deleteTemplate("template-delete")

        assertTrue(result.isSuccess)

        val templates = repository.getAvailableTemplates().first()
        assertFalse(templates.any { it.id == "template-delete" })
    }

    @Test
    @DisplayName("logReportOperation should record operation")
    fun testLogReportOperation() = runTest {
        val operation = ReportOperation(
            id = "op-1",
            timestamp = Instant.now(),
            operationType = ReportOperationType.GENERATE,
            reportId = "report-1",
            success = true,
            errorMessage = null,
            durationMs = 5000
        )

        repository.logReportOperation(operation)

        val logs = repository.getReportLogs().first()
        assertTrue(logs.any { it.id == "op-1" })
    }

    // Helper functions

    private fun createTestReport(
        id: String,
        authId: String = "BTSEC-TEST",
        status: ReportStatus = ReportStatus.DRAFT
    ): SecurityReport {
        val now = Instant.now()
        return SecurityReport(
            id = id,
            authId = authId,
            title = "Test Report",
            generatedAt = now,
            testPeriod = ReportPeriod(now.minusSeconds(86400), now),
            targetDevices = emptyList(),
            vulnerabilities = emptyList(),
            fuzzingResults = emptyList(),
            keyExtractionResults = emptyList(),
            executiveSummary = "Test summary",
            findings = emptyList(),
            recommendations = emptyList(),
            appendix = ReportAppendix(
                toolsUsed = emptyList(),
                testMethodology = "Test methodology",
                limitations = emptyList(),
                glossary = emptyMap(),
                references = emptyList()
            ),
            status = status
        )
    }

    private fun createTestVulnerability(cveId: String): Vulnerability {
        return Vulnerability(
            id = "vuln-$cveId",
            cveId = cveId,
            name = "Test Vulnerability",
            description = "Test description",
            severity = VulnerabilitySeverity.HIGH,
            cvssScore = 7.5,
            affectedDevice = createTestDevice(),
            discoveredAt = Instant.now(),
            category = VulnerabilityCategory.PROTOCOL,
            affectedBluetoothVersions = emptyList(),
            references = emptyList(),
            mitigation = "Update firmware",
            verified = false
        )
    }

    private fun createTestFuzzResult(id: String): FuzzResult {
        return FuzzResult(
            id = id,
            config = createTestFuzzConfig(),
            startTime = Instant.now().minusSeconds(60),
            endTime = Instant.now(),
            status = FuzzStatus.COMPLETED,
            packetsSent = 100,
            packetsReceived = 80,
            errors = emptyList(),
            findings = emptyList(),
            captureFile = null
        )
    }

    private fun createTestKeyExtractionResult(id: String): KeyExtractionResult {
        return KeyExtractionResult(
            id = id,
            targetDevice = createTestDevice(),
            keyType = KeyType.LTK,
            extracted = false,
            keyValue = null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.LOW,
            timestamp = Instant.now()
        )
    }

    private fun createTestDevice(): BluetoothDevice {
        return BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF",
            name = "Test Device",
            type = DeviceType.BLE,
            deviceClass = DeviceClass.UNCATEGORIZED,
            bondState = BondState.NONE,
            rssi = -60,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
            scanCount = 1
        )
    }

    private fun createTestFuzzConfig(): FuzzConfig {
        return FuzzConfig(
            targetDevice = createTestDevice(),
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 100,
            packetsPerSecond = 10,
            dataPatterns = emptyList(),
            durationSeconds = 60
        )
    }
}
