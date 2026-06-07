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
import com.btsec.testtool.data.local.dao.BluetoothDao
import com.btsec.testtool.data.local.dao.FuzzingDao
import com.btsec.testtool.data.local.dao.KeyExtractionDao
import com.btsec.testtool.data.local.dao.ReportDao
import com.btsec.testtool.data.local.dao.VulnerabilityDao
import com.btsec.testtool.data.local.entity.SecurityReportEntity
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
class ReportRepositoryImplTest {

    private lateinit var context: Context
    private lateinit var reportDao: ReportDao
    private lateinit var bluetoothDao: BluetoothDao
    private lateinit var vulnerabilityDao: VulnerabilityDao
    private lateinit var fuzzingDao: FuzzingDao
    private lateinit var keyExtractionDao: KeyExtractionDao
    private lateinit var reportGenerator: ReportGenerator
    private lateinit var exportFormatters: ExportFormatters
    private lateinit var repository: ReportRepositoryImpl

    private val testInstant = Instant.parse("2026-03-10T12:00:00Z")

    private fun createTestReport(
        id: String = "report-1",
        authId: String = "AUTH-001",
        status: ReportStatus = ReportStatus.DRAFT
    ) = SecurityReport(
        id = id,
        authId = authId,
        title = "Test Report",
        generatedAt = testInstant,
        testPeriod = ReportPeriod(testInstant.minusSeconds(86400), testInstant),
        targetDevices = emptyList(),
        vulnerabilities = emptyList(),
        fuzzingResults = emptyList(),
        keyExtractionResults = emptyList(),
        executiveSummary = "Test summary",
        findings = emptyList(),
        recommendations = emptyList(),
        appendix = ReportAppendix(
            toolsUsed = emptyList(),
            testMethodology = "",
            limitations = emptyList(),
            glossary = emptyMap(),
            references = emptyList()
        ),
        status = status
    )

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        reportDao = mockk(relaxed = true)
        bluetoothDao = mockk(relaxed = true)
        vulnerabilityDao = mockk(relaxed = true)
        fuzzingDao = mockk(relaxed = true)
        keyExtractionDao = mockk(relaxed = true)
        reportGenerator = mockk(relaxed = true)
        exportFormatters = mockk(relaxed = true)
        repository = ReportRepositoryImpl(
            context, reportDao, bluetoothDao, vulnerabilityDao,
            fuzzingDao, keyExtractionDao, reportGenerator, exportFormatters
        )
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // ========== saveReport ==========

    @Test
    fun `saveReport returns success on successful insert`() = runTest {
        coEvery { reportDao.insertReport(any()) } just Runs

        val report = createTestReport()
        val result = repository.saveReport(report)

        assertThat(result.isSuccess).isTrue()
        coVerify(exactly = 1) { reportDao.insertReport(any()) }
    }

    @Test
    fun `saveReport returns failure on DAO exception`() = runTest {
        coEvery { reportDao.insertReport(any()) } throws RuntimeException("DB error")

        val report = createTestReport()
        val result = repository.saveReport(report)

        assertThat(result.isFailure).isTrue()
    }

    // ========== getReportById ==========

    @Test
    fun `getReportById returns mapped report when found`() = runTest {
        val entity = mockk<SecurityReportEntity>(relaxed = true)
        every { entity.id } returns "report-1"
        every { entity.authId } returns "AUTH-001"
        coEvery { reportDao.getReportById("report-1") } returns entity

        val result = repository.getReportById("report-1")

        assertThat(result).isNotNull()
        assertThat(result!!.id).isEqualTo("report-1")
    }

    @Test
    fun `getReportById returns null when not found`() = runTest {
        coEvery { reportDao.getReportById("nonexistent") } returns null

        val result = repository.getReportById("nonexistent")

        assertThat(result).isNull()
    }

    @Test
    fun `getReportById returns null on DAO exception`() = runTest {
        coEvery { reportDao.getReportById(any()) } throws RuntimeException("DB error")

        val result = repository.getReportById("report-1")

        assertThat(result).isNull()
    }

    // ========== deleteReport ==========

    @Test
    fun `deleteReport returns success on successful delete`() = runTest {
        coEvery { reportDao.deleteReportById("report-1") } just Runs

        val result = repository.deleteReport("report-1")

        assertThat(result.isSuccess).isTrue()
        coVerify { reportDao.deleteReportById("report-1") }
    }

    @Test
    fun `deleteReport returns failure on DAO exception`() = runTest {
        coEvery { reportDao.deleteReportById(any()) } throws RuntimeException("DB error")

        val result = repository.deleteReport("report-1")

        assertThat(result.isFailure).isTrue()
    }

    // ========== archiveReport ==========

    @Test
    fun `archiveReport returns success and updates status`() = runTest {
        coEvery { reportDao.updateReportStatus("report-1", "ARCHIVED") } just Runs

        val result = repository.archiveReport("report-1")

        assertThat(result.isSuccess).isTrue()
        coVerify { reportDao.updateReportStatus("report-1", "ARCHIVED") }
    }

    @Test
    fun `archiveReport returns failure on DAO exception`() = runTest {
        coEvery { reportDao.updateReportStatus(any(), any()) } throws RuntimeException("DB error")

        val result = repository.archiveReport("report-1")

        assertThat(result.isFailure).isTrue()
    }

    // ========== generateSummaryReport ==========

    @Test
    fun `generateSummaryReport returns success with report`() = runTest {
        val result = repository.generateSummaryReport("AUTH-001")

        assertThat(result.isSuccess).isTrue()
        assertThat(result.getOrNull()!!.authId).isEqualTo("AUTH-001")
        assertThat(result.getOrNull()!!.title).isEqualTo("Security Assessment Summary")
    }

    @Test
    fun `generateSummaryReport with deviceAddress returns report`() = runTest {
        val result = repository.generateSummaryReport("AUTH-001", "AA:BB:CC:DD:EE:FF")

        assertThat(result.isSuccess).isTrue()
        assertThat(result.getOrNull()!!.authId).isEqualTo("AUTH-001")
    }

    // ========== generateVulnerabilityReport ==========

    @Test
    fun `generateVulnerabilityReport maps vulnerabilities to target devices`() = runTest {
        val device = BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF", name = "Test", type = BluetoothType.BLE,
            deviceClass = null, bondState = BondState.NONE, rssi = -50,
            txPower = null, firstSeen = testInstant, lastSeen = testInstant
        )
        val vuln = Vulnerability(
            id = "v-1", cveId = "CVE-2026-0001", name = "Test Vuln",
            description = "desc", severity = VulnerabilitySeverity.HIGH,
            cvssScore = 7.5, affectedDevice = device, discoveredAt = testInstant,
            category = VulnerabilityCategory.ENCRYPTION,
            affectedBluetoothVersions = emptyList(),
            mitigation = null
        )

        val result = repository.generateVulnerabilityReport("AUTH-001", listOf(vuln))

        assertThat(result.isSuccess).isTrue()
        val report = result.getOrNull()!!
        assertThat(report.vulnerabilities).hasSize(1)
        assertThat(report.targetDevices).hasSize(1)
        assertThat(report.executiveSummary).contains("1 vulnerabilities")
    }

    // ========== generateFuzzingReport ==========

    @Test
    fun `generateFuzzingReport maps fuzzing results to report`() = runTest {
        val device = BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF", name = "Test", type = BluetoothType.BLE,
            deviceClass = null, bondState = BondState.NONE, rssi = -50,
            txPower = null, firstSeen = testInstant, lastSeen = testInstant
        )
        val fuzzConfig = mockk<com.btsec.testtool.domain.model.FuzzConfig>(relaxed = true)
        every { fuzzConfig.targetDevice } returns device
        val fuzzResult = mockk<com.btsec.testtool.domain.model.FuzzResult>(relaxed = true)
        every { fuzzResult.config } returns fuzzConfig

        val result = repository.generateFuzzingReport("AUTH-001", listOf(fuzzResult))

        assertThat(result.isSuccess).isTrue()
        val report = result.getOrNull()!!
        assertThat(report.fuzzingResults).hasSize(1)
        assertThat(report.executiveSummary).contains("1 fuzzing tests")
    }

    // ========== getAvailableExportFormats ==========

    @Test
    fun `getAvailableExportFormats returns all supported formats`() {
        val formats = repository.getAvailableExportFormats()

        assertThat(formats).containsExactly(
            ExportFormat.PDF, ExportFormat.HTML,
            ExportFormat.JSON, ExportFormat.CSV, ExportFormat.MARKDOWN
        )
    }

    // ========== getAllReports ==========

    @Test
    fun `getAllReports returns mapped reports from DAO`() = runTest {
        val entity = mockk<SecurityReportEntity>(relaxed = true)
        every { entity.id } returns "r-1"
        every { reportDao.getAllReports() } returns flowOf(listOf(entity))

        val reports = repository.getAllReports().first()

        assertThat(reports).hasSize(1)
        assertThat(reports[0].id).isEqualTo("r-1")
    }

    // ========== getReportsByAuthId ==========

    @Test
    fun `getReportsByAuthId returns filtered reports`() = runTest {
        val entity = mockk<SecurityReportEntity>(relaxed = true)
        every { entity.authId } returns "AUTH-001"
        every { reportDao.getReportsByAuthId("AUTH-001") } returns flowOf(listOf(entity))

        val reports = repository.getReportsByAuthId("AUTH-001").first()

        assertThat(reports).hasSize(1)
        assertThat(reports[0].authId).isEqualTo("AUTH-001")
    }

    // ========== getReportsByStatus ==========

    @Test
    fun `getReportsByStatus queries DAO with status name`() = runTest {
        val entity = mockk<SecurityReportEntity>(relaxed = true)
        every { reportDao.getReportsByStatus("DRAFT") } returns flowOf(listOf(entity))

        val reports = repository.getReportsByStatus(ReportStatus.DRAFT).first()

        assertThat(reports).hasSize(1)
        verify { reportDao.getReportsByStatus("DRAFT") }
    }

    // ========== uploadReport ==========

    @Test
    fun `uploadReport returns success with upload id`() = runTest {
        val result = repository.uploadReport("report-1", "https://server.com", "key123")

        assertThat(result.isSuccess).isTrue()
        assertThat(result.getOrNull()).isEqualTo("upload_id")
    }

    // ========== shareReport ==========

    @Test
    fun `shareReport returns success`() = runTest {
        val result = repository.shareReport("report-1", ExportFormat.PDF)

        assertThat(result.isSuccess).isTrue()
    }

    // ========== Template CRUD ==========

    @Test
    fun `createTemplate and getTemplate round-trip`() = runTest {
        val template = ReportTemplate(
            id = "tpl-1", name = "Standard", description = "Std report",
            format = ExportFormat.HTML, includeExecutiveSummary = true,
            includeVulnerabilities = true, includeFuzzingResults = true,
            includeKeyExtraction = true, includeRecommendations = true,
            includeAppendix = true
        )

        repository.createTemplate(template)
        val retrieved = repository.getTemplate("tpl-1")

        assertThat(retrieved).isNotNull()
        assertThat(retrieved!!.name).isEqualTo("Standard")
    }

    @Test
    fun `updateTemplate replaces existing template`() = runTest {
        val template = ReportTemplate(
            id = "tpl-1", name = "Original", description = null,
            format = ExportFormat.HTML, includeExecutiveSummary = true,
            includeVulnerabilities = true, includeFuzzingResults = true,
            includeKeyExtraction = true, includeRecommendations = true,
            includeAppendix = true
        )
        repository.createTemplate(template)

        val updated = template.copy(name = "Updated")
        repository.updateTemplate(updated)

        val retrieved = repository.getTemplate("tpl-1")
        assertThat(retrieved!!.name).isEqualTo("Updated")
    }

    @Test
    fun `deleteTemplate removes template`() = runTest {
        val template = ReportTemplate(
            id = "tpl-1", name = "To Delete", description = null,
            format = ExportFormat.HTML, includeExecutiveSummary = true,
            includeVulnerabilities = true, includeFuzzingResults = true,
            includeKeyExtraction = true, includeRecommendations = true,
            includeAppendix = true
        )
        repository.createTemplate(template)
        repository.deleteTemplate("tpl-1")

        val retrieved = repository.getTemplate("tpl-1")
        assertThat(retrieved).isNull()
    }

    @Test
    fun `getAvailableTemplates returns empty initially`() = runTest {
        val templates = repository.getAvailableTemplates().first()
        assertThat(templates).isEmpty()
    }

    // ========== logReportOperation ==========

    @Test
    fun `logReportOperation appends to logs`() = runTest {
        val operation = ReportOperation(
            id = "op-1",
            timestamp = testInstant,
            operationType = ReportOperationType.GENERATE,
            reportId = "report-1",
            success = true,
            errorMessage = null,
            durationMs = 500L
        )

        repository.logReportOperation(operation)

        val logs = repository.getReportLogs().first()
        assertThat(logs).hasSize(1)
        assertThat(logs[0].id).isEqualTo("op-1")
    }

    // ========== getReportsSummary ==========

    @Test
    fun `getReportsSummary computes dashboard summary`() = runTest {
        val entity = mockk<SecurityReportEntity>(relaxed = true)
        every { reportDao.getAllReports() } returns flowOf(listOf(entity))

        val summary = repository.getReportsSummary().first()

        assertThat(summary.totalReports).isEqualTo(1)
        assertThat(summary.pendingActions).isEqualTo(0)
    }

    // ========== exportToJson ==========

    @Test
    fun `exportToJson returns failure when report not found`() = runTest {
        coEvery { reportDao.getReportById("nonexistent") } returns null

        val result = repository.exportToJson("nonexistent", "/tmp/out.json")

        assertThat(result.isFailure).isTrue()
    }
}
