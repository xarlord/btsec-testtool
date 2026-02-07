/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.*
import java.io.File
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for ReportGenerationUseCase.
 */
@ExtendWith(MockitoExtension::class)
@DisplayName("ReportGenerationUseCase Tests")
class ReportGenerationUseCaseTest {

    @Mock
    private lateinit var reportRepository: ReportRepository

    @Mock
    private lateinit var vulnerabilityRepository: VulnerabilityRepository

    @Mock
    private lateinit var fuzzingRepository: FuzzingRepository

    @Mock
    private lateinit var keyExtractionRepository: KeyExtractionRepository

    @Mock
    private lateinit var authorizationUseCase: AuthorizationUseCase

    private lateinit var useCase: ReportGenerationUseCase

    private lateinit var testAuthorization: Authorization

    @BeforeEach
    fun setUp() {
        useCase = ReportGenerationUseCase(
            reportRepository,
            vulnerabilityRepository,
            fuzzingRepository,
            keyExtractionRepository,
            authorizationUseCase
        )

        testAuthorization = Authorization(
            authId = "BTSEC-20260207-A1B2C3D4",
            issuedTo = "Security Researcher",
            issuedBy = "Security Authority",
            issuedAt = Instant.now(),
            expiresAt = Instant.now().plusSeconds(86400),
            authorizedActions = setOf(TestAction.GENERATE_REPORT),
            scope = TestScope(
                authId = "BTSEC-TEST",
                authorizedTargets = emptyList(),
                allowedActions = emptySet(),
                validFrom = Instant.now(),
                validUntil = Instant.now().plusSeconds(3600),
                maxPacketsPerSecond = 100
            ),
            signature = "test-signature",
            terms = listOf("Authorized testing only")
        )
    }

    @Test
    @DisplayName("generateReport should succeed when authorized")
    fun testGenerateReportAuthorized() = runTest {
        whenever(authorizationUseCase.getCurrentAuthorization())
            .thenReturn(flowOf(testAuthorization))
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), mock()))

        val config = ReportConfig(
            title = "Test Report",
            includeVulnerabilities = true,
            includeFuzzingResults = true,
            includeKeyExtraction = true
        )

        val result = useCase.generateReport(config)

        assertTrue(result is ReportGenerationResult.Started)
        assertEquals("BTSEC-20260207-A1B2C3D4", (result as ReportGenerationResult.Started).authId)
        verify(reportRepository).generateReport(eq("BTSEC-20260207-A1B2C3D4"), eq(config))
    }

    @Test
    @DisplayName("generateReport should fail when not authorized")
    fun testGenerateReportNotAuthorized() = runTest {
        whenever(authorizationUseCase.getCurrentAuthorization())
            .thenReturn(flowOf(null))

        val config = ReportConfig(
            title = "Test Report",
            includeVulnerabilities = true,
            includeFuzzingResults = false,
            includeKeyExtraction = false
        )

        val result = useCase.generateReport(config)

        assertTrue(result is ReportGenerationResult.NotAuthorized)
    }

    @Test
    @DisplayName("generateReport should require consent when denied")
    fun testGenerateReportConsentDenied() = runTest {
        whenever(authorizationUseCase.getCurrentAuthorization())
            .thenReturn(flowOf(testAuthorization))
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.ConsentDenied(mock()))

        val config = ReportConfig(
            title = "Test Report",
            includeVulnerabilities = true,
            includeFuzzingResults = false,
            includeKeyExtraction = false
        )

        val result = useCase.generateReport(config)

        assertTrue(result is ReportGenerationResult.ConsentRequired)
    }

    @Test
    @DisplayName("generateSummaryReport should generate summary")
    fun testGenerateSummaryReport() = runTest {
        whenever(authorizationUseCase.getCurrentAuthorization())
            .thenReturn(flowOf(testAuthorization))

        val report = createTestReport()
        whenever(reportRepository.generateSummaryReport(any(), any()))
            .thenReturn(Result.success(report))

        val result = useCase.generateSummaryReport()

        assertTrue(result.isSuccess)
        assertEquals("Test Report", result.getOrNull()?.title)
    }

    @Test
    @DisplayName("generateVulnerabilityReport should generate report")
    fun testGenerateVulnerabilityReport() = runTest {
        whenever(authorizationUseCase.getCurrentAuthorization())
            .thenReturn(flowOf(testAuthorization))

        val vulnerabilities = listOf(createTestVulnerability())
        whenever(vulnerabilityRepository.getAllDiscoveredVulnerabilities())
            .thenReturn(flowOf(vulnerabilities))

        val report = createTestReport()
        whenever(reportRepository.generateVulnerabilityReport(any(), any()))
            .thenReturn(Result.success(report))

        val result = useCase.generateVulnerabilityReport()

        assertTrue(result.isSuccess)
        verify(reportRepository).generateVulnerabilityReport(eq("BTSEC-20260207-A1B2C3D4"), any())
    }

    @Test
    @DisplayName("generateFuzzingReport should generate report")
    fun testGenerateFuzzingReport() = runTest {
        whenever(authorizationUseCase.getCurrentAuthorization())
            .thenReturn(flowOf(testAuthorization))

        val fuzzingResults = listOf(createTestFuzzResult())
        whenever(fuzzingRepository.getAllFuzzingResults())
            .thenReturn(flowOf(fuzzingResults))

        val report = createTestReport()
        whenever(reportRepository.generateFuzzingReport(any(), any()))
            .thenReturn(Result.success(report))

        val result = useCase.generateFuzzingReport()

        assertTrue(result.isSuccess)
        verify(reportRepository).generateFuzzingReport(eq("BTSEC-20260207-A1B2C3D4"), any())
    }

    @Test
    @DisplayName("getAllReports should return all reports")
    fun testGetAllReports() = runTest {
        val reports = listOf(createTestReport())
        whenever(reportRepository.getAllReports())
            .thenReturn(flowOf(reports))

        val result = useCase.getAllReports().first()

        assertEquals(1, result.size)
    }

    @Test
    @DisplayName("getReportsByAuthId should filter by auth ID")
    fun testGetReportsByAuthId() = runTest {
        val reports = listOf(createTestReport("report-1", "BTSEC-20260207-A1B2C3D4"))
        whenever(reportRepository.getReportsByAuthId(any()))
            .thenReturn(flowOf(reports))

        val result = useCase.getReportsByAuthId("BTSEC-20260207-A1B2C3D4").first()

        assertEquals(1, result.size)
        verify(reportRepository).getReportsByAuthId("BTSEC-20260207-A1B2C3D4")
    }

    @Test
    @DisplayName("getReportsByStatus should filter by status")
    fun testGetReportsByStatus() = runTest {
        val reports = listOf(createTestReport("report-1", status = ReportStatus.DRAFT))
        whenever(reportRepository.getReportsByStatus(any()))
            .thenReturn(flowOf(reports))

        val result = useCase.getReportsByStatus(ReportStatus.DRAFT).first()

        assertEquals(1, result.size)
        verify(reportRepository).getReportsByStatus(ReportStatus.DRAFT)
    }

    @Test
    @DisplayName("getReportById should return specific report")
    fun testGetReportById() = runTest {
        val report = createTestReport()
        whenever(reportRepository.getReportById(any()))
            .thenReturn(report)

        val result = useCase.getReportById("report-1")

        assertNotNull(result)
        assertEquals("report-1", result?.id)
    }

    @Test
    @DisplayName("deleteReport should delete report")
    fun testDeleteReport() = runTest {
        whenever(reportRepository.deleteReport(any()))
            .thenReturn(Result.success(Unit))

        val result = useCase.deleteReport("report-1")

        assertTrue(result.isSuccess)
        verify(reportRepository).deleteReport("report-1")
    }

    @Test
    @DisplayName("archiveReport should archive report")
    fun testArchiveReport() = runTest {
        whenever(reportRepository.archiveReport(any()))
            .thenReturn(Result.success(Unit))

        val result = useCase.archiveReport("report-1")

        assertTrue(result.isSuccess)
        verify(reportRepository).archiveReport("report-1")
    }

    @Test
    @DisplayName("exportToPdf should export PDF")
    fun testExportToPdf() = runTest {
        val file = File("/tmp/test.pdf")
        whenever(reportRepository.exportToPdf(any(), any()))
            .thenReturn(Result.success(file))

        val result = useCase.exportToPdf("report-1", "/tmp/test.pdf")

        assertTrue(result.isSuccess)
        assertEquals(file, result.getOrNull())
    }

    @Test
    @DisplayName("exportToHtml should export HTML")
    fun testExportToHtml() = runTest {
        val file = File("/tmp/test.html")
        whenever(reportRepository.exportToHtml(any(), any()))
            .thenReturn(Result.success(file))

        val result = useCase.exportToHtml("report-1", "/tmp/test.html")

        assertTrue(result.isSuccess)
        assertEquals(file, result.getOrNull())
    }

    @Test
    @DisplayName("exportToJson should export JSON")
    fun testExportToJson() = runTest {
        val file = File("/tmp/test.json")
        whenever(reportRepository.exportToJson(any(), any()))
            .thenReturn(Result.success(file))

        val result = useCase.exportToJson("report-1", "/tmp/test.json")

        assertTrue(result.isSuccess)
        assertEquals(file, result.getOrNull())
    }

    @Test
    @DisplayName("exportToCsv should export CSV")
    fun testExportToCsv() = runTest {
        val file = File("/tmp/test.csv")
        whenever(reportRepository.exportToCsv(any(), any()))
            .thenReturn(Result.success(file))

        val result = useCase.exportToCsv("report-1", "/tmp/test.csv")

        assertTrue(result.isSuccess)
        assertEquals(file, result.getOrNull())
    }

    @Test
    @DisplayName("getAvailableExportFormats should return formats")
    fun testGetAvailableExportFormats() = runTest {
        val formats = listOf(ExportFormat.PDF, ExportFormat.HTML, ExportFormat.JSON)
        whenever(reportRepository.getAvailableExportFormats())
            .thenReturn(formats)

        val result = useCase.getAvailableExportFormats()

        assertEquals(3, result.size)
        assertTrue(result.contains(ExportFormat.PDF))
    }

    @Test
    @DisplayName("exportToMultipleFormats should export to all formats")
    fun testExportToMultipleFormats() = runTest {
        val files = listOf(File("/tmp/test.pdf"), File("/tmp/test.html"))
        whenever(reportRepository.exportToMultipleFormats(any(), any(), any()))
            .thenReturn(Result.success(files))

        val formats = listOf(ExportFormat.PDF, ExportFormat.HTML)
        val result = useCase.exportToMultipleFormats("report-1", "/tmp", formats)

        assertTrue(result.isSuccess)
        assertEquals(2, result.getOrNull()?.size)
    }

    @Test
    @DisplayName("shareReport should share report")
    fun testShareReport() = runTest {
        whenever(reportRepository.shareReport(any(), any()))
            .thenReturn(Result.success(Unit))

        val result = useCase.shareReport("report-1", ExportFormat.PDF)

        assertTrue(result.isSuccess)
        verify(reportRepository).shareReport("report-1", ExportFormat.PDF)
    }

    @Test
    @DisplayName("uploadReport should upload report")
    fun testUploadReport() = runTest {
        whenever(reportRepository.uploadReport(any(), any(), any()))
            .thenReturn(Result.success("https://example.com/report/1"))

        val result = useCase.uploadReport("report-1", "https://example.com", "api-key")

        assertTrue(result.isSuccess)
        assertEquals("https://example.com/report/1", result.getOrNull())
    }

    @Test
    @DisplayName("getReportStatistics should return statistics")
    fun testGetReportStatistics() = runTest {
        val stats = ReportStatistics(
            totalReports = 10,
            draftReports = 2,
            finalReports = 8,
            averageVulnerabilitiesPerReport = 5.0,
            reportsByMonth = mapOf("2024-01" to 5)
        )
        whenever(reportRepository.getReportStatistics())
            .thenReturn(flowOf(stats))

        val result = useCase.getReportStatistics().first()

        assertEquals(10, result.totalReports)
    }

    @Test
    @DisplayName("getReportsSummary should return summary")
    fun testGetReportsSummary() = runTest {
        val summary = ReportsSummary(
            totalReports = 10,
            draftReports = 2,
            finalReports = 8,
            criticalVulnerabilitiesTotal = 5,
            highVulnerabilitiesTotal = 10,
            pendingActions = 3
        )
        whenever(reportRepository.getReportsSummary())
            .thenReturn(flowOf(summary))

        val result = useCase.getReportsSummary().first()

        assertEquals(10, result.totalReports)
    }

    @Test
    @DisplayName("getAvailableTemplates should return templates")
    fun testGetAvailableTemplates() = runTest {
        val templates = listOf(createTestTemplate())
        whenever(reportRepository.getAvailableTemplates())
            .thenReturn(flowOf(templates))

        val result = useCase.getAvailableTemplates().first()

        assertEquals(1, result.size)
    }

    @Test
    @DisplayName("createTemplate should create template")
    fun testCreateTemplate() = runTest {
        val template = createTestTemplate()
        whenever(reportRepository.createTemplate(any()))
            .thenReturn(Result.success(Unit))

        val result = useCase.createTemplate(template)

        assertTrue(result.isSuccess)
        verify(reportRepository).createTemplate(template)
    }

    @Test
    @DisplayName("updateTemplate should update template")
    fun testUpdateTemplate() = runTest {
        val template = createTestTemplate()
        whenever(reportRepository.updateTemplate(any()))
            .thenReturn(Result.success(Unit))

        val result = useCase.updateTemplate(template)

        assertTrue(result.isSuccess)
        verify(reportRepository).updateTemplate(template)
    }

    @Test
    @DisplayName("deleteTemplate should delete template")
    fun testDeleteTemplate() = runTest {
        whenever(reportRepository.deleteTemplate(any()))
            .thenReturn(Result.success(Unit))

        val result = useCase.deleteTemplate("template-1")

        assertTrue(result.isSuccess)
        verify(reportRepository).deleteTemplate("template-1")
    }

    @Test
    @DisplayName("createDefaultConfig should create default config")
    fun testCreateDefaultConfig() {
        val config = useCase.createDefaultConfig()

        assertEquals("Bluetooth Security Assessment Report", config.title)
        assertTrue(config.includeVulnerabilities)
        assertTrue(config.includeFuzzingResults)
        assertTrue(config.includeExecutiveSummary)
        assertEquals(VulnerabilitySeverity.LOW, config.minSeverity)
    }

    @Test
    @DisplayName("createMinimalConfig should create minimal config")
    fun testCreateMinimalConfig() {
        val config = useCase.createMinimalConfig()

        assertEquals("Security Assessment Summary", config.title)
        assertTrue(config.includeVulnerabilities)
        assertFalse(config.includeFuzzingResults)
        assertFalse(config.includeKeyExtraction)
        assertEquals(VulnerabilitySeverity.HIGH, config.minSeverity)
    }

    @Test
    @DisplayName("createComprehensiveConfig should create comprehensive config")
    fun testCreateComprehensiveConfig() {
        val config = useCase.createComprehensiveConfig()

        assertEquals("Comprehensive Bluetooth Security Assessment", config.title)
        assertTrue(config.includeVulnerabilities)
        assertTrue(config.includeFuzzingResults)
        assertTrue(config.includeKeyExtraction)
        assertTrue(config.includePacketCaptures)
        assertEquals(VulnerabilitySeverity.NONE, config.minSeverity)
    }

    @Test
    @DisplayName("getReportDashboardData should return dashboard data")
    fun testGetReportDashboardData() = runTest {
        val summary = ReportsSummary(
            totalReports = 10,
            draftReports = 2,
            finalReports = 8,
            criticalVulnerabilitiesTotal = 5,
            highVulnerabilitiesTotal = 10,
            pendingActions = 3
        )
        whenever(reportRepository.getReportsSummary()).thenReturn(flowOf(summary))

        val stats = ReportStatistics(
            totalReports = 10,
            draftReports = 2,
            finalReports = 8,
            averageVulnerabilitiesPerReport = 5.0,
            reportsByMonth = mapOf("2024-01" to 5)
        )
        whenever(reportRepository.getReportStatistics()).thenReturn(flowOf(stats))

        val reports = listOf(createTestReport())
        whenever(reportRepository.getAllReports()).thenReturn(flowOf(reports))

        val result = useCase.getReportDashboardData()

        assertEquals(10, result.totalReports)
        assertEquals(2, result.draftReports)
        assertEquals(8, result.finalReports)
        assertEquals(5, result.criticalVulnerabilities)
    }

    // Helper functions

    private fun createTestReport(
        id: String = "report-1",
        authId: String = "BTSEC-TEST",
        status: ReportStatus = ReportStatus.DRAFT
    ): SecurityReport {
        return SecurityReport(
            id = id,
            authId = authId,
            title = "Test Report",
            generatedAt = Instant.now(),
            testPeriod = ReportPeriod(Instant.now(), Instant.now()),
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

    private fun createTestVulnerability(): Vulnerability {
        return Vulnerability(
            id = "vuln-1",
            cveId = "CVE-2019-9506",
            name = "Test Vulnerability",
            description = "Test description",
            severity = VulnerabilitySeverity.HIGH,
            cvssScore = 7.5,
            affectedDevice = BluetoothDevice(
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
            ),
            discoveredAt = Instant.now(),
            category = VulnerabilityCategory.PROTOCOL,
            affectedBluetoothVersions = emptyList(),
            references = emptyList(),
            mitigation = "Update firmware",
            verified = false
        )
    }

    private fun createTestFuzzResult(): FuzzResult {
        return FuzzResult(
            id = "fuzz-1",
            config = FuzzConfig(
                targetDevice = BluetoothDevice(
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
                ),
                fuzzMethod = FuzzMethod.RANDOM,
                packetCount = 100,
                packetsPerSecond = 10,
                dataPatterns = emptyList(),
                durationSeconds = 60
            ),
            startTime = Instant.now().minusSeconds(60),
            endTime = Instant.now(),
            status = FuzzStatus.COMPLETED,
            packetsSent = 100,
            packetsReceived = 95,
            errors = emptyList(),
            findings = emptyList(),
            captureFile = null
        )
    }

    private fun createTestTemplate(): ReportTemplate {
        return ReportTemplate(
            id = "template-1",
            name = "Default Template",
            description = "Default report template",
            format = ExportFormat.PDF,
            includeExecutiveSummary = true,
            includeVulnerabilities = true,
            includeFuzzingResults = true,
            includeKeyExtraction = true,
            includeRecommendations = true,
            includeAppendix = true,
            isDefault = true
        )
    }
}
