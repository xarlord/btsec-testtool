/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.report

import com.btsec.testtool.TestHelpers
import com.btsec.testtool.domain.model.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.Instant

/**
 * Unit tests for ExportFormatters — report output format correctness.
 * Covers JSON, HTML, CSV export paths including edge cases and injection prevention.
 *
 * Addresses GitHub issue #228: No tests for ExportFormatters.
 */
class ExportFormattersTest {

    private lateinit var formatters: ExportFormatters
    private lateinit var testReport: SecurityReport

    @BeforeEach
    fun setUp() {
        formatters = ExportFormatters()

        val now = Instant.now()
        val device = TestHelpers.createTestBluetoothDevice()
        val vuln = TestHelpers.createTestVulnerability()

        testReport = SecurityReport(
            id = "report-001",
            authId = "BTSEC-20260207-A1B2C3D4",
            title = "Test Security Report",
            generatedAt = now,
            testPeriod = ReportPeriod(start = now.minusSeconds(3600), end = now),
            targetDevices = listOf(device),
            vulnerabilities = listOf(vuln),
            fuzzingResults = listOf(
                FuzzResult(
                    id = "fuzz-1",
                    config = TestHelpers.createTestFuzzConfig(device),
                    startTime = now.minusSeconds(1800),
                    endTime = now,
                    status = FuzzStatus.COMPLETED,
                    packetsSent = 100,
                    packetsReceived = 95,
                    errors = emptyList(),
                    findings = emptyList(),
                    captureFile = null
                )
            ),
            keyExtractionResults = listOf(
                TestHelpers.createTestKeyExtractionResult(extracted = false)
            ),
            executiveSummary = "Test executive summary",
            findings = listOf(
                ReportFinding(
                    category = FindingCategory.UNEXPECTED_RESPONSE,
                    severity = VulnerabilitySeverity.MEDIUM,
                    count = 3,
                    description = "Unexpected responses detected",
                    affectedDevices = listOf("AA:BB:CC:DD:EE:FF")
                )
            ),
            recommendations = listOf(
                Recommendation(
                    priority = RecommendationPriority.HIGH,
                    title = "Update Firmware",
                    description = "Device firmware is outdated",
                    affectedDevices = listOf("AA:BB:CC:DD:EE:FF"),
                    implementation = "Apply vendor patch",
                    verification = "Re-scan after update"
                )
            ),
            appendix = ReportAppendix(
                toolsUsed = listOf("BTSec TestTool v1.5"),
                testMethodology = "Automated BLE fuzzing and vulnerability scanning",
                limitations = listOf("Limited to BLE protocol"),
                glossary = mapOf("BLE" to "Bluetooth Low Energy"),
                references = emptyList()
            ),
            status = ReportStatus.FINAL
        )
    }

    // ── JSON Tests ──

    @Test
    @DisplayName("JSON contains all required fields")
    fun toJson_containsAllRequiredFields() {
        val json = formatters.toJson(testReport)

        assertTrue(json.contains("\"id\": \"report-001\""))
        assertTrue(json.contains("\"authId\":"))
        assertTrue(json.contains("\"title\":"))
        assertTrue(json.contains("\"status\":"))
        assertTrue(json.contains("\"executiveSummary\":"))
    }

    @Test
    @DisplayName("JSON contains target devices")
    fun toJson_containsTargetDevices() {
        val json = formatters.toJson(testReport)

        assertTrue(json.contains("\"targetDevices\": ["))
        assertTrue(json.contains("AA:BB:CC:DD:EE:FF"))
        assertTrue(json.contains("Test Device"))
    }

    @Test
    @DisplayName("JSON contains vulnerabilities")
    fun toJson_containsVulnerabilities() {
        val json = formatters.toJson(testReport)

        assertTrue(json.contains("\"vulnerabilities\": ["))
        assertTrue(json.contains("CVE-2024-0001"))
        assertTrue(json.contains("\"severity\":"))
        assertTrue(json.contains("\"cvssScore\":"))
    }

    @Test
    @DisplayName("JSON contains findings")
    fun toJson_containsFindings() {
        val json = formatters.toJson(testReport)

        assertTrue(json.contains("\"findings\": ["))
        assertTrue(json.contains("\"category\":"))
        assertTrue(json.contains("Unexpected responses detected"))
    }

    @Test
    @DisplayName("JSON escapes special characters in title")
    fun toJson_escapesSpecialCharactersInTitle() {
        val reportWithSpecialChars = testReport.copy(
            title = "Report with \"quotes\" and \\backslashes\\"
        )
        val json = formatters.toJson(reportWithSpecialChars)

        assertTrue(json.contains("\\\"quotes\\\""))
        assertTrue(json.contains("\\\\backslashes\\\\"))
    }

    @Test
    @DisplayName("JSON handles empty collections")
    fun toJson_handlesEmptyCollections() {
        val emptyReport = testReport.copy(
            targetDevices = emptyList(),
            vulnerabilities = emptyList(),
            findings = emptyList()
        )
        val json = formatters.toJson(emptyReport)

        assertTrue(json.contains("\"targetDevices\": ["))
        assertTrue(json.contains("\"vulnerabilities\": ["))
        assertTrue(json.contains("\"findings\": ["))
    }

    @Test
    @DisplayName("JSON escapes newlines in strings")
    fun toJson_handlesNewlinesInStrings() {
        val reportWithNewlines = testReport.copy(
            executiveSummary = "Line one\nLine two\nLine three"
        )
        val json = formatters.toJson(reportWithNewlines)

        assertTrue(json.contains("\\n"))
        assertFalse(json.contains("Line one\n"))
    }

    // ── HTML Tests ──

    @Test
    @DisplayName("HTML produces valid structure")
    fun toHtml_producesValidHtmlStructure() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.startsWith("<!DOCTYPE html>"))
        assertTrue(html.contains("<html"))
        assertTrue(html.contains("</html>"))
        assertTrue(html.contains("<head>"))
        assertTrue(html.contains("</body>"))
    }

    @Test
    @DisplayName("HTML contains report title")
    fun toHtml_containsTitle() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Test Security Report"))
        assertTrue(html.contains("<title>"))
    }

    @Test
    @DisplayName("HTML contains executive summary")
    fun toHtml_containsExecutiveSummary() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Executive Summary"))
        assertTrue(html.contains("Test executive summary"))
    }

    @Test
    @DisplayName("HTML contains target devices")
    fun toHtml_containsTargetDevices() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Target Devices"))
        assertTrue(html.contains("AA:BB:CC:DD:EE:FF"))
    }

    @Test
    @DisplayName("HTML contains vulnerabilities")
    fun toHtml_containsVulnerabilities() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Vulnerabilities Detected"))
        assertTrue(html.contains("CVE-2024-0001"))
    }

    @Test
    @DisplayName("HTML contains findings")
    fun toHtml_containsFindings() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Findings"))
        assertTrue(html.contains("Unexpected responses detected"))
    }

    @Test
    @DisplayName("HTML contains recommendations")
    fun toHtml_containsRecommendations() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("Recommendations"))
        assertTrue(html.contains("Update Firmware"))
    }

    @Test
    @DisplayName("HTML escapes special characters to prevent XSS")
    fun toHtml_escapesHtmlSpecialCharacters() {
        val reportWithHtml = testReport.copy(
            title = "<script>alert('xss')</script>",
            executiveSummary = "Test with <b>bold</b> & 'quotes'"
        )
        val html = formatters.toHtml(reportWithHtml)

        assertFalse(html.contains("<script>alert"))
        assertTrue(html.contains("&lt;script"))
        assertTrue(html.contains("&amp;"))
    }

    @Test
    @DisplayName("HTML applies severity CSS classes")
    fun toHtml_appliesSeverityCssClasses() {
        val html = formatters.toHtml(testReport)

        assertTrue(html.contains("class=\""))
        assertTrue(html.contains("class=\"high\""))
    }

    // ── CSV Tests ──

    @Test
    @DisplayName("CSV has header row")
    fun toCsv_hasHeaderRow() {
        val csv = formatters.toCsv(testReport)

        assertTrue(csv.startsWith("Type,CVE/ID,Name,Severity,CVSS,Description"))
    }

    @Test
    @DisplayName("CSV contains vulnerability data")
    fun toCsv_containsVulnerabilities() {
        val csv = formatters.toCsv(testReport)

        assertTrue(csv.contains("Vulnerability,"))
        assertTrue(csv.contains("CVE-2024-0001"))
    }

    @Test
    @DisplayName("CSV contains findings data")
    fun toCsv_containsFindings() {
        val csv = formatters.toCsv(testReport)

        assertTrue(csv.contains("Finding,"))
        assertTrue(csv.contains("UNEXPECTED_RESPONSE"))
    }

    @Test
    @DisplayName("CSV contains recommendations data")
    fun toCsv_containsRecommendations() {
        val csv = formatters.toCsv(testReport)

        assertTrue(csv.contains("Recommendation,"))
        assertTrue(csv.contains("Update Firmware"))
    }

    @Test
    @DisplayName("CSV escapes commas in fields")
    fun toCsv_escapesCommasInFields() {
        val vulnWithCommas = testReport.vulnerabilities.first().copy(
            name = "Vuln, with, commas"
        )
        val report = testReport.copy(vulnerabilities = listOf(vulnWithCommas))
        val csv = formatters.toCsv(report)

        assertTrue(csv.contains("\"Vuln, with, commas\""))
    }

    @Test
    @DisplayName("CSV handles empty report with header only")
    fun toCsv_handlesEmptyReport() {
        val emptyReport = testReport.copy(
            vulnerabilities = emptyList(),
            findings = emptyList(),
            recommendations = emptyList()
        )
        val csv = formatters.toCsv(emptyReport)

        assertTrue(csv.startsWith("Type,CVE/ID,"))
        val lines = csv.lines().filter { it.isNotBlank() }
        assertEquals(1, lines.size)
    }

    // ── Edge Cases ──

    @Test
    @DisplayName("JSON handles device with null name using fallback")
    fun toJson_handlesDeviceWithNullName() {
        val baseDevice = TestHelpers.createTestBluetoothDevice()
        val deviceWithNullName = baseDevice.copy(name = null)
        val report = testReport.copy(targetDevices = listOf(deviceWithNullName))
        val json = formatters.toJson(report)

        assertTrue(json.contains("Unknown"))
    }

    @Test
    @DisplayName("HTML omits vulnerability section when empty")
    fun toHtml_omitsVulnerabilitySectionWhenEmpty() {
        val report = testReport.copy(vulnerabilities = emptyList())
        val html = formatters.toHtml(report)

        assertFalse(html.contains("Vulnerabilities Detected"))
    }

    @Test
    @DisplayName("HTML omits recommendations section when empty")
    fun toHtml_omitsRecommendationsSectionWhenEmpty() {
        val report = testReport.copy(recommendations = emptyList())
        val html = formatters.toHtml(report)

        assertFalse(html.contains("Recommendations</h2>"))
    }

    @Test
    @DisplayName("CSV escapes double quotes in fields")
    fun toCsv_escapingFieldWithDoubleQuotes() {
        val vuln = testReport.vulnerabilities.first().copy(
            name = "Vuln \"with\" quotes"
        )
        val report = testReport.copy(vulnerabilities = listOf(vuln))
        val csv = formatters.toCsv(report)

        assertTrue(csv.contains("\"\"with\"\" quotes"))
    }
}
