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
import com.btsec.testtool.domain.repository.DetectionConfidence
import com.btsec.testtool.domain.repository.ReportConfig
import com.btsec.testtool.domain.repository.VulnerabilityTestResult
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for [ReportGenerator].
 *
 * Tests report generation, risk scoring, risk labels, and
 * that generated reports contain correct findings and recommendations.
 */
@DisplayName("ReportGenerator Tests")
class ReportGeneratorTest {
    private lateinit var generator: ReportGenerator
    private lateinit var testDevice: BluetoothDevice

    @BeforeEach
    fun setUp() {
        generator = ReportGenerator()
        testDevice = TestHelpers.createTestBluetoothDevice()
    }

    // ── Risk scoring ──

    @Test
    @DisplayName("calculateRiskScore with empty results should return 0.0")
    fun testRiskScoreEmpty() {
        assertEquals(0.0, generator.calculateRiskScore(emptyList()))
    }

    @Test
    @DisplayName("calculateRiskScore with no detected vulnerabilities should return 0.0")
    fun testRiskScoreNoDetected() {
        val results =
            listOf(
                createTestResult(detected = false, severity = VulnerabilitySeverity.CRITICAL, cvss = 9.8),
                createTestResult(detected = false, severity = VulnerabilitySeverity.HIGH, cvss = 7.5),
            )
        assertEquals(0.0, generator.calculateRiskScore(results))
    }

    @Test
    @DisplayName("calculateRiskScore with single critical detected vulnerability should be positive")
    fun testRiskScoreSingleCritical() {
        val results =
            listOf(
                createTestResult(detected = true, severity = VulnerabilitySeverity.CRITICAL, cvss = 9.8),
            )
        val score = generator.calculateRiskScore(results)
        assertTrue(score > 0.0)
        // Critical weight is 1.5x: 9.8 * 1.5 / 1 = 14.7, clamped to 10.0
        assertEquals(10.0, score)
    }

    @Test
    @DisplayName("calculateRiskScore with single high detected vulnerability")
    fun testRiskScoreSingleHigh() {
        val results =
            listOf(
                createTestResult(detected = true, severity = VulnerabilitySeverity.HIGH, cvss = 7.5),
            )
        val score = generator.calculateRiskScore(results)
        // High weight is 1.2x: 7.5 * 1.2 / 1 = 9.0
        assertEquals(9.0, score)
    }

    @Test
    @DisplayName("calculateRiskScore with single medium detected vulnerability")
    fun testRiskScoreSingleMedium() {
        val results =
            listOf(
                createTestResult(detected = true, severity = VulnerabilitySeverity.MEDIUM, cvss = 5.3),
            )
        val score = generator.calculateRiskScore(results)
        // Medium weight is 1.0x: 5.3 * 1.0 / 1 = 5.3
        assertEquals(5.3, score)
    }

    @Test
    @DisplayName("calculateRiskScore with single low detected vulnerability")
    fun testRiskScoreSingleLow() {
        val results =
            listOf(
                createTestResult(detected = true, severity = VulnerabilitySeverity.LOW, cvss = 3.0),
            )
        val score = generator.calculateRiskScore(results)
        // Low weight is 0.5x: 3.0 * 0.5 / 1 = 1.5
        assertEquals(1.5, score)
    }

    @Test
    @DisplayName("calculateRiskScore with single informational detected vulnerability")
    fun testRiskScoreSingleInformational() {
        val results =
            listOf(
                createTestResult(detected = true, severity = VulnerabilitySeverity.INFORMATIONAL, cvss = 2.0),
            )
        val score = generator.calculateRiskScore(results)
        // Info weight is 0.2x: 2.0 * 0.2 / 1 = 0.4
        assertEquals(0.4, score)
    }

    @Test
    @DisplayName("calculateRiskScore with NONE severity detected should not contribute")
    fun testRiskScoreNoneSeverity() {
        val results =
            listOf(
                createTestResult(detected = true, severity = VulnerabilitySeverity.NONE, cvss = 0.0),
            )
        val score = generator.calculateRiskScore(results)
        assertEquals(0.0, score)
    }

    @Test
    @DisplayName("calculateRiskScore with mixed detected and not-detected should average only detected")
    fun testRiskScoreMixed() {
        val results =
            listOf(
                createTestResult(detected = false, severity = VulnerabilitySeverity.CRITICAL, cvss = 9.8),
                createTestResult(detected = true, severity = VulnerabilitySeverity.HIGH, cvss = 7.5),
            )
        val score = generator.calculateRiskScore(results)
        // 7.5 * 1.2 / 2 = 4.5
        assertEquals(4.5, score)
    }

    @Test
    @DisplayName("calculateRiskScore should be clamped to 0.0-10.0 range")
    fun testRiskScoreClamped() {
        val results =
            listOf(
                createTestResult(detected = true, severity = VulnerabilitySeverity.CRITICAL, cvss = 10.0),
            )
        val score = generator.calculateRiskScore(results)
        assertEquals(10.0, score) // Clamped at 10.0
    }

    // ── Risk label ──

    @Test
    @DisplayName("getRiskLabel for score >= 9.0 should return CRITICAL")
    fun testRiskLabelCritical() {
        assertEquals("CRITICAL", generator.getRiskLabel(9.0))
        assertEquals("CRITICAL", generator.getRiskLabel(9.5))
        assertEquals("CRITICAL", generator.getRiskLabel(10.0))
    }

    @Test
    @DisplayName("getRiskLabel for score >= 7.0 and < 9.0 should return HIGH")
    fun testRiskLabelHigh() {
        assertEquals("HIGH", generator.getRiskLabel(7.0))
        assertEquals("HIGH", generator.getRiskLabel(8.0))
        assertEquals("HIGH", generator.getRiskLabel(8.99))
    }

    @Test
    @DisplayName("getRiskLabel for score >= 4.0 and < 7.0 should return MEDIUM")
    fun testRiskLabelMedium() {
        assertEquals("MEDIUM", generator.getRiskLabel(4.0))
        assertEquals("MEDIUM", generator.getRiskLabel(5.5))
        assertEquals("MEDIUM", generator.getRiskLabel(6.99))
    }

    @Test
    @DisplayName("getRiskLabel for score >= 1.0 and < 4.0 should return LOW")
    fun testRiskLabelLow() {
        assertEquals("LOW", generator.getRiskLabel(1.0))
        assertEquals("LOW", generator.getRiskLabel(2.5))
        assertEquals("LOW", generator.getRiskLabel(3.99))
    }

    @Test
    @DisplayName("getRiskLabel for score < 1.0 should return NONE")
    fun testRiskLabelNone() {
        assertEquals("NONE", generator.getRiskLabel(0.0))
        assertEquals("NONE", generator.getRiskLabel(0.5))
        assertEquals("NONE", generator.getRiskLabel(0.99))
    }

    // ── Report generation ──

    @Test
    @DisplayName("generateReport should produce a report with correct auth ID")
    fun testGenerateReportAuthId() {
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST-REPORT",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = emptyList(),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        assertEquals("BTSEC-TEST-REPORT", report.authId)
    }

    @Test
    @DisplayName("generateReport should include target devices")
    fun testGenerateReportTargetDevices() {
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = emptyList(),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        assertEquals(1, report.targetDevices.size)
        assertEquals(testDevice.address, report.targetDevices[0].address)
    }

    @Test
    @DisplayName("generateReport with no vulnerabilities should have empty findings and recommendations")
    fun testGenerateReportNoVulns() {
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = emptyList(),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        assertTrue(report.vulnerabilities.isEmpty())
        assertTrue(report.recommendations.isEmpty())
        assertTrue(report.executiveSummary.contains("No critical vulnerabilities detected"))
    }

    @Test
    @DisplayName("generateReport with detected vulnerabilities should have recommendations")
    fun testGenerateReportWithDetectedVulns() {
        val vulnResult =
            createTestResult(
                detected = true,
                severity = VulnerabilitySeverity.CRITICAL,
                cvss = 9.8,
                name = "BlueBorne",
                cveId = "CVE-2017-0785",
                mitigation = "Apply OS security patches",
            )
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = listOf(vulnResult),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        assertEquals(1, report.vulnerabilities.size)
        assertEquals("CVE-2017-0785", report.vulnerabilities[0].cveId)
        assertEquals(1, report.recommendations.size)
        assertTrue(report.recommendations[0].title.contains("BlueBorne"))
        assertTrue(report.executiveSummary.contains("IMMEDIATE ACTION REQUIRED"))
    }

    @Test
    @DisplayName("generateReport executive summary should include vulnerability counts")
    fun testGenerateReportExecutiveSummary() {
        val results =
            listOf(
                createTestResult(detected = true, severity = VulnerabilitySeverity.CRITICAL, cvss = 9.8),
                createTestResult(detected = true, severity = VulnerabilitySeverity.HIGH, cvss = 7.5),
                createTestResult(detected = false, severity = VulnerabilitySeverity.MEDIUM, cvss = 5.3),
            )
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = results,
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        assertTrue(report.executiveSummary.contains("Vulnerabilities scanned: 3"))
        assertTrue(report.executiveSummary.contains("Vulnerabilities detected: 2"))
        assertTrue(report.executiveSummary.contains("Critical: 1"))
        assertTrue(report.executiveSummary.contains("High: 1"))
    }

    @Test
    @DisplayName("generateReport should include appendix with tools and glossary")
    fun testGenerateReportAppendix() {
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = emptyList(),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        assertNotNull(report.appendix)
        assertTrue(report.appendix.toolsUsed.isNotEmpty())
        assertTrue(report.appendix.glossary.containsKey("CVSS"))
        assertTrue(report.appendix.glossary.containsKey("BLE"))
        assertTrue(report.appendix.limitations.isNotEmpty())
    }

    @Test
    @DisplayName("generateReport should have FINAL status")
    fun testGenerateReportStatus() {
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = emptyList(),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        assertEquals(ReportStatus.FINAL, report.status)
    }

    @Test
    @DisplayName("generateReport should include fuzzing and key extraction results")
    fun testGenerateReportWithFuzzingAndKeys() {
        val fuzzResult =
            FuzzResult(
                id = "fuzz-1",
                config = TestHelpers.createTestFuzzConfig(),
                startTime = java.time.Instant.now(),
                endTime = java.time.Instant.now(),
                status = FuzzStatus.COMPLETED,
                packetsSent = 100,
                packetsReceived = 95,
                errors = emptyList(),
                findings = emptyList(),
                captureFile = null,
            )
        val keyResult = TestHelpers.createTestKeyExtractionResult(extracted = true)

        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = emptyList(),
                fuzzingResults = listOf(fuzzResult),
                keyExtractionResults = listOf(keyResult),
            )
        assertEquals(1, report.fuzzingResults.size)
        assertEquals(1, report.keyExtractionResults.size)
        assertTrue(report.executiveSummary.contains("Fuzzing sessions: 1"))
        assertTrue(report.executiveSummary.contains("Key extraction attempts: 1"))
    }

    @Test
    @DisplayName("generateReport should group findings by category and severity")
    fun testGenerateReportFindingsGrouping() {
        val results =
            listOf(
                createTestResult(
                    detected = false,
                    severity = VulnerabilitySeverity.HIGH,
                    cvss = 7.5,
                    category = VulnerabilityCategory.ENCRYPTION,
                    name = "KNOB",
                ),
                createTestResult(
                    detected = false,
                    severity = VulnerabilitySeverity.HIGH,
                    cvss = 7.5,
                    category = VulnerabilityCategory.ENCRYPTION,
                    name = "BLURtooth",
                ),
                createTestResult(
                    detected = false,
                    severity = VulnerabilitySeverity.MEDIUM,
                    cvss = 5.3,
                    category = VulnerabilityCategory.AUTHENTICATION,
                    name = "BIAS",
                ),
            )
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = results,
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        // Two groups: (INFORMATION_LEAK, HIGH) and (BYPASS, MEDIUM)
        assertEquals(2, report.findings.size)
    }

    @Test
    @DisplayName("generateReport recommendations should be sorted by severity descending")
    fun testGenerateReportRecommendationsOrdering() {
        val results =
            listOf(
                createTestResult(detected = true, severity = VulnerabilitySeverity.MEDIUM, cvss = 5.0, name = "Medium Vuln"),
                createTestResult(detected = true, severity = VulnerabilitySeverity.CRITICAL, cvss = 9.8, name = "Critical Vuln"),
                createTestResult(detected = true, severity = VulnerabilitySeverity.HIGH, cvss = 7.5, name = "High Vuln"),
            )
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = listOf(testDevice),
                vulnerabilityResults = results,
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        assertEquals(3, report.recommendations.size)
        // First recommendation should be for the critical vuln (highest CVSS)
        assertTrue(report.recommendations[0].title.contains("Critical Vuln"))
    }

    @Test
    @DisplayName("generateReport with no target devices should still produce valid report")
    fun testGenerateReportNoDevices() {
        val report =
            generator.generateReport(
                authId = "BTSEC-TEST",
                config = ReportConfig(title = "Test Report"),
                targetDevices = emptyList(),
                vulnerabilityResults = emptyList(),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )
        assertTrue(report.targetDevices.isEmpty())
        assertTrue(report.title.contains("Unknown"))
    }

    // ── Helpers ──

    private fun createTestResult(
        detected: Boolean,
        severity: VulnerabilitySeverity,
        cvss: Double,
        name: String = "Test Vuln",
        cveId: String = "CVE-2024-0001",
        mitigation: String = "Update firmware",
        category: VulnerabilityCategory = VulnerabilityCategory.PROTOCOL,
    ): VulnerabilityTestResult {
        return VulnerabilityTestResult(
            vulnerability =
                VulnerabilityDefinition(
                    cveId = cveId,
                    name = name,
                    description = "Test description",
                    severity = severity,
                    cvssScore = cvss,
                    category = category,
                    affectedVersions = "All",
                    affectedProfiles = listOf("GATT"),
                    yearDiscovered = 2024,
                    references = listOf("https://example.com"),
                    mitigation = mitigation,
                    testMethodology = "automated",
                ),
            detected = detected,
            confidence = if (detected) DetectionConfidence.HIGH else DetectionConfidence.MEDIUM,
            details = "",
            evidence = listOf("Test evidence"),
            timestamp = java.time.Instant.now(),
        )
    }
}
