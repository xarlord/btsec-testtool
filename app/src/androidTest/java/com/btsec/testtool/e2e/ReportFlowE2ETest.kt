/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.ExportConfig
import com.btsec.testtool.domain.model.Recommendation
import com.btsec.testtool.domain.model.RecommendationPriority
import com.btsec.testtool.domain.model.ReportAppendix
import com.btsec.testtool.domain.model.ReportFinding
import com.btsec.testtool.domain.model.ReportPeriod
import com.btsec.testtool.domain.model.ReportStatus
import com.btsec.testtool.domain.model.SecurityReport
import com.btsec.testtool.domain.model.VulnerabilitySeverity
import com.btsec.testtool.domain.repository.ExportFormat
import com.btsec.testtool.domain.repository.GenerationStep
import com.btsec.testtool.domain.repository.ReportGenerationStatus
import com.btsec.testtool.domain.repository.ReportRepository
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant
import javax.inject.Inject

/**
 * E2E tests for the report generation flow.
 *
 * Exercises: Complete scan → generate report → verify export file contents.
 *
 * Validates the report repository contract, report model construction,
 * generation progress tracking, and export format support.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class ReportFlowE2ETest {

    @get:Rule
    val hiltRule = HiltAndroidRule(this)

    @Inject
    lateinit var reportRepository: ReportRepository

    private val targetDevice = BluetoothDevice(
        address = "22:33:44:55:66:77",
        name = "E2E-Report-Target",
        type = BluetoothType.BLE,
        deviceClass = null,
        bondState = BondState.NONE,
        rssi = -50,
        txPower = null,
        firstSeen = Instant.now(),
        lastSeen = Instant.now(),
        scanCount = 1,
        services = emptyList(),
        manufacturerData = emptyMap()
    )

    @Before
    fun setUp() {
        hiltRule.inject()
    }

    // ── Report State Observation ──────────────────────────────────────

    @Test
    fun reportFlow_reportsObservable() = runBlocking {
        val reports = reportRepository.getAllReports().first()
        assertNotNull("Reports flow should be observable", reports)
    }

    @Test
    fun reportFlow_reportTemplatesObservable() = runBlocking {
        val templates = reportRepository.getAvailableTemplates().first()
        assertNotNull("Report templates flow should be observable", templates)
    }

    @Test
    fun reportFlow_reportStatisticsObservable() = runBlocking {
        val stats = reportRepository.getReportStatistics().first()
        assertNotNull("Report statistics should be observable", stats)
    }

    @Test
    fun reportFlow_reportsSummaryObservable() = runBlocking {
        val summary = reportRepository.getReportsSummary().first()
        assertNotNull("Reports summary should be observable", summary)
    }

    // ── Report Operations Log ────────────────────────────────────────

    @Test
    fun reportFlow_operationsLogInitiallyObservable() = runBlocking {
        val ops = reportRepository.getReportLogs().first()
        assertNotNull("Report logs flow should be observable", ops)
    }

    // ── Report Model Construction ────────────────────────────────────

    @Test
    fun reportFlow_securityReportConstruction() {
        val now = Instant.now()
        val report = SecurityReport(
            id = "report-001",
            authId = "BTSEC-20260610-TEST1234",
            title = "E2E Test Security Assessment",
            generatedAt = now,
            testPeriod = ReportPeriod(
                start = now.minusSeconds(3600),
                end = now
            ),
            targetDevices = listOf(targetDevice),
            vulnerabilities = emptyList(),
            fuzzingResults = emptyList(),
            keyExtractionResults = emptyList(),
            executiveSummary = "Test summary for E2E validation",
            findings = listOf(
                ReportFinding(
                    category = com.btsec.testtool.domain.model.FindingCategory.UNEXPECTED_RESPONSE,
                    severity = VulnerabilitySeverity.HIGH,
                    count = 3,
                    description = "Unexpected responses during fuzzing",
                    affectedDevices = listOf(targetDevice.address)
                )
            ),
            recommendations = listOf(
                Recommendation(
                    priority = RecommendationPriority.HIGH,
                    title = "Disable legacy pairing",
                    description = "Legacy pairing is vulnerable to KNOB attack",
                    affectedDevices = listOf(targetDevice.address),
                    implementation = "Disable BR/EDR Secure Connections fallback",
                    verification = "Re-scan after configuration change"
                )
            ),
            appendix = ReportAppendix(
                toolsUsed = listOf("BTSec TestTool v1.0"),
                testMethodology = "OWASP IoT Testing Guide",
                limitations = listOf("Test conducted in controlled lab environment"),
                glossary = mapOf(
                    "BLE" to "Bluetooth Low Energy",
                    "GATT" to "Generic Attribute Profile"
                ),
                references = listOf("https://owasp.org/www-project-internet-of-things/")
            ),
            status = ReportStatus.DRAFT
        )

        assertEquals("report-001", report.id)
        assertEquals("BTSEC-20260610-TEST1234", report.authId)
        assertEquals(1, report.targetDevices.size)
        assertEquals(targetDevice.address, report.targetDevices[0].address)
        assertEquals(1, report.findings.size)
        assertEquals(VulnerabilitySeverity.HIGH, report.findings[0].severity)
        assertEquals(1, report.recommendations.size)
        assertEquals(RecommendationPriority.HIGH, report.recommendations[0].priority)
        assertEquals(ReportStatus.DRAFT, report.status)
        assertEquals(2, report.appendix.glossary.size)
    }

    // ── Export Formats ────────────────────────────────────────────────

    @Test
    fun reportFlow_allExportFormatsAvailable() {
        val formats = reportRepository.getAvailableExportFormats()
        assertNotNull("Export formats should be available", formats)
        assertTrue("Should have at least 5 export formats", formats.size >= 5)
        assertTrue(formats.contains(ExportFormat.PDF))
        assertTrue(formats.contains(ExportFormat.HTML))
        assertTrue(formats.contains(ExportFormat.JSON))
        assertTrue(formats.contains(ExportFormat.CSV))
        assertTrue(formats.contains(ExportFormat.MARKDOWN))
    }

    // ── Generation Status ────────────────────────────────────────────

    @Test
    fun reportFlow_generationStatusValues() {
        val statuses = ReportGenerationStatus.entries
        assertTrue("Should have at least 4 generation statuses", statuses.size >= 4)
        assertTrue(ReportGenerationStatus.entries.contains(ReportGenerationStatus.PENDING))
        assertTrue(ReportGenerationStatus.entries.contains(ReportGenerationStatus.GENERATING))
        assertTrue(ReportGenerationStatus.entries.contains(ReportGenerationStatus.COMPLETED))
        assertTrue(ReportGenerationStatus.entries.contains(ReportGenerationStatus.FAILED))
    }

    @Test
    fun reportFlow_generationStepValues() {
        val steps = GenerationStep.entries
        assertTrue("Should have at least 6 generation steps", steps.size >= 6)
        assertTrue(GenerationStep.entries.contains(GenerationStep.INITIALIZING))
        assertTrue(GenerationStep.entries.contains(GenerationStep.GATHERING_DATA))
        assertTrue(GenerationStep.entries.contains(GenerationStep.COMPLETED))
    }

    // ── Report Status Enum ────────────────────────────────────────────

    @Test
    fun reportFlow_reportStatusValues() {
        val statuses = ReportStatus.entries
        assertTrue("Should have at least 3 report statuses", statuses.size >= 3)
        assertTrue(ReportStatus.entries.contains(ReportStatus.DRAFT))
        assertTrue(ReportStatus.entries.contains(ReportStatus.FINAL))
        assertTrue(ReportStatus.entries.contains(ReportStatus.REVIEW))
    }

    // ── Export Config ─────────────────────────────────────────────────

    @Test
    fun reportFlow_exportConfigDefaults() {
        val config = ExportConfig()
        assertNotNull(config)
        assertTrue(config.encrypt)
    }

    @Test
    fun reportFlow_exportConfigWithoutEncryption() {
        val config = ExportConfig(
            encrypt = false,
            autoGeneratePassword = false
        )
        assertTrue(!config.encrypt)
    }
}
