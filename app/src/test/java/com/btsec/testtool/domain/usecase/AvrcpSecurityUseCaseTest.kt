/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.AvrcpBrowseResult
import com.btsec.testtool.domain.model.AvrcpSeverity
import com.btsec.testtool.domain.model.AvrcpTestCategory
import com.btsec.testtool.domain.model.AvrcpTestReport
import com.btsec.testtool.domain.model.AvrcpTestResult
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Unit tests for [AvrcpSecurityUseCase].
 *
 * Validates test suite generation, response analysis, risk computation,
 * path traversal detection, and report generation.
 */
@DisplayName("AvrcpSecurityUseCase Tests")
class AvrcpSecurityUseCaseTest {

    private lateinit var useCase: AvrcpSecurityUseCase

    @BeforeEach
    fun setUp() {
        useCase = AvrcpSecurityUseCase()
    }

    // ── Test Suite ──

    @Nested
    @DisplayName("Test Suite")
    inner class TestSuite {

        @Test
        @DisplayName("Test suite has at least 18 tests")
        fun testGetTestSuite_hasMinimum18Tests() {
            val suite = useCase.getTestSuite()
            assertThat(suite.size).isAtLeast(18)
        }

        @Test
        @DisplayName("All test categories are covered")
        fun testGetTestSuite_allCategoriesCovered() {
            val suite = useCase.getTestSuite()
            val categories = suite.map { it.category }.toSet()
            for (cat in AvrcpTestCategory.entries) {
                assertThat(categories).contains(cat)
            }
        }

        @Test
        @DisplayName("Every test case has a non-blank name and command")
        fun testGetTestSuite_allFieldsPopulated() {
            val suite = useCase.getTestSuite()
            for (tc in suite) {
                assertThat(tc.name).isNotEmpty()
                assertThat(tc.command).isNotEmpty()
                assertThat(tc.expectedBehavior).isNotEmpty()
                assertThat(tc.vulnerabilityIndicator).isNotEmpty()
                assertThat(tc.recommendation).isNotEmpty()
            }
        }
    }

    // ── Response Analysis ──

    @Nested
    @DisplayName("Response Analysis")
    inner class ResponseAnalysis {

        private val playTestCase = AvrcpTestCase(
            name = "Play command without auth",
            category = AvrcpTestCategory.MEDIA_CONTROL,
            command = "AVRCP_PRESS:PLAY",
            expectedBehavior = "Should reject",
            vulnerabilityIndicator = "Playback started",
            severity = AvrcpSeverity.HIGH,
            recommendation = "Require auth"
        )

        private val browseTestCase = AvrcpTestCase(
            name = "Browse root folder",
            category = AvrcpTestCategory.BROWSING,
            command = "BROWSE:GetFolderItems(uid=0)",
            expectedBehavior = "Should restrict",
            vulnerabilityIndicator = "Contents listed",
            severity = AvrcpSeverity.MEDIUM,
            recommendation = "Access control"
        )

        private val traversalTestCase = AvrcpTestCase(
            name = "ChangePath with ../",
            category = AvrcpTestCategory.PATH_TRAVERSAL,
            command = "BROWSE:ChangePath(path=\"../\")",
            expectedBehavior = "Should reject",
            vulnerabilityIndicator = "Parent dir accessed",
            severity = AvrcpSeverity.HIGH,
            recommendation = "Validate paths"
        )

        @Test
        @DisplayName("Play success response is marked vulnerable")
        fun testAnalyzeResponse_playSuccess() {
            val result = useCase.analyzeResponse(playTestCase, "OK: playback started")
            assertThat(result.vulnerable).isTrue()
            assertThat(result.confidence).isGreaterThan(0.8)
            assertThat(result.category).isEqualTo(AvrcpTestCategory.MEDIA_CONTROL)
        }

        @Test
        @DisplayName("Browse success response is marked vulnerable")
        fun testAnalyzeResponse_browseSuccess() {
            val result = useCase.analyzeResponse(browseTestCase, "Success: 42 items found")
            assertThat(result.vulnerable).isTrue()
            assertThat(result.confidence).isGreaterThan(0.8)
        }

        @Test
        @DisplayName("Path traversal indicators detected in response")
        fun testAnalyzeResponse_pathTraversal() {
            val result = useCase.analyzeResponse(
                traversalTestCase,
                "Changed to /etc/passwd"
            )
            assertThat(result.vulnerable).isTrue()
            assertThat(result.confidence).isGreaterThan(0.8)
        }

        @Test
        @DisplayName("Error response is not marked vulnerable")
        fun testAnalyzeResponse_errorNotVulnerable() {
            val result = useCase.analyzeResponse(playTestCase, "Error: rejected")
            assertThat(result.vulnerable).isFalse()
            assertThat(result.confidence).isGreaterThan(0.9)
        }

        @Test
        @DisplayName("Null response is not marked vulnerable")
        fun testAnalyzeResponse_nullResponse() {
            val result = useCase.analyzeResponse(playTestCase, null)
            assertThat(result.vulnerable).isFalse()
            assertThat(result.confidence).isGreaterThan(0.8)
            assertThat(result.evidence).contains("No response")
        }

        @Test
        @DisplayName("Denied response is not vulnerable")
        fun testAnalyzeResponse_deniedResponse() {
            val result = useCase.analyzeResponse(playTestCase, "Command denied")
            assertThat(result.vulnerable).isFalse()
        }
    }

    // ── Risk Computation ──

    @Nested
    @DisplayName("Risk Computation")
    inner class RiskComputation {

        @Test
        @DisplayName("Critical finding yields CRITICAL overall risk")
        fun testComputeOverallRisk_criticalFinding() {
            val results = listOf(
                createTestResult(vulnerable = true, severity = AvrcpSeverity.CRITICAL),
                createTestResult(vulnerable = true, severity = AvrcpSeverity.MEDIUM),
                createTestResult(vulnerable = false, severity = AvrcpSeverity.LOW)
            )
            val risk = useCase.computeOverallRisk(results)
            assertThat(risk).isEqualTo(AvrcpSeverity.CRITICAL)
        }

        @Test
        @DisplayName("All INFO / non-vulnerable yields INFO overall risk")
        fun testComputeOverallRisk_allInfo() {
            val results = listOf(
                createTestResult(vulnerable = false, severity = AvrcpSeverity.LOW),
                createTestResult(vulnerable = false, severity = AvrcpSeverity.INFO)
            )
            val risk = useCase.computeOverallRisk(results)
            assertThat(risk).isEqualTo(AvrcpSeverity.INFO)
        }

        @Test
        @DisplayName("Empty results yield INFO overall risk")
        fun testComputeOverallRisk_emptyResults() {
            val risk = useCase.computeOverallRisk(emptyList())
            assertThat(risk).isEqualTo(AvrcpSeverity.INFO)
        }

        @Test
        @DisplayName("HIGH finding without CRITICAL yields HIGH overall risk")
        fun testComputeOverallRisk_highFinding() {
            val results = listOf(
                createTestResult(vulnerable = true, severity = AvrcpSeverity.HIGH),
                createTestResult(vulnerable = true, severity = AvrcpSeverity.MEDIUM)
            )
            val risk = useCase.computeOverallRisk(results)
            assertThat(risk).isEqualTo(AvrcpSeverity.HIGH)
        }
    }

    // ── Path Traversal Detection ──

    @Nested
    @DisplayName("Path Traversal Detection")
    inner class PathTraversal {

        @Test
        @DisplayName("Parent directory ../ is detected")
        fun testDetectPathTraversal_parentDir() {
            assertThat(useCase.detectPathTraversal("../../../etc/passwd")).isTrue()
        }

        @Test
        @DisplayName("Root path / is NOT flagged by detectPathTraversal")
        fun testDetectPathTraversal_rootPath() {
            // The method checks specific traversal patterns, not bare /
            // A simple "/" should not match any pattern unless it has ../ etc.
            assertThat(useCase.detectPathTraversal("/")).isFalse()
        }

        @Test
        @DisplayName("Null byte is detected")
        fun testDetectPathTraversal_nullByte() {
            assertThat(useCase.detectPathTraversal("file\u0000.txt")).isTrue()
        }

        @Test
        @DisplayName("Normal path is not flagged")
        fun testDetectPathTraversal_normalPath() {
            assertThat(useCase.detectPathTraversal("music/track01.mp3")).isFalse()
        }

        @Test
        @DisplayName("URL-encoded traversal %2e%2e is detected")
        fun testDetectPathTraversal_urlEncoded() {
            assertThat(useCase.detectPathTraversal("%2e%2e%2f")).isTrue()
        }

        @Test
        @DisplayName("Backslash traversal ..\\ is detected")
        fun testDetectPathTraversal_backslash() {
            assertThat(useCase.detectPathTraversal("..\\windows\\system32")).isTrue()
        }
    }

    // ── Report Generation ──

    @Nested
    @DisplayName("Report Generation")
    inner class ReportGeneration {

        @Test
        @DisplayName("Generated report is not empty")
        fun testGenerateReport_notEmpty() {
            val report = createSampleReport()
            val text = useCase.generateReport(report)
            assertThat(text).isNotEmpty()
            assertThat(text).contains("AVRCP Security Test Report")
        }

        @Test
        @DisplayName("Generated report includes finding details")
        fun testGenerateReport_includesFindings() {
            val results = listOf(
                createTestResult(
                    testName = "Play command without auth",
                    vulnerable = true,
                    severity = AvrcpSeverity.HIGH
                )
            )
            val report = createSampleReport(results = results, criticalCount = 0, highCount = 1)
            val text = useCase.generateReport(report)
            assertThat(text).contains("Play command without auth")
            assertThat(text).contains("HIGH")
            assertThat(text).contains("true")
            assertThat(text).contains("Overall Risk")
        }

        @Test
        @DisplayName("Report includes browse results when present")
        fun testGenerateReport_includesBrowseResults() {
            val browseResults = listOf(
                AvrcpBrowseResult(
                    path = "/media/music",
                    depth = 2,
                    itemsFound = 42,
                    traversalSuccessful = true,
                    sensitivePaths = listOf("/etc/passwd")
                )
            )
            val report = createSampleReport(browseResults = browseResults)
            val text = useCase.generateReport(report)
            assertThat(text).contains("/media/music")
            assertThat(text).contains("/etc/passwd")
        }
    }

    // ── Helpers ──

    private fun createTestResult(
        testName: String = "Test",
        category: AvrcpTestCategory = AvrcpTestCategory.MEDIA_CONTROL,
        vulnerable: Boolean = false,
        severity: AvrcpSeverity = AvrcpSeverity.INFO
    ): AvrcpTestResult {
        return AvrcpTestResult(
            category = category,
            testName = testName,
            command = "TEST",
            response = null,
            vulnerable = vulnerable,
            confidence = 0.9,
            evidence = "Test evidence",
            severity = severity,
            recommendation = "Test recommendation"
        )
    }

    private fun createSampleReport(
        results: List<AvrcpTestResult> = emptyList(),
        browseResults: List<AvrcpBrowseResult> = emptyList(),
        criticalCount: Int = 0,
        highCount: Int = 0
    ): AvrcpTestReport {
        return AvrcpTestReport(
            targetDevice = "AA:BB:CC:DD:EE:FF",
            results = results,
            browseResults = browseResults,
            mediaItemsExtracted = 0,
            criticalCount = criticalCount,
            highCount = highCount,
            testDurationMs = 1500L
        )
    }
}
