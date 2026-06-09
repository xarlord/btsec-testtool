/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.HfpTestCategory
import com.btsec.testtool.domain.model.HfpSeverity
import com.btsec.testtool.domain.model.HfpTestResult
import com.btsec.testtool.domain.model.HfpTestSuite
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Unit tests for [HfpSecurityUseCase].
 *
 * Tests HFP security test suite generation, response analysis,
 * vulnerability detection, risk computation, and report generation.
 */
@DisplayName("HfpSecurityUseCase Tests")
class HfpSecurityUseCaseTest {

    private lateinit var useCase: HfpSecurityUseCase

    @BeforeEach
    fun setUp() {
        useCase = HfpSecurityUseCase()
    }

    // ── Helpers ──

    private fun findTestCase(name: String): HfpTestCase {
        return useCase.getTestSuite().first { it.name == name }
    }

    private fun createTestResult(
        category: HfpTestCategory = HfpTestCategory.CALL_MANIPULATION,
        testName: String = "Test",
        command: String = "AT",
        response: String? = null,
        vulnerable: Boolean = false,
        confidence: Double = 0.0,
        evidence: String = "",
        severity: HfpSeverity = HfpSeverity.MEDIUM,
        recommendation: String = ""
    ): HfpTestResult {
        return HfpTestResult(
            category = category,
            testName = testName,
            command = command,
            response = response,
            vulnerable = vulnerable,
            confidence = confidence,
            evidence = evidence,
            severity = severity,
            recommendation = recommendation
        )
    }

    private fun createTestSuite(
        results: List<HfpTestResult>,
        overallRisk: HfpSeverity = HfpSeverity.INFO
    ): HfpTestSuite {
        return HfpTestSuite(
            deviceAddress = "AA:BB:CC:DD:EE:FF",
            deviceName = "Test Device",
            results = results,
            criticalCount = results.count { it.vulnerable && it.severity == HfpSeverity.CRITICAL },
            highCount = results.count { it.vulnerable && it.severity == HfpSeverity.HIGH },
            mediumCount = results.count { it.vulnerable && it.severity == HfpSeverity.MEDIUM },
            lowCount = results.count { it.vulnerable && it.severity == HfpSeverity.LOW },
            infoCount = results.count { it.vulnerable && it.severity == HfpSeverity.INFO },
            overallRisk = overallRisk,
            testDurationMs = 1500L
        )
    }

    // ── Test Suite Coverage ──

    @Nested
    @DisplayName("Test Suite Generation")
    inner class TestSuiteGeneration {

        @Test
        @DisplayName("Should have at least 20 predefined test cases")
        fun testGetTestSuite_hasMinimum20Tests() {
            val suite = useCase.getTestSuite()
            assertTrue(suite.size >= 20, "Expected at least 20 test cases, got ${suite.size}")
        }

        @Test
        @DisplayName("Should cover all HFP test categories")
        fun testGetTestSuite_allCategoriesCovered() {
            val suite = useCase.getTestSuite()
            val coveredCategories = suite.map { it.category }.toSet()
            val expectedCategories = HfpTestCategory.entries.toSet()

            for (category in expectedCategories) {
                assertTrue(
                    coveredCategories.contains(category),
                    "Missing category: $category"
                )
            }
        }

        @Test
        @DisplayName("All test cases should have non-empty names and commands")
        fun testGetTestSuite_nonEmptyFields() {
            val suite = useCase.getTestSuite()
            for (tc in suite) {
                assertTrue(tc.name.isNotBlank(), "Test case has blank name")
                assertTrue(tc.command.isNotBlank(), "Test case '${tc.name}' has blank command")
                assertTrue(tc.expectedBehavior.isNotBlank(), "Test case '${tc.name}' has blank expectedBehavior")
                assertTrue(tc.vulnerabilityIndicator.isNotBlank(), "Test case '${tc.name}' has blank vulnerabilityIndicator")
                assertTrue(tc.recommendation.isNotBlank(), "Test case '${tc.name}' has blank recommendation")
            }
        }
    }

    // ── Response Analysis ──

    @Nested
    @DisplayName("Response Analysis")
    inner class ResponseAnalysis {

        @Test
        @DisplayName("Format string %x leak should be detected as vulnerable")
        fun testAnalyzeResponse_formatStringLeak() {
            val testCase = findTestCase("Format String %x Leak")
            val result = useCase.analyzeResponse(testCase, "0x41414141.0x42424242.0x43434343")

            assertTrue(result.vulnerable, "Should detect format string vulnerability")
            assertTrue(result.confidence >= 0.9, "High confidence expected for hex leak, got ${result.confidence}")
            assertEquals(HfpSeverity.CRITICAL, result.severity)
        }

        @Test
        @DisplayName("Successful call origination should be detected as vulnerable")
        fun testAnalyzeResponse_callOriginationSuccess() {
            val testCase = findTestCase("Call Origination")
            val result = useCase.analyzeResponse(testCase, "OK")

            assertTrue(result.vulnerable, "Should detect call origination vulnerability")
            assertEquals(HfpSeverity.CRITICAL, result.severity)
            assertTrue(result.confidence > 0.0, "Confidence should be > 0")
        }

        @Test
        @DisplayName("Phonebook data leak should be detected")
        fun testAnalyzeResponse_phonebookDataLeak() {
            val testCase = findTestCase("Phonebook Read Entry")
            val result = useCase.analyzeResponse(testCase, "+CPBR: 1,\"+1234567890\",145,\"John Doe\"")

            assertTrue(result.vulnerable, "Should detect phonebook data leak")
            assertTrue(result.confidence >= 0.9, "High confidence expected for phonebook leak")
            assertEquals(HfpSeverity.CRITICAL, result.severity)
        }

        @Test
        @DisplayName("SMS access success should be detected")
        fun testAnalyzeResponse_smsAccessSuccess() {
            val testCase = findTestCase("SMS List All")
            val result = useCase.analyzeResponse(testCase, "+CMGL: 1,\"REC READ\",\"+1234567890\"")

            assertTrue(result.vulnerable, "Should detect SMS access vulnerability")
            assertTrue(result.confidence >= 0.9, "High confidence expected for SMS access")
            assertEquals(HfpSeverity.CRITICAL, result.severity)
        }

        @Test
        @DisplayName("ERROR response should not be flagged as vulnerable for call manipulation")
        fun testAnalyzeResponse_errorResponse_notVulnerable() {
            val testCase = findTestCase("Call Origination")
            val result = useCase.analyzeResponse(testCase, "ERROR")

            assertFalse(result.vulnerable, "ERROR response should not indicate vulnerability")
            assertEquals(0.0, result.confidence, 0.01)
        }

        @Test
        @DisplayName("Null response should not be flagged as vulnerable")
        fun testAnalyzeResponse_nullResponse_notVulnerable() {
            val testCase = findTestCase("Call Origination")
            val result = useCase.analyzeResponse(testCase, null)

            assertFalse(result.vulnerable, "Null response should not indicate vulnerability")
            assertEquals(0.0, result.confidence, 0.01)
        }

        @Test
        @DisplayName("Buffer overflow with no error should be detected")
        fun testAnalyzeResponse_bufferOverflow_noError() {
            val testCase = findTestCase("Buffer Overflow 4KB")
            val result = useCase.analyzeResponse(testCase, "OK")

            assertTrue(result.vulnerable, "No error to buffer overflow should be detected")
            assertEquals(HfpSeverity.HIGH, result.severity)
        }

        @Test
        @DisplayName("Buffer overflow with ERROR should not be vulnerable")
        fun testAnalyzeResponse_bufferOverflow_withError() {
            val testCase = findTestCase("Buffer Overflow 4KB")
            val result = useCase.analyzeResponse(testCase, "ERROR")

            assertFalse(result.vulnerable, "ERROR response should indicate safe handling")
        }

        @Test
        @DisplayName("Information disclosure returns device info")
        fun testAnalyzeResponse_informationDisclosure() {
            val testCase = findTestCase("Device Info Leak (ATI)")
            val result = useCase.analyzeResponse(testCase, "Manufacturer: ACME Corp, Model: BT-2000")

            assertTrue(result.vulnerable, "Device info returned should indicate disclosure")
            assertEquals(HfpSeverity.LOW, result.severity)
        }

        @Test
        @DisplayName("Auth bypass detection when connected without pairing")
        fun testAnalyzeResponse_authBypass() {
            val testCase = findTestCase("HFP Auth Bypass (No Pairing)")
            val result = useCase.analyzeResponse(testCase, "CONNECT 1")

            assertTrue(result.vulnerable, "CONNECT without pairing should be detected")
            assertEquals(HfpSeverity.CRITICAL, result.severity)
        }
    }

    // ── Overall Risk Computation ──

    @Nested
    @DisplayName("Overall Risk Computation")
    inner class RiskComputation {

        @Test
        @DisplayName("Any CRITICAL finding should yield CRITICAL overall risk")
        fun testComputeOverallRisk_criticalFinding() {
            val results = listOf(
                createTestResult(severity = HfpSeverity.LOW, vulnerable = true),
                createTestResult(severity = HfpSeverity.MEDIUM, vulnerable = true),
                createTestResult(severity = HfpSeverity.CRITICAL, vulnerable = true)
            )
            assertEquals(HfpSeverity.CRITICAL, useCase.computeOverallRisk(results))
        }

        @Test
        @DisplayName("Only LOW findings should yield LOW overall risk")
        fun testComputeOverallRisk_allLow() {
            val results = listOf(
                createTestResult(severity = HfpSeverity.LOW, vulnerable = true),
                createTestResult(severity = HfpSeverity.LOW, vulnerable = true)
            )
            assertEquals(HfpSeverity.LOW, useCase.computeOverallRisk(results))
        }

        @Test
        @DisplayName("Empty results should yield INFO overall risk")
        fun testComputeOverallRisk_emptyResults() {
            assertEquals(HfpSeverity.INFO, useCase.computeOverallRisk(emptyList()))
        }

        @Test
        @DisplayName("Non-vulnerable results should yield INFO overall risk")
        fun testComputeOverallRisk_allSafe() {
            val results = listOf(
                createTestResult(severity = HfpSeverity.CRITICAL, vulnerable = false),
                createTestResult(severity = HfpSeverity.HIGH, vulnerable = false)
            )
            assertEquals(HfpSeverity.INFO, useCase.computeOverallRisk(results))
        }

        @Test
        @DisplayName("HIGH finding without CRITICAL should yield HIGH overall risk")
        fun testComputeOverallRisk_highFinding() {
            val results = listOf(
                createTestResult(severity = HfpSeverity.MEDIUM, vulnerable = true),
                createTestResult(severity = HfpSeverity.HIGH, vulnerable = true)
            )
            assertEquals(HfpSeverity.HIGH, useCase.computeOverallRisk(results))
        }
    }

    // ── Report Generation ──

    @Nested
    @DisplayName("Report Generation")
    inner class ReportGeneration {

        @Test
        @DisplayName("Generated report should not be empty")
        fun testGenerateReport_notEmpty() {
            val suite = createTestSuite(
                results = listOf(
                    createTestResult(
                        testName = "Test A",
                        vulnerable = false,
                        severity = HfpSeverity.INFO
                    )
                )
            )
            val report = useCase.generateReport(suite)
            assertTrue(report.isNotBlank(), "Report should not be blank")
            assertTrue(report.contains("HFP Security Test Report"))
            assertTrue(report.contains("AA:BB:CC:DD:EE:FF"))
        }

        @Test
        @DisplayName("Report should include critical findings")
        fun testGenerateReport_includesCriticalFindings() {
            val suite = createTestSuite(
                results = listOf(
                    createTestResult(
                        testName = "Critical Vuln",
                        vulnerable = true,
                        severity = HfpSeverity.CRITICAL,
                        evidence = "Memory leaked"
                    )
                ),
                overallRisk = HfpSeverity.CRITICAL
            )
            val report = useCase.generateReport(suite)
            assertTrue(report.contains("Critical Vuln"), "Report should mention the finding name")
            assertTrue(report.contains("VULNERABLE"), "Report should show VULNERABLE status")
            assertTrue(report.contains("CRITICAL"), "Report should show CRITICAL severity")
        }
    }

    // ── Severity and Category Tests ──

    @Test
    @DisplayName("HfpSeverity enum should be ordered CRITICAL > HIGH > MEDIUM > LOW > INFO")
    fun testHfpSeverityOrdering() {
        val expected = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        val actual = HfpSeverity.entries.map { it.name }
        assertEquals(expected, actual)
    }

    @Test
    @DisplayName("Test case severity should match the expected severity for category")
    fun testTestCase_severityMatchesCategory() {
        val suite = useCase.getTestSuite()

        // All FORMAT_STRING tests should be CRITICAL
        val formatStringTests = suite.filter { it.category == HfpTestCategory.FORMAT_STRING }
        for (tc in formatStringTests) {
            assertEquals(
                HfpSeverity.CRITICAL, tc.severity,
                "Format string test '${tc.name}' should be CRITICAL"
            )
        }

        // All AUTHENTICATION_BYPASS tests should be CRITICAL
        val authBypassTests = suite.filter { it.category == HfpTestCategory.AUTHENTICATION_BYPASS }
        for (tc in authBypassTests) {
            assertEquals(
                HfpSeverity.CRITICAL, tc.severity,
                "Auth bypass test '${tc.name}' should be CRITICAL"
            )
        }

        // All PHONEBOOK_ACCESS tests should be CRITICAL
        val phonebookTests = suite.filter { it.category == HfpTestCategory.PHONEBOOK_ACCESS }
        for (tc in phonebookTests) {
            assertEquals(
                HfpSeverity.CRITICAL, tc.severity,
                "Phonebook test '${tc.name}' should be CRITICAL"
            )
        }
    }

    @Test
    @DisplayName("All test cases should have valid confidence range")
    fun testAnalyzeResponse_confidenceRange() {
        val suite = useCase.getTestSuite()
        for (tc in suite) {
            val result = useCase.analyzeResponse(tc, "OK")
            assertTrue(
                result.confidence in 0.0..1.0,
                "Confidence for '${tc.name}' should be in [0.0, 1.0], got ${result.confidence}"
            )
        }
    }

    @Test
    @DisplayName("Command chain injection should be detected")
    fun testAnalyzeResponse_commandChainInjection() {
        val testCase = findTestCase("Command Chain Injection")
        val result = useCase.analyzeResponse(testCase, "OKOK")

        assertTrue(result.vulnerable, "Multiple OK responses indicate command chaining")
        assertEquals(HfpSeverity.HIGH, result.severity)
    }

    @Test
    @DisplayName("SMS format set OK should be detected as HIGH vulnerability")
    fun testAnalyzeResponse_smsFormatSet() {
        val testCase = findTestCase("SMS Format Set")
        val result = useCase.analyzeResponse(testCase, "OK")

        assertTrue(result.vulnerable, "OK response to CMGF should be detected")
        assertEquals(HfpSeverity.HIGH, result.severity)
    }
}
