/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("SapSecurityUseCase")
class SapSecurityUseCaseTest {
    private lateinit var useCase: SapSecurityUseCase

    @BeforeEach
    fun setUp() {
        useCase = SapSecurityUseCase()
    }

    @Nested
    @DisplayName("getTestSuite")
    inner class GetTestSuiteTests {
        @Test
        @DisplayName("should return at least 12 test cases")
        fun testGetTestSuite_hasMinimum12Tests() {
            val suite = useCase.getTestSuite()
            assertThat(suite).hasSize(15)
        }

        @Test
        @DisplayName("should cover all SAP test categories")
        fun testGetTestSuite_allCategoriesCovered() {
            val suite = useCase.getTestSuite()
            val coveredCategories = suite.map { it.category }.toSet()
            assertThat(coveredCategories).containsAtLeastElementsIn(
                listOf(
                    SapTestCategory.AUTHENTICATION_BYPASS,
                    SapTestCategory.ATR_EXTRACTION,
                    SapTestCategory.SIM_DATA_READ,
                    SapTestCategory.SIM_POWER_CONTROL,
                    SapTestCategory.SIM_RESET,
                    SapTestCategory.CARD_READER_STATUS,
                    SapTestCategory.APDU_INJECTION,
                    SapTestCategory.EMERGENCY_CALL,
                ),
            )
        }
    }

    @Nested
    @DisplayName("SimApdu.toBytes")
    inner class SimApduTests {
        @Test
        @DisplayName("should build APDU bytes without data or Le")
        fun testSimApdu_toBytes() {
            val apdu = SimApdu(cla = 0x00, ins = 0xA4, p1 = 0x08, p2 = 0x04)
            val bytes = apdu.toBytes()
            assertThat(bytes).hasLength(4)
            assertThat(bytes[0]).isEqualTo(0x00.toByte())
            assertThat(bytes[1]).isEqualTo(0xA4.toByte())
            assertThat(bytes[2]).isEqualTo(0x08.toByte())
            assertThat(bytes[3]).isEqualTo(0x04.toByte())
        }

        @Test
        @DisplayName("should build APDU bytes with data and Le")
        fun testSimApdu_toBytes_withData() {
            val apdu =
                SimApdu(
                    cla = 0x00,
                    ins = 0xA4,
                    p1 = 0x08,
                    p2 = 0x04,
                    data = byteArrayOf(0x3F, 0x00),
                    le = 0x09,
                )
            val bytes = apdu.toBytes()
            // CLA INS P1 P2 Lc Data Le = 4 + 1 + 2 + 1 = 8
            assertThat(bytes).hasLength(8)
            assertThat(bytes[0]).isEqualTo(0x00.toByte()) // CLA
            assertThat(bytes[1]).isEqualTo(0xA4.toByte()) // INS
            assertThat(bytes[2]).isEqualTo(0x08.toByte()) // P1
            assertThat(bytes[3]).isEqualTo(0x04.toByte()) // P2
            assertThat(bytes[4]).isEqualTo(0x02.toByte()) // Lc = data.length
            assertThat(bytes[5]).isEqualTo(0x3F.toByte()) // Data[0]
            assertThat(bytes[6]).isEqualTo(0x00.toByte()) // Data[1]
            assertThat(bytes[7]).isEqualTo(0x09.toByte()) // Le
        }

        @Test
        @DisplayName("should build APDU bytes with only Le (no data)")
        fun testSimApdu_toBytes_withLeOnly() {
            val apdu = SimApdu(cla = 0x00, ins = 0xB2, p1 = 0x01, p2 = 0x04, le = 0x09)
            val bytes = apdu.toBytes()
            // CLA INS P1 P2 Le = 5
            assertThat(bytes).hasLength(5)
            assertThat(bytes[4]).isEqualTo(0x09.toByte()) // Le
        }
    }

    @Nested
    @DisplayName("parseSimResponse")
    inner class ParseSimResponseTests {
        @Test
        @DisplayName("should parse success response (90 00)")
        fun testParseSimResponse_success() {
            val response = byteArrayOf(0x08.toByte(), 0x90.toByte(), 0x00.toByte())
            val result = useCase.parseSimResponse(response)
            assertThat(result).isNotNull()
            assertThat(result).contains("Success")
            assertThat(result).contains("1 bytes")
        }

        @Test
        @DisplayName("should parse error response (6A 82)")
        fun testParseSimResponse_error() {
            val response = byteArrayOf(0x6A.toByte(), 0x82.toByte())
            val result = useCase.parseSimResponse(response)
            assertThat(result).isNotNull()
            assertThat(result).contains("Error")
            assertThat(result).contains("File not found")
        }

        @Test
        @DisplayName("should parse more data response (61 XX)")
        fun testParseSimResponse_moreData() {
            val response = byteArrayOf(0x61.toByte(), 0x20.toByte())
            val result = useCase.parseSimResponse(response)
            assertThat(result).isNotNull()
            assertThat(result).contains("More data available")
            assertThat(result).contains("32")
        }

        @Test
        @DisplayName("should return null for too-short response")
        fun testParseSimResponse_tooShort() {
            val response = byteArrayOf(0x90.toByte())
            val result = useCase.parseSimResponse(response)
            assertThat(result).isNull()
        }

        @Test
        @DisplayName("should parse security error (69 82)")
        fun testParseSimResponse_securityError() {
            val response = byteArrayOf(0x69.toByte(), 0x82.toByte())
            val result = useCase.parseSimResponse(response)
            assertThat(result).contains("Security status not satisfied")
        }
    }

    @Nested
    @DisplayName("extractImsi")
    inner class ExtractImsiTests {
        @Test
        @DisplayName("should extract valid IMSI from BCD data")
        fun testExtractImsi_validData() {
            // IMSI 310150123456789 encoded per 3GPP TS 24.008 mobile identity.
            val data =
                byteArrayOf(
                    // length
                    0x08.toByte(),
                    0x39.toByte(), 0x01.toByte(), 0x51.toByte(), 0x10.toByte(),
                    0x32.toByte(), 0x54.toByte(), 0x76.toByte(), 0x98.toByte(),
                )
            val imsi = useCase.extractImsi(data)
            assertThat(imsi).isEqualTo("310150123456789")
        }

        @Test
        @DisplayName("should decode an even-length IMSI with a final filler nibble")
        fun testExtractImsi_evenDigitCount() {
            val data =
                byteArrayOf(
                    0x08.toByte(),
                    // Digit 1 = 3; even parity; mobile identity type = IMSI.
                    0x31.toByte(),
                    0x01.toByte(), 0x51.toByte(), 0x10.toByte(), 0x32.toByte(),
                    0x54.toByte(), 0x76.toByte(), 0xF8.toByte(),
                )

            assertThat(useCase.extractImsi(data)).isEqualTo("31015012345678")
        }

        @Test
        @DisplayName("should reject non-decimal BCD digits")
        fun testExtractImsi_invalidBcdDigit() {
            val data =
                byteArrayOf(
                    0x08.toByte(),
                    0x39.toByte(), 0x0A.toByte(), 0x51.toByte(), 0x10.toByte(),
                    0x32.toByte(), 0x54.toByte(), 0x76.toByte(), 0x98.toByte(),
                )

            assertThat(useCase.extractImsi(data)).isNull()
        }

        @Test
        @DisplayName("should reject a filler nibble before the final octet")
        fun testExtractImsi_earlyFiller() {
            val data =
                byteArrayOf(
                    0x08.toByte(),
                    0x39.toByte(), 0xF1.toByte(), 0x51.toByte(), 0x10.toByte(),
                    0x32.toByte(), 0x54.toByte(), 0x76.toByte(), 0x98.toByte(),
                )

            assertThat(useCase.extractImsi(data)).isNull()
        }

        @Test
        @DisplayName("should return null for empty data")
        fun testExtractImsi_emptyData() {
            val imsi = useCase.extractImsi(byteArrayOf())
            assertThat(imsi).isNull()
        }
    }

    @Nested
    @DisplayName("extractIccid")
    inner class ExtractIccidTests {
        @Test
        @DisplayName("should extract valid ICCID from BCD data")
        fun testExtractIccid_validData() {
            // BCD-encoded ICCID: 98 68 01 23 45 67 89 01 23 45
            val data =
                byteArrayOf(
                    0x98.toByte(), 0x68.toByte(), 0x01.toByte(), 0x23.toByte(),
                    0x45.toByte(), 0x67.toByte(), 0x89.toByte(), 0x01.toByte(),
                    0x23.toByte(), 0x45.toByte(),
                )
            val iccid = useCase.extractIccid(data)
            assertThat(iccid).isNotNull()
            assertThat(iccid).isNotEmpty()
            // First byte 0x98 -> low nibble 8, high nibble 9 -> "89"
            assertThat(iccid).startsWith("89")
        }
    }

    @Nested
    @DisplayName("analyzeResult")
    inner class AnalyzeResultTests {
        @Test
        @DisplayName("should detect vulnerability when connection accepted")
        fun testAnalyzeResult_connectionAccepted() {
            val testCase =
                SapTestCase(
                    name = "Connect without pairing",
                    category = SapTestCategory.AUTHENTICATION_BYPASS,
                    apduCommand = null,
                    sapMessage = SapMessageType.CONNECT_REQ,
                    expectedBehavior = "Connection should be rejected",
                    vulnerabilityIndicator = "Connection accepted without pairing",
                    severity = SapSeverity.CRITICAL,
                    recommendation = "Enforce pairing",
                )
            val result = useCase.analyzeResult(testCase, "Success: Connected")
            assertThat(result.vulnerable).isTrue()
            assertThat(result.confidence).isWithin(0.01).of(0.9)
            assertThat(result.severity).isEqualTo(SapSeverity.CRITICAL)
        }

        @Test
        @DisplayName("should detect vulnerability when ATR returned")
        fun testAnalyzeResult_atrReturned() {
            val testCase =
                SapTestCase(
                    name = "ATR extraction",
                    category = SapTestCategory.ATR_EXTRACTION,
                    apduCommand = null,
                    sapMessage = SapMessageType.TRANSFER_ATR_REQ,
                    expectedBehavior = "ATR should be protected",
                    vulnerabilityIndicator = "ATR returned without authentication",
                    severity = SapSeverity.HIGH,
                    recommendation = "Require authentication",
                )
            val result = useCase.analyzeResult(testCase, "Success (15 bytes): 3B 9F...")
            assertThat(result.vulnerable).isTrue()
            assertThat(result.evidence).contains("Vulnerability confirmed")
        }

        @Test
        @DisplayName("should not detect vulnerability on error response")
        fun testAnalyzeResult_errorResponse() {
            val testCase =
                SapTestCase(
                    name = "Connect without pairing",
                    category = SapTestCategory.AUTHENTICATION_BYPASS,
                    apduCommand = null,
                    sapMessage = SapMessageType.CONNECT_REQ,
                    expectedBehavior = "Connection should be rejected",
                    vulnerabilityIndicator = "Connection accepted without pairing",
                    severity = SapSeverity.CRITICAL,
                    recommendation = "Enforce pairing",
                )
            val result = useCase.analyzeResult(testCase, "Error: Connection rejected")
            assertThat(result.vulnerable).isFalse()
        }

        @Test
        @DisplayName("should not detect vulnerability on null response")
        fun testAnalyzeResult_nullResponse() {
            val testCase =
                SapTestCase(
                    name = "Connect without pairing",
                    category = SapTestCategory.AUTHENTICATION_BYPASS,
                    apduCommand = null,
                    sapMessage = SapMessageType.CONNECT_REQ,
                    expectedBehavior = "Connection should be rejected",
                    vulnerabilityIndicator = "Connection accepted without pairing",
                    severity = SapSeverity.CRITICAL,
                    recommendation = "Enforce pairing",
                )
            val result = useCase.analyzeResult(testCase, null)
            assertThat(result.vulnerable).isFalse()
            assertThat(result.confidence).isWithin(0.01).of(0.0)
        }
    }

    @Nested
    @DisplayName("computeOverallRisk")
    inner class ComputeOverallRiskTests {
        @Test
        @DisplayName("should return CRITICAL when critical vulnerability found")
        fun testComputeOverallRisk_critical() {
            val results =
                listOf(
                    createTestResult(SapSeverity.CRITICAL, true),
                    createTestResult(SapSeverity.HIGH, true),
                    createTestResult(SapSeverity.LOW, false),
                )
            assertThat(useCase.computeOverallRisk(results)).isEqualTo(SapSeverity.CRITICAL)
        }

        @Test
        @DisplayName("should return HIGH when only high vulnerability found")
        fun testComputeOverallRisk_high() {
            val results =
                listOf(
                    createTestResult(SapSeverity.HIGH, true),
                    createTestResult(SapSeverity.MEDIUM, false),
                    createTestResult(SapSeverity.LOW, false),
                )
            assertThat(useCase.computeOverallRisk(results)).isEqualTo(SapSeverity.HIGH)
        }

        @Test
        @DisplayName("should return INFO when no vulnerabilities found")
        fun testComputeOverallRisk_info() {
            val results =
                listOf(
                    createTestResult(SapSeverity.HIGH, false),
                    createTestResult(SapSeverity.MEDIUM, false),
                )
            assertThat(useCase.computeOverallRisk(results)).isEqualTo(SapSeverity.INFO)
        }

        @Test
        @DisplayName("should return INFO for empty results")
        fun testComputeOverallRisk_empty() {
            assertThat(useCase.computeOverallRisk(emptyList())).isEqualTo(SapSeverity.INFO)
        }
    }

    @Nested
    @DisplayName("generateReport")
    inner class GenerateReportTests {
        @Test
        @DisplayName("should include SIM data in report")
        fun testGenerateReport_includesSimData() {
            val report =
                SapTestReport(
                    targetDevice = "AA:BB:CC:DD:EE:FF",
                    results =
                        listOf(
                            createTestResult(SapSeverity.CRITICAL, true).copy(testName = "Test A"),
                            createTestResult(SapSeverity.HIGH, false).copy(testName = "Test B"),
                        ),
                    simDataExtracted =
                        SapSimData(
                            imsi = "310150123456789",
                            iccid = "89123456789012345678",
                            operatorName = "Test Operator",
                        ),
                    criticalCount = 1,
                    highCount = 0,
                    testDurationMs = 5000L,
                )
            val text = useCase.generateReport(report)
            assertThat(text).contains("310150123456789")
            assertThat(text).contains("89123456789012345678")
            assertThat(text).contains("Test Operator")
            assertThat(text).contains("CRITICAL")
            assertThat(text).contains("AUTHORIZED")
        }

        @Test
        @DisplayName("should handle report without SIM data")
        fun testGenerateReport_noSimData() {
            val report =
                SapTestReport(
                    targetDevice = "AA:BB:CC:DD:EE:FF",
                    results = emptyList(),
                    simDataExtracted = null,
                    criticalCount = 0,
                    highCount = 0,
                    testDurationMs = 1000L,
                )
            val text = useCase.generateReport(report)
            assertThat(text).contains("AA:BB:CC:DD:EE:FF")
            assertThat(text).contains("Overall Risk")
        }
    }

    private fun createTestResult(
        severity: SapSeverity,
        vulnerable: Boolean,
        category: SapTestCategory = SapTestCategory.APDU_INJECTION,
    ): SapTestResult =
        SapTestResult(
            category = category,
            testName = "Test-${severity.name}",
            apduCommand = null,
            sapMessage = null,
            response = if (vulnerable) "Success" else "Error",
            vulnerable = vulnerable,
            confidence = if (vulnerable) 0.9 else 0.3,
            evidence = "test evidence",
            severity = severity,
            recommendation = "test recommendation",
        )
}
