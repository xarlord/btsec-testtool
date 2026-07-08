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
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Tests for [L2capSecurityUseCase].
 *
 * All test scenarios are designed for AUTHORIZED security testing validation.
 */
class L2capSecurityUseCaseTest {
    private lateinit var useCase: L2capSecurityUseCase

    @BeforeEach
    fun setup() {
        useCase = L2capSecurityUseCase()
    }

    @Nested
    @DisplayName("getTestSuite")
    inner class GetTestSuite {
        @Test
        @DisplayName("should have at least 14 predefined tests")
        fun testGetTestSuite_hasMinimum14Tests() {
            val suite = useCase.getTestSuite()
            assertThat(suite).hasSize(23)
            assertThat(suite.size).isAtLeast(14)
        }

        @Test
        @DisplayName("should cover all test categories")
        fun testGetTestSuite_allCategoriesCovered() {
            val suite = useCase.getTestSuite()
            val categories = suite.map { it.category }.toSet()
            assertThat(categories).containsAtLeastElementsIn(
                L2capTestCategory.entries,
            )
        }

        @Test
        @DisplayName("should include disconnection attack test case")
        fun testGetTestSuite_hasDisconnectionAttack() {
            val suite = useCase.getTestSuite()
            val testCase = suite.find { it.category == L2capTestCategory.DISCONNECTION_ATTACK }
            assertThat(testCase).isNotNull()
            assertThat(testCase!!.signalCommand).isEqualTo(L2capSignalCommand.DISCONNECTION_REQUEST)
            assertThat(testCase.severity).isEqualTo(L2capSeverity.HIGH)
            assertThat(testCase.name).contains("Disconnection attack")
        }

        @Test
        @DisplayName("should include LE signaling connection parameter update test")
        fun testGetTestSuite_hasLeSignaling() {
            val suite = useCase.getTestSuite()
            val testCase = suite.find { it.category == L2capTestCategory.LE_SIGNALING }
            assertThat(testCase).isNotNull()
            assertThat(testCase!!.severity).isEqualTo(L2capSeverity.MEDIUM)
            assertThat(testCase.name).contains("Connection Parameter Update")
        }

        @Test
        @DisplayName("should include credit-based flow control abuse test")
        fun testGetTestSuite_hasCreditFlowControl() {
            val suite = useCase.getTestSuite()
            val testCase = suite.find { it.category == L2capTestCategory.CREDIT_FLOW_CONTROL }
            assertThat(testCase).isNotNull()
            assertThat(testCase!!.severity).isEqualTo(L2capSeverity.HIGH)
            assertThat(testCase.name).contains("Credit flow control")
        }

        @Test
        @DisplayName("should include ACL connection flood test")
        fun testGetTestSuite_hasAclFlood() {
            val suite = useCase.getTestSuite()
            val testCase = suite.find { it.category == L2capTestCategory.ACL_FLOOD }
            assertThat(testCase).isNotNull()
            assertThat(testCase!!.severity).isEqualTo(L2capSeverity.HIGH)
            assertThat(testCase.name).contains("ACL flood")
        }

        @Test
        @DisplayName("should include configuration rejection test")
        fun testGetTestSuite_hasConfigRejection() {
            val suite = useCase.getTestSuite()
            val testCase = suite.find { it.category == L2capTestCategory.CONFIG_REJECTION }
            assertThat(testCase).isNotNull()
            assertThat(testCase!!.signalCommand).isEqualTo(L2capSignalCommand.CONFIGURATION_RESPONSE)
            assertThat(testCase.severity).isEqualTo(L2capSeverity.MEDIUM)
            assertThat(testCase.name).contains("Config rejection")
        }

        @Test
        @DisplayName("should include command reject fuzzing test")
        fun testGetTestSuite_hasCommandRejectFuzz() {
            val suite = useCase.getTestSuite()
            val testCase = suite.find { it.category == L2capTestCategory.COMMAND_REJECT_FUZZ }
            assertThat(testCase).isNotNull()
            assertThat(testCase!!.signalCommand).isEqualTo(L2capSignalCommand.COMMAND_REJECT)
            assertThat(testCase.severity).isEqualTo(L2capSeverity.MEDIUM)
            assertThat(testCase.name).contains("Command reject fuzzing")
        }

        @Test
        @DisplayName("should include reconnection attack test")
        fun testGetTestSuite_hasReconnectionAttack() {
            val suite = useCase.getTestSuite()
            val testCase = suite.find { it.category == L2capTestCategory.RECONNECTION_ATTACK }
            assertThat(testCase).isNotNull()
            assertThat(testCase!!.signalCommand).isEqualTo(L2capSignalCommand.CONNECTION_REQUEST)
            assertThat(testCase.severity).isEqualTo(L2capSeverity.HIGH)
            assertThat(testCase.name).contains("Reconnection attack")
        }
    }

    @Nested
    @DisplayName("buildL2capPacket")
    inner class BuildL2capPacket {
        @Test
        @DisplayName("should produce correct L2CAP packet format")
        fun testBuildL2capPacket_correctFormat() {
            val payload = byteArrayOf(0x0A, 0x01, 0x00, 0x01)
            val result = useCase.buildL2capPacket(0x0001, payload)

            // length(2 LE) + cid(2 LE) + payload
            assertThat(result).hasLength(4 + payload.size)

            val buffer = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN)
            assertThat(buffer.short.toInt() and 0xFFFF).isEqualTo(payload.size)
            assertThat(buffer.short.toInt() and 0xFFFF).isEqualTo(0x0001)
        }

        @Test
        @DisplayName("should match payload length in header")
        fun testBuildL2capPacket_lengthMatches() {
            val payload = ByteArray(100) { it.toByte() }
            val result = useCase.buildL2capPacket(0x0004, payload)

            val buffer = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN)
            val declaredLength = buffer.short.toInt() and 0xFFFF
            assertThat(declaredLength).isEqualTo(100)

            val payloadInResult = result.copyOfRange(4, result.size)
            assertThat(payloadInResult).isEqualTo(payload)
        }
    }

    @Nested
    @DisplayName("buildSignalPacket")
    inner class BuildSignalPacket {
        @Test
        @DisplayName("should produce correct signaling header")
        fun testBuildSignalPacket_correctHeader() {
            val payload = byteArrayOf(0x01, 0x00)
            val result =
                useCase.buildSignalPacket(
                    L2capSignalCommand.INFORMATION_REQUEST,
                    0x42,
                    payload,
                )

            assertThat(result).hasLength(4 + payload.size)

            // code(1) + identifier(1) + length(2 LE) + payload
            assertThat(result[0].toInt() and 0xFF).isEqualTo(L2capSignalCommand.INFORMATION_REQUEST.code)
            assertThat(result[1].toInt() and 0xFF).isEqualTo(0x42)

            val buffer = ByteBuffer.wrap(result, 2, 2).order(ByteOrder.LITTLE_ENDIAN)
            assertThat(buffer.short.toInt() and 0xFFFF).isEqualTo(payload.size)
        }

        @Test
        @DisplayName("should match command code in first byte")
        fun testBuildSignalPacket_commandCodeMatches() {
            val payload = byteArrayOf()
            val result =
                useCase.buildSignalPacket(
                    L2capSignalCommand.ECHO_REQUEST,
                    0x01,
                    payload,
                )

            assertThat(result[0].toInt() and 0xFF).isEqualTo(0x08)
        }
    }

    @Nested
    @DisplayName("parseL2capResponse")
    inner class ParseL2capResponse {
        @Test
        @DisplayName("should parse valid L2CAP packet")
        fun testParseL2capResponse_validPacket() {
            val payload = byteArrayOf(0x0A, 0x01, 0x00, 0x01)
            val rawPacket = useCase.buildL2capPacket(0x0001, payload)

            val parsed = useCase.parseL2capResponse(rawPacket)

            assertThat(parsed).isNotNull()
            assertThat(parsed!!.length).isEqualTo(payload.size)
            assertThat(parsed.channelId).isEqualTo(0x0001)
            assertThat(parsed.payload).isEqualTo(payload)
        }

        @Test
        @DisplayName("should return null for data too short")
        fun testParseL2capResponse_tooShort() {
            val result = useCase.parseL2capResponse(byteArrayOf(0x01, 0x02))
            assertThat(result).isNull()
        }

        @Test
        @DisplayName("should return null when declared length exceeds actual data")
        fun testParseL2capResponse_lengthMismatch() {
            // Declare length=100 but only provide 4-byte header + 2 bytes
            val buffer = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
            buffer.putShort(100) // length=100
            buffer.putShort(0x0001) // CID
            buffer.put(0x0A) // partial payload
            buffer.put(0x01)

            val result = useCase.parseL2capResponse(buffer.array())
            assertThat(result).isNull()
        }
    }

    @Nested
    @DisplayName("identifyChannel")
    inner class IdentifyChannel {
        @Test
        @DisplayName("should identify L2CAP Signaling channel")
        fun testIdentifyChannel_signaling() {
            assertThat(useCase.identifyChannel(0x0001)).isEqualTo("L2CAP Signaling")
        }

        @Test
        @DisplayName("should identify Attribute Protocol channel")
        fun testIdentifyChannel_att() {
            assertThat(useCase.identifyChannel(0x0004)).isEqualTo("Attribute Protocol")
        }

        @Test
        @DisplayName("should return Unknown for unrecognized CIDs")
        fun testIdentifyChannel_unknown() {
            val result = useCase.identifyChannel(0x00FF)
            assertThat(result).contains("Unknown")
            assertThat(result).contains("00FF")
        }
    }

    @Nested
    @DisplayName("analyzeResult")
    inner class AnalyzeResult {
        @Test
        @DisplayName("should detect vulnerability when null response on high-severity test")
        fun testAnalyzeResult_vulnerableResponse() {
            val testCase =
                L2capTestCase(
                    name = "Config Request: MTU=0",
                    category = L2capTestCategory.MTU_NEGOTIATION,
                    signalCommand = L2capSignalCommand.CONFIGURATION_REQUEST,
                    requestPayload = "test",
                    expectedBehavior = "Should reject",
                    vulnerabilityIndicator = "Accepts zero MTU",
                    severity = L2capSeverity.HIGH,
                    recommendation = "Patch firmware",
                )

            val result = useCase.analyzeResult(testCase, null)

            assertThat(result.vulnerable).isTrue()
            assertThat(result.evidence).contains("No response")
            assertThat(result.confidence).isGreaterThan(0.0)
        }

        @Test
        @DisplayName("should not mark as vulnerable when command is properly rejected")
        fun testAnalyzeResult_errorResponse() {
            val testCase =
                L2capTestCase(
                    name = "Info Request: MTU",
                    category = L2capTestCategory.INFORMATION_QUERY,
                    signalCommand = L2capSignalCommand.INFORMATION_REQUEST,
                    requestPayload = "0100",
                    expectedBehavior = "Respond with MTU",
                    vulnerabilityIndicator = "No response",
                    severity = L2capSeverity.INFO,
                    recommendation = "Document",
                )

            // Build a COMMAND_REJECT response
            val rejectPayload = byteArrayOf(0x01, 0x01, 0x02, 0x00)
            val rawPacket = useCase.buildL2capPacket(0x0001, rejectPayload)

            val result = useCase.analyzeResult(testCase, rawPacket)

            assertThat(result.vulnerable).isFalse()
            assertThat(result.evidence).contains("rejected")
        }
    }

    @Nested
    @DisplayName("computeOverallRisk")
    inner class ComputeOverallRisk {
        @Test
        @DisplayName("should return CRITICAL when any result is critical and vulnerable")
        fun testComputeOverallRisk_critical() {
            val results =
                listOf(
                    L2capTestResult(
                        category = L2capTestCategory.MTU_NEGOTIATION,
                        testName = "MTU=0",
                        signalCommand = L2capSignalCommand.CONFIGURATION_REQUEST,
                        requestPayload = "",
                        responsePayload = null,
                        vulnerable = true,
                        confidence = 0.9,
                        evidence = "Device crashed",
                        severity = L2capSeverity.CRITICAL,
                        recommendation = "Patch",
                    ),
                    L2capTestResult(
                        category = L2capTestCategory.ECHO_TESTING,
                        testName = "Echo",
                        signalCommand = L2capSignalCommand.ECHO_REQUEST,
                        requestPayload = "",
                        responsePayload = "ok",
                        vulnerable = false,
                        confidence = 0.8,
                        evidence = "Normal",
                        severity = L2capSeverity.INFO,
                        recommendation = "None",
                    ),
                )

            val risk = useCase.computeOverallRisk(results)

            // CRITICAL has ordinal 0, so minOf returns CRITICAL
            assertThat(risk).isEqualTo(L2capSeverity.CRITICAL)
        }
    }

    @Nested
    @DisplayName("generateReport")
    inner class GenerateReport {
        @Test
        @DisplayName("should include discovered channels in output")
        fun testGenerateReport_includesChannels() {
            val report =
                L2capTestReport(
                    targetDevice = "AA:BB:CC:DD:EE:FF",
                    results = emptyList(),
                    discoveredChannels =
                        listOf(
                            L2capFixedChannel.SIGNALING,
                            L2capFixedChannel.ATT,
                            L2capFixedChannel.SMP,
                        ),
                    supportedFeatures = listOf("Flow Control", "Retransmission"),
                    criticalCount = 0,
                    highCount = 0,
                    testDurationMs = 5000,
                )

            val output = useCase.generateReport(report)

            assertThat(output).contains("L2CAP Signaling")
            assertThat(output).contains("Attribute Protocol")
            assertThat(output).contains("Security Manager (LE)")
            assertThat(output).contains("Discovered Channels")
            assertThat(output).contains("AA:BB:CC:DD:EE:FF")
        }

        @Test
        @DisplayName("should include test results with severity and evidence")
        fun testGenerateReport_includesResults() {
            val report =
                L2capTestReport(
                    targetDevice = "11:22:33:44:55:66",
                    results =
                        listOf(
                            L2capTestResult(
                                category = L2capTestCategory.MTU_NEGOTIATION,
                                testName = "Config Request: MTU=0",
                                signalCommand = L2capSignalCommand.CONFIGURATION_REQUEST,
                                requestPayload = "payload",
                                responsePayload = "resp",
                                vulnerable = true,
                                confidence = 0.95,
                                evidence = "Device accepted zero MTU",
                                severity = L2capSeverity.HIGH,
                                recommendation = "Reject zero MTU",
                            ),
                        ),
                    discoveredChannels = emptyList(),
                    supportedFeatures = emptyList(),
                    criticalCount = 0,
                    highCount = 1,
                    testDurationMs = 1200,
                )

            val output = useCase.generateReport(report)

            assertThat(output).contains("Config Request: MTU=0")
            assertThat(output).contains("HIGH")
            assertThat(output).contains("Device accepted zero MTU")
            assertThat(output).contains("Reject zero MTU")
            assertThat(output).contains("High: 1")
        }
    }
}
