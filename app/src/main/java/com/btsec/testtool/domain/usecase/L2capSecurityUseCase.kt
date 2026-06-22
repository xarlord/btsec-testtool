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
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for L2CAP Signaling & Protocol-Level Attack Testing.
 *
 * Provides test suites and packet-building utilities for probing
 * L2CAP signaling channels, connection management, MTU negotiation,
 * and protocol-level vulnerabilities.
 *
 * All operations must be performed on AUTHORIZED targets only.
 */
@Singleton
class L2capSecurityUseCase
    @Inject
    constructor() {
        /**
         * Returns the predefined test suite of L2CAP security test cases.
         */
        fun getTestSuite(): List<L2capTestCase> =
            listOf(
                // Information Query tests
                L2capTestCase(
                    name = "Info Request: Connectionless MTU",
                    category = L2capTestCategory.INFORMATION_QUERY,
                    signalCommand = L2capSignalCommand.INFORMATION_REQUEST,
                    requestPayload = InfoRequestType.CONNECTIONLESS_MTU.code.toLEHexString(),
                    expectedBehavior = "Device responds with connectionless MTU value",
                    vulnerabilityIndicator = "No response or malformed response",
                    severity = L2capSeverity.INFO,
                    recommendation = "Document MTU for further analysis",
                ),
                L2capTestCase(
                    name = "Info Request: Extended Features",
                    category = L2capTestCategory.INFORMATION_QUERY,
                    signalCommand = L2capSignalCommand.INFORMATION_REQUEST,
                    requestPayload = InfoRequestType.EXTENDED_FEATURES.code.toLEHexString(),
                    expectedBehavior = "Device responds with supported extended feature mask",
                    vulnerabilityIndicator = "No response or unexpected feature bits",
                    severity = L2capSeverity.INFO,
                    recommendation = "Document feature support for further analysis",
                ),
                L2capTestCase(
                    name = "Info Request: Fixed Channels",
                    category = L2capTestCategory.INFORMATION_QUERY,
                    signalCommand = L2capSignalCommand.INFORMATION_REQUEST,
                    requestPayload = InfoRequestType.FIXED_CHANNELS.code.toLEHexString(),
                    expectedBehavior = "Device responds with fixed channel bitmap",
                    vulnerabilityIndicator = "No response or unexpected channel bits",
                    severity = L2capSeverity.INFO,
                    recommendation = "Document fixed channel support for further analysis",
                ),
                // Echo Testing
                L2capTestCase(
                    name = "Echo Request: empty payload",
                    category = L2capTestCategory.ECHO_TESTING,
                    signalCommand = L2capSignalCommand.ECHO_REQUEST,
                    requestPayload = "",
                    expectedBehavior = "Device responds with empty echo response",
                    vulnerabilityIndicator = "No response indicates filtering or non-compliance",
                    severity = L2capSeverity.LOW,
                    recommendation = "Verify L2CAP echo is functioning",
                ),
                L2capTestCase(
                    name = "Echo Request: 65535 byte payload (max)",
                    category = L2capTestCategory.ECHO_TESTING,
                    signalCommand = L2capSignalCommand.ECHO_REQUEST,
                    requestPayload = "<max-size-payload>",
                    expectedBehavior = "Device rejects or truncates oversized payload",
                    vulnerabilityIndicator = "Device crashes, reboots, or echoes full payload",
                    severity = L2capSeverity.MEDIUM,
                    recommendation = "Validate MTU handling; oversized payloads may cause buffer overflow",
                ),
                L2capTestCase(
                    name = "Echo Request: malformed data",
                    category = L2capTestCategory.ECHO_TESTING,
                    signalCommand = L2capSignalCommand.ECHO_REQUEST,
                    requestPayload = "DEADBEEFCAFEBABE",
                    expectedBehavior = "Device echoes payload or sends command reject",
                    vulnerabilityIndicator = "Device crashes or sends unexpected response",
                    severity = L2capSeverity.MEDIUM,
                    recommendation = "Investigate malformed data handling",
                ),
                // Connection Manipulation
                L2capTestCase(
                    name = "Connection Request: PSM 0x0001 (SDP)",
                    category = L2capTestCategory.CONNECTION_MANIPULATION,
                    signalCommand = L2capSignalCommand.CONNECTION_REQUEST,
                    requestPayload = "01000041",
                    expectedBehavior = "Device responds with connection response for SDP",
                    vulnerabilityIndicator = "No response or unexpected CID assignment",
                    severity = L2capSeverity.LOW,
                    recommendation = "Verify SDP channel handling",
                ),
                L2capTestCase(
                    name = "Connection Request: invalid PSM",
                    category = L2capTestCategory.CONNECTION_MANIPULATION,
                    signalCommand = L2capSignalCommand.CONNECTION_REQUEST,
                    requestPayload = "FEFF0041",
                    expectedBehavior = "Device responds with connection refuse (PSM not supported)",
                    vulnerabilityIndicator = "Device crashes or accepts invalid PSM",
                    severity = L2capSeverity.LOW,
                    recommendation = "Ensure proper PSM validation",
                ),
                L2capTestCase(
                    name = "Connection Request: reserved PSM",
                    category = L2capTestCategory.CONNECTION_MANIPULATION,
                    signalCommand = L2capSignalCommand.CONNECTION_REQUEST,
                    requestPayload = "00000041",
                    expectedBehavior = "Device rejects connection to reserved PSM",
                    vulnerabilityIndicator = "Device accepts reserved PSM connection",
                    severity = L2capSeverity.MEDIUM,
                    recommendation = "Validate PSM range checking",
                ),
                // MTU Negotiation / Configuration Fuzz
                L2capTestCase(
                    name = "Config Request: MTU=0 (zero MTU DoS)",
                    category = L2capTestCategory.MTU_NEGOTIATION,
                    signalCommand = L2capSignalCommand.CONFIGURATION_REQUEST,
                    requestPayload = "410001000000",
                    expectedBehavior = "Device rejects MTU=0 configuration",
                    vulnerabilityIndicator = "Device accepts zero MTU causing denial of service",
                    severity = L2capSeverity.HIGH,
                    recommendation = "Patch device firmware to reject zero MTU values",
                ),
                L2capTestCase(
                    name = "Config Request: MTU=65535",
                    category = L2capTestCategory.MTU_NEGOTIATION,
                    signalCommand = L2capSignalCommand.CONFIGURATION_REQUEST,
                    requestPayload = "410001FFFF00",
                    expectedBehavior = "Device negotiates down to supported MTU",
                    vulnerabilityIndicator = "Device accepts and attempts to use max MTU",
                    severity = L2capSeverity.MEDIUM,
                    recommendation = "Verify MTU negotiation boundaries",
                ),
                L2capTestCase(
                    name = "Config Request: negative flush timeout",
                    category = L2capTestCategory.CONFIGURATION_FUZZ,
                    signalCommand = L2capSignalCommand.CONFIGURATION_REQUEST,
                    requestPayload = "410002FFFF00",
                    expectedBehavior = "Device rejects invalid flush timeout",
                    vulnerabilityIndicator = "Device accepts negative flush timeout",
                    severity = L2capSeverity.MEDIUM,
                    recommendation = "Validate flush timeout parameter range",
                ),
                L2capTestCase(
                    name = "Config Request: malformed QoS",
                    category = L2capTestCategory.CONFIGURATION_FUZZ,
                    signalCommand = L2capSignalCommand.CONFIGURATION_REQUEST,
                    requestPayload = "4100030000000000",
                    expectedBehavior = "Device rejects malformed QoS configuration",
                    vulnerabilityIndicator = "Device crashes or accepts malformed QoS",
                    severity = L2capSeverity.MEDIUM,
                    recommendation = "Validate QoS parameter parsing",
                ),
                // Signaling Flood
                L2capTestCase(
                    name = "Signal flood: rapid connect/disconnect",
                    category = L2capTestCategory.SIGNALING_FLOOD,
                    signalCommand = L2capSignalCommand.CONNECTION_REQUEST,
                    requestPayload = "<rapid-cycling>",
                    expectedBehavior = "Device rate-limits or gracefully handles rapid commands",
                    vulnerabilityIndicator = "Device crashes, hangs, or drops connections",
                    severity = L2capSeverity.HIGH,
                    recommendation = "Implement rate limiting and command throttling",
                ),
                // Segmentation Attack
                L2capTestCase(
                    name = "Segmentation: incomplete fragment",
                    category = L2capTestCategory.SEGMENTATION_ATTACK,
                    signalCommand = null,
                    requestPayload = "<partial-fragment>",
                    expectedBehavior = "Device discards incomplete L2CAP fragment after timeout",
                    vulnerabilityIndicator = "Device crashes or enters undefined state",
                    severity = L2capSeverity.HIGH,
                    recommendation = "Validate L2CAP segmentation reassembly logic",
                ),
                // Channel Enumeration
                L2capTestCase(
                    name = "Channel enumeration: probe fixed CIDs",
                    category = L2capTestCategory.CHANNEL_ENUMERATION,
                    signalCommand = L2capSignalCommand.INFORMATION_REQUEST,
                    requestPayload = "<cid-probe>",
                    expectedBehavior = "Device responds to valid CIDs, rejects invalid ones",
                    vulnerabilityIndicator = "Unexpected channels responding",
                    severity = L2capSeverity.INFO,
                    recommendation = "Document channel availability for security posture assessment",
                ),
            )

        /**
         * Builds a raw L2CAP packet: length(2 LE) + cid(2 LE) + payload.
         */
        fun buildL2capPacket(
            cid: Int,
            payload: ByteArray,
        ): ByteArray {
            val buffer = ByteBuffer.allocate(4 + payload.size).order(ByteOrder.LITTLE_ENDIAN)
            buffer.putShort(payload.size.toShort())
            buffer.putShort(cid.toShort())
            buffer.put(payload)
            return buffer.array()
        }

        /**
         * Builds a signaling command packet: code(1) + identifier(1) + length(2 LE) + payload.
         */
        fun buildSignalPacket(
            command: L2capSignalCommand,
            identifier: Int,
            payload: ByteArray,
        ): ByteArray {
            val buffer = ByteBuffer.allocate(4 + payload.size).order(ByteOrder.LITTLE_ENDIAN)
            buffer.put(command.code.toByte())
            buffer.put(identifier.toByte())
            buffer.putShort(payload.size.toShort())
            buffer.put(payload)
            return buffer.array()
        }

        /**
         * Parses a raw L2CAP response into an [L2capPacket].
         * Returns null if data is too short or length field mismatches.
         */
        fun parseL2capResponse(data: ByteArray): L2capPacket? {
            if (data.size < L2CAP_HEADER_SIZE) return null

            val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
            val length = buffer.short.toInt() and 0xFFFF
            val channelId = buffer.short.toInt() and 0xFFFF

            if (data.size < L2CAP_HEADER_SIZE + length) return null

            val payload = data.copyOfRange(L2CAP_HEADER_SIZE, L2CAP_HEADER_SIZE + length)

            val signalingCommand =
                if (channelId == L2capFixedChannel.SIGNALING.cid ||
                    channelId == L2capFixedChannel.LE_SIGNALING.cid
                ) {
                    if (payload.isNotEmpty()) {
                        L2capSignalCommand.fromCode(payload[0].toInt() and 0xFF)
                    } else {
                        null
                    }
                } else {
                    null
                }

            val identifier = if (payload.size >= 2) payload[1].toInt() and 0xFF else 0

            return L2capPacket(
                length = length,
                channelId = channelId,
                payload = payload,
                signalingCommand = signalingCommand,
                identifier = identifier,
            )
        }

        /**
         * Maps a CID to its human-readable name using [L2capFixedChannel].
         */
        fun identifyChannel(cid: Int): String {
            return L2capFixedChannel.fromCid(cid)?.channelName
                ?: "Unknown (0x${String.format("%04X", cid)})"
        }

        /**
         * Analyzes a test case result against the actual response bytes.
         */
        fun analyzeResult(
            testCase: L2capTestCase,
            response: ByteArray?,
        ): L2capTestResult {
            val responseHex = response?.toHexString() ?: "null"
            val vulnerable: Boolean
            val evidence: String
            val confidence: Double

            when {
                response == null -> {
                    vulnerable = testCase.severity in
                        setOf(
                            L2capSeverity.HIGH, L2capSeverity.CRITICAL,
                        )
                    evidence = "No response received from target device"
                    confidence = 0.6
                }
                response.isEmpty() -> {
                    vulnerable = testCase.severity in
                        setOf(
                            L2capSeverity.HIGH, L2capSeverity.CRITICAL,
                        )
                    evidence = "Empty response received"
                    confidence = 0.5
                }
                else -> {
                    val packet = parseL2capResponse(response)
                    if (packet != null && packet.signalingCommand == L2capSignalCommand.COMMAND_REJECT) {
                        vulnerable = false
                        evidence = "Target properly rejected command: $responseHex"
                        confidence = 0.9
                    } else {
                        vulnerable = testCase.severity in
                            setOf(
                                L2capSeverity.HIGH, L2capSeverity.CRITICAL,
                            )
                        evidence = "Response received: $responseHex"
                        confidence = 0.7
                    }
                }
            }

            return L2capTestResult(
                category = testCase.category,
                testName = testCase.name,
                signalCommand = testCase.signalCommand,
                requestPayload = testCase.requestPayload,
                responsePayload = responseHex,
                vulnerable = vulnerable,
                confidence = confidence,
                evidence = evidence,
                severity = testCase.severity,
                recommendation = testCase.recommendation,
            )
        }

        /**
         * Computes the overall risk severity from a list of test results.
         */
        fun computeOverallRisk(results: List<L2capTestResult>): L2capSeverity {
            if (results.isEmpty()) return L2capSeverity.INFO

            val vulnerableResults = results.filter { it.vulnerable }
            if (vulnerableResults.isEmpty()) return L2capSeverity.INFO

            return vulnerableResults.minOf { it.severity }
        }

        /**
         * Generates a human-readable text report from an [L2capTestReport].
         */
        fun generateReport(report: L2capTestReport): String {
            val sb = StringBuilder()
            sb.appendLine("=== L2CAP Security Test Report ===")
            sb.appendLine("Target Device: ${report.targetDevice}")
            sb.appendLine("Test Duration: ${report.testDurationMs}ms")
            sb.appendLine()

            if (report.discoveredChannels.isNotEmpty()) {
                sb.appendLine("--- Discovered Channels ---")
                for (channel in report.discoveredChannels) {
                    sb.appendLine("  CID 0x${String.format("%04X", channel.cid)}: ${channel.channelName}")
                }
                sb.appendLine()
            }

            if (report.supportedFeatures.isNotEmpty()) {
                sb.appendLine("--- Supported Features ---")
                for (feature in report.supportedFeatures) {
                    sb.appendLine("  - $feature")
                }
                sb.appendLine()
            }

            sb.appendLine("--- Test Results ---")
            sb.appendLine("Total tests: ${report.results.size}")
            sb.appendLine("Critical: ${report.criticalCount}")
            sb.appendLine("High: ${report.highCount}")
            sb.appendLine()

            for (result in report.results) {
                sb.appendLine("[${result.severity}] ${result.testName}")
                sb.appendLine("  Category: ${result.category}")
                sb.appendLine("  Vulnerable: ${result.vulnerable}")
                sb.appendLine("  Confidence: ${String.format("%.2f", result.confidence)}")
                sb.appendLine("  Evidence: ${result.evidence}")
                sb.appendLine("  Recommendation: ${result.recommendation}")
                sb.appendLine()
            }

            sb.appendLine("=== End of Report ===")
            return sb.toString()
        }

        private fun Int.toLEHexString(): String {
            val buffer = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN)
            buffer.putShort(this.toShort())
            return buffer.array().toHexString()
        }

        private fun ByteArray.toHexString(): String = joinToString("") { String.format("%02X", it) }

        companion object {
            const val L2CAP_HEADER_SIZE = 4
        }
    }
