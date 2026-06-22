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
import javax.inject.Singleton

/**
 * Predefined test case for SAP security testing in AUTHORIZED scenarios.
 */
data class SapTestCase(
    val name: String,
    val category: SapTestCategory,
    val apduCommand: SimApdu?,
    val sapMessage: SapMessageType?,
    val expectedBehavior: String,
    val vulnerabilityIndicator: String,
    val severity: SapSeverity,
    val recommendation: String,
)

/**
 * Use case for SAP (SIM Access Profile) security testing.
 * Provides predefined test cases and analysis for AUTHORIZED security testing
 * of SIM access over Bluetooth connections.
 */
@Singleton
class SapSecurityUseCase {
    /**
     * Returns the full suite of predefined SAP security test cases.
     */
    fun getTestSuite(): List<SapTestCase> =
        listOf(
            // 1. SAP CONNECT_REQ without pairing -> CRITICAL if accepted
            SapTestCase(
                name = "Connect without pairing",
                category = SapTestCategory.AUTHENTICATION_BYPASS,
                apduCommand = null,
                sapMessage = SapMessageType.CONNECT_REQ,
                expectedBehavior = "Connection should be rejected without prior pairing",
                vulnerabilityIndicator = "Connection accepted without pairing",
                severity = SapSeverity.CRITICAL,
                recommendation = "Enforce Bluetooth pairing requirement before accepting SAP connections",
            ),
            // 2. TRANSFER_ATR_REQ -> HIGH if ATR returned
            SapTestCase(
                name = "ATR extraction",
                category = SapTestCategory.ATR_EXTRACTION,
                apduCommand = null,
                sapMessage = SapMessageType.TRANSFER_ATR_REQ,
                expectedBehavior = "ATR should only be returned to authenticated clients",
                vulnerabilityIndicator = "ATR returned without proper authentication",
                severity = SapSeverity.HIGH,
                recommendation = "Require authentication before responding to ATR requests",
            ),
            // 3. Read IMSI: SELECT MF then READ BINARY EF_IMSI
            SapTestCase(
                name = "Read IMSI (EF_IMSI)",
                category = SapTestCategory.SIM_DATA_READ,
                apduCommand = SimApdu(cla = 0x00, ins = 0xB2, p1 = 0x01, p2 = 0x04, le = 0x09),
                sapMessage = SapMessageType.TRANSFER_APDU_REQ,
                expectedBehavior = "IMSI should require PIN authentication to read",
                vulnerabilityIndicator = "IMSI readable without PIN verification",
                severity = SapSeverity.CRITICAL,
                recommendation = "Require SIM PIN before allowing IMSI read operations",
            ),
            // 4. Read ICCID
            SapTestCase(
                name = "Read ICCID (EF_ICCID 2FE2)",
                category = SapTestCategory.SIM_DATA_READ,
                apduCommand = SimApdu(cla = 0x00, ins = 0xB2, p1 = 0x01, p2 = 0x04, le = 0x0A),
                sapMessage = SapMessageType.TRANSFER_APDU_REQ,
                expectedBehavior = "ICCID should require PIN authentication to read",
                vulnerabilityIndicator = "ICCID readable without PIN verification",
                severity = SapSeverity.CRITICAL,
                recommendation = "Require SIM PIN before allowing ICCID read operations",
            ),
            // 5. Read SPN (operator name)
            SapTestCase(
                name = "Read SPN (Service Provider Name)",
                category = SapTestCategory.SIM_DATA_READ,
                apduCommand = SimApdu(cla = 0x00, ins = 0xB2, p1 = 0x01, p2 = 0x04, le = 0x11),
                sapMessage = SapMessageType.TRANSFER_APDU_REQ,
                expectedBehavior = "SPN read may be allowed but should be monitored",
                vulnerabilityIndicator = "SPN readable reveals operator information",
                severity = SapSeverity.HIGH,
                recommendation = "Log SPN access attempts for audit purposes",
            ),
            // 6. Read phonebook EF_ADN
            SapTestCase(
                name = "Read phonebook (EF_ADN 6F3A)",
                category = SapTestCategory.SIM_DATA_READ,
                apduCommand = SimApdu(cla = 0x00, ins = 0xA4, p1 = 0x08, p2 = 0x04, data = byteArrayOf(0x3F, 0x00, 0x7F, 0x10, 0x6F, 0x3A)),
                sapMessage = SapMessageType.TRANSFER_APDU_REQ,
                expectedBehavior = "Phonebook should require PIN authentication to read",
                vulnerabilityIndicator = "Phonebook entries readable without PIN",
                severity = SapSeverity.CRITICAL,
                recommendation = "Require SIM PIN before allowing phonebook read operations",
            ),
            // 7. Read SMS
            SapTestCase(
                name = "Read SMS (EF_SMS 6F3C)",
                category = SapTestCategory.SIM_DATA_READ,
                apduCommand = SimApdu(cla = 0x00, ins = 0xA4, p1 = 0x08, p2 = 0x04, data = byteArrayOf(0x3F, 0x00, 0x7F, 0x10, 0x6F, 0x3C)),
                sapMessage = SapMessageType.TRANSFER_APDU_REQ,
                expectedBehavior = "SMS should require PIN authentication to read",
                vulnerabilityIndicator = "SMS messages readable without PIN",
                severity = SapSeverity.CRITICAL,
                recommendation = "Require SIM PIN before allowing SMS read operations",
            ),
            // 8. Power SIM off
            SapTestCase(
                name = "Power SIM off",
                category = SapTestCategory.SIM_POWER_CONTROL,
                apduCommand = null,
                sapMessage = SapMessageType.POWER_SIM_OFF_REQ,
                expectedBehavior = "Power off should be rejected without proper authorization",
                vulnerabilityIndicator = "SIM power off accepted without authorization",
                severity = SapSeverity.HIGH,
                recommendation = "Require explicit user authorization for SIM power control",
            ),
            // 9. Reset SIM
            SapTestCase(
                name = "Reset SIM",
                category = SapTestCategory.SIM_RESET,
                apduCommand = null,
                sapMessage = SapMessageType.RESET_SIM_REQ,
                expectedBehavior = "Reset should be rejected without proper authorization",
                vulnerabilityIndicator = "SIM reset accepted without authorization",
                severity = SapSeverity.HIGH,
                recommendation = "Require explicit user authorization for SIM reset operations",
            ),
            // 10. Card reader status
            SapTestCase(
                name = "Card reader status",
                category = SapTestCategory.CARD_READER_STATUS,
                apduCommand = null,
                sapMessage = SapMessageType.TRANSFER_CARD_READER_STATUS_REQ,
                expectedBehavior = "Card reader status may be informational",
                vulnerabilityIndicator = "Card reader status reveals SIM presence information",
                severity = SapSeverity.LOW,
                recommendation = "Consider restricting card reader status to authenticated clients",
            ),
            // 11. Fuzz APDU with random bytes
            SapTestCase(
                name = "Fuzz APDU with random parameters",
                category = SapTestCategory.APDU_INJECTION,
                apduCommand = SimApdu(cla = 0xFF, ins = 0xFF, p1 = 0xFF, p2 = 0xFF, data = ByteArray(8) { it.toByte() }),
                sapMessage = SapMessageType.TRANSFER_APDU_REQ,
                expectedBehavior = "Invalid APDU should be rejected with appropriate error",
                vulnerabilityIndicator = "No proper APDU validation or error handling",
                severity = SapSeverity.MEDIUM,
                recommendation = "Implement robust APDU validation and error handling",
            ),
            // 12. Oversized APDU data
            SapTestCase(
                name = "Oversized APDU data",
                category = SapTestCategory.APDU_INJECTION,
                apduCommand = SimApdu(cla = 0x00, ins = 0xA4, p1 = 0x08, p2 = 0x04, data = ByteArray(255) { 0xAA.toByte() }),
                sapMessage = SapMessageType.TRANSFER_APDU_REQ,
                expectedBehavior = "Oversized APDU should be rejected",
                vulnerabilityIndicator = "No length validation on APDU data",
                severity = SapSeverity.MEDIUM,
                recommendation = "Implement APDU data length limits and validation",
            ),
            // 13. Malformed APDU (wrong CLA)
            SapTestCase(
                name = "Malformed APDU (invalid CLA byte)",
                category = SapTestCategory.APDU_INJECTION,
                apduCommand = SimApdu(cla = 0xEE, ins = 0xA4, p1 = 0x00, p2 = 0x00),
                sapMessage = SapMessageType.TRANSFER_APDU_REQ,
                expectedBehavior = "Invalid CLA should be rejected",
                vulnerabilityIndicator = "Invalid CLA byte accepted",
                severity = SapSeverity.LOW,
                recommendation = "Validate CLA byte against expected values",
            ),
            // 14. SELECT MF with wrong params
            SapTestCase(
                name = "SELECT MF with wrong parameters",
                category = SapTestCategory.APDU_INJECTION,
                apduCommand = SimApdu(cla = 0x00, ins = 0xA4, p1 = 0xDE, p2 = 0xAD, data = byteArrayOf(0x3F, 0x00)),
                sapMessage = SapMessageType.TRANSFER_APDU_REQ,
                expectedBehavior = "Invalid SELECT parameters should be rejected",
                vulnerabilityIndicator = "Invalid SELECT parameters accepted",
                severity = SapSeverity.LOW,
                recommendation = "Validate SELECT command parameters",
            ),
            // 15. Emergency call check
            SapTestCase(
                name = "Emergency call capability check",
                category = SapTestCategory.EMERGENCY_CALL,
                apduCommand = null,
                sapMessage = SapMessageType.CONNECT_REQ,
                expectedBehavior = "SAP should not allow emergency call bypass",
                vulnerabilityIndicator = "Emergency calls possible via SAP without authentication",
                severity = SapSeverity.HIGH,
                recommendation = "Ensure emergency call handling follows regulatory requirements",
            ),
        )

    /**
     * Parses a SIM APDU response and returns a human-readable description.
     * Response format: [data] SW1 SW2
     * Common status words: 90 00 = success, 6x xx = error, 61 xx = more data
     */
    fun parseSimResponse(response: ByteArray): String? {
        if (response.size < 2) return null

        val sw1 = response[response.size - 2].toInt() and 0xFF
        val sw2 = response[response.size - 1].toInt() and 0xFF
        val dataBytes = if (response.size > 2) response.copyOfRange(0, response.size - 2) else byteArrayOf()

        return when {
            sw1 == 0x90 && sw2 == 0x00 -> {
                if (dataBytes.isNotEmpty()) {
                    "Success (${dataBytes.size} bytes): ${dataBytes.toHexString()}"
                } else {
                    "Success (no data)"
                }
            }
            sw1 == 0x61 -> "More data available: $sw2 bytes remaining"
            sw1 == 0x6A ->
                when (sw2) {
                    0x82 -> "Error: File not found"
                    0x83 -> "Error: Record not found"
                    0x86 -> "Error: Incorrect P1/P2"
                    0x87 -> "Error: Lc inconsistent with P1/P2"
                    else -> "Error: Wrong parameters (6A%02X)".format(sw2)
                }
            sw1 == 0x6D -> "Error: Instruction not supported"
            sw1 == 0x6E -> "Error: Class not supported"
            sw1 == 0x69 ->
                when (sw2) {
                    0x82 -> "Error: Security status not satisfied"
                    0x83 -> "Error: Authentication method blocked"
                    0x85 -> "Error: Condition of use not satisfied"
                    else -> "Error: Command not allowed (69%02X)".format(sw2)
                }
            sw1 == 0x98 ->
                when (sw2) {
                    0x02 -> "Error: No CHV initialized"
                    0x04 -> "Error: Access condition not fulfilled"
                    else -> "Error: Security error (98%02X)".format(sw2)
                }
            sw1 == 0x62 -> "Warning: State non-volatile changed"
            sw1 == 0x63 ->
                when {
                    sw2 and 0xC0 == 0xC0 -> "Warning: Verification failed (%d tries remaining)".format(sw2 and 0x0F)
                    else -> "Warning: State changed (63%02X)".format(sw2)
                }
            else -> "Unknown response: %02X %02X".format(sw1, sw2)
        }
    }

    /**
     * Extracts IMSI from BCD-encoded EF_IMSI data.
     * Format: first byte is length, then MCC+MNC+MSIN in BCD encoding.
     */
    fun extractImsi(data: ByteArray): String? {
        if (data.isEmpty()) return null

        try {
            val length = data[0].toInt() and 0xFF
            if (length <= 0 || length > data.size - 1) return null

            val bcdData = data.copyOfRange(1, 1 + length)
            val sb = StringBuilder()

            for (i in bcdData.indices) {
                val byte = bcdData[i].toInt() and 0xFF
                val low = byte and 0x0F
                val high = (byte shr 4) and 0x0F

                // Skip first nibble (parity/type byte)
                if (i == 0) {
                    sb.append(low)
                    if (high != 0x0F) sb.append(high)
                } else {
                    if (low != 0x0F) sb.append(low)
                    if (high != 0x0F) sb.append(high)
                }
            }

            return sb.toString()
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Extracts ICCID from BCD-encoded EF_ICCID data.
     * ICCID is stored as BCD-encoded digits, swapped nibbles.
     */
    fun extractIccid(data: ByteArray): String? {
        if (data.isEmpty()) return null

        try {
            val sb = StringBuilder()
            for (byte in data) {
                val b = byte.toInt() and 0xFF
                val low = b and 0x0F
                val high = (b shr 4) and 0x0F

                // BCD: low nibble first, then high nibble
                if (low != 0x0F) sb.append(low)
                if (high != 0x0F) sb.append(high)
            }
            val result = sb.toString()
            return if (result.isNotEmpty()) result else null
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Analyzes a test case result against the actual response received.
     */
    fun analyzeResult(
        testCase: SapTestCase,
        response: String?,
    ): SapTestResult {
        val isVulnerable =
            when (testCase.category) {
                SapTestCategory.AUTHENTICATION_BYPASS ->
                    response != null && !response.contains("Error", ignoreCase = true) &&
                        !response.contains("rejected", ignoreCase = true)

                SapTestCategory.ATR_EXTRACTION ->
                    response != null && response.contains("Success", ignoreCase = true)

                SapTestCategory.SIM_DATA_READ ->
                    response != null && response.startsWith("Success", ignoreCase = true)

                SapTestCategory.SIM_POWER_CONTROL ->
                    response != null && !response.contains("Error", ignoreCase = true)

                SapTestCategory.SIM_RESET ->
                    response != null && !response.contains("Error", ignoreCase = true)

                SapTestCategory.CARD_READER_STATUS ->
                    response != null && !response.contains("Error", ignoreCase = true)

                SapTestCategory.APDU_INJECTION ->
                    response != null && !response.contains("Error", ignoreCase = true) &&
                        !response.contains("rejected", ignoreCase = true)

                SapTestCategory.CONNECTION_ACCESS ->
                    response != null && !response.contains("Error", ignoreCase = true)

                SapTestCategory.EMERGENCY_CALL ->
                    response != null && response.contains("Success", ignoreCase = true)

                SapTestCategory.DOS ->
                    response != null && !response.contains("Error", ignoreCase = true)
            }

        val confidence =
            when {
                response == null -> 0.0
                isVulnerable -> 0.9
                else -> 0.3
            }

        val evidence =
            when {
                response == null -> "No response received from device"
                isVulnerable -> "Vulnerability confirmed: ${testCase.vulnerabilityIndicator}. Response: $response"
                else -> "No vulnerability detected. Response: $response"
            }

        return SapTestResult(
            category = testCase.category,
            testName = testCase.name,
            apduCommand = testCase.apduCommand,
            sapMessage = testCase.sapMessage,
            response = response,
            vulnerable = isVulnerable,
            confidence = confidence,
            evidence = evidence,
            severity = testCase.severity,
            recommendation = testCase.recommendation,
        )
    }

    /**
     * Computes the overall risk severity based on all test results.
     */
    fun computeOverallRisk(results: List<SapTestResult>): SapSeverity {
        if (results.isEmpty()) return SapSeverity.INFO

        val hasCritical = results.any { it.vulnerable && it.severity == SapSeverity.CRITICAL }
        val hasHigh = results.any { it.vulnerable && it.severity == SapSeverity.HIGH }
        val hasMedium = results.any { it.vulnerable && it.severity == SapSeverity.MEDIUM }

        return when {
            hasCritical -> SapSeverity.CRITICAL
            hasHigh -> SapSeverity.HIGH
            hasMedium -> SapSeverity.MEDIUM
            results.any { it.vulnerable } -> SapSeverity.LOW
            else -> SapSeverity.INFO
        }
    }

    /**
     * Generates a human-readable security report from the test results.
     */
    fun generateReport(report: SapTestReport): String {
        val overallRisk = computeOverallRisk(report.results)
        val lines = mutableListOf<String>()

        lines.add("=== SAP Security Test Report ===")
        lines.add("Target Device: ${report.targetDevice}")
        lines.add("Test Duration: ${report.testDurationMs}ms")
        lines.add("Overall Risk: $overallRisk")
        lines.add("Critical Findings: ${report.criticalCount}")
        lines.add("High Findings: ${report.highCount}")
        lines.add("Total Tests: ${report.results.size}")
        lines.add("")

        // SIM data section
        report.simDataExtracted?.let { simData ->
            lines.add("--- Extracted SIM Data ---")
            simData.imsi?.let { lines.add("IMSI: $it") }
            simData.iccid?.let { lines.add("ICCID: $it") }
            simData.operatorName?.let { lines.add("Operator: $it") }
            simData.simType?.let { lines.add("SIM Type: $it") }
            simData.atr?.let { lines.add("ATR: $it") }
            if (simData.phoneNumbers.isNotEmpty()) {
                lines.add("Phone Numbers: ${simData.phoneNumbers.joinToString(", ")}")
            }
            lines.add("")
        }

        // Vulnerable findings
        val vulnerableResults = report.results.filter { it.vulnerable }
        if (vulnerableResults.isNotEmpty()) {
            lines.add("--- Vulnerable Tests ---")
            vulnerableResults.forEach { result ->
                lines.add("[${result.severity}] ${result.testName}")
                lines.add("  Category: ${result.category}")
                lines.add("  Evidence: ${result.evidence}")
                lines.add("  Recommendation: ${result.recommendation}")
                lines.add("")
            }
        }

        // All test results summary
        lines.add("--- All Test Results ---")
        report.results.forEach { result ->
            val status = if (result.vulnerable) "VULNERABLE" else "OK"
            lines.add("[${result.severity}] ${result.testName}: $status")
        }

        lines.add("")
        lines.add("=== AUTHORIZED security testing only ===")
        return lines.joinToString("\n")
    }

    private fun ByteArray.toHexString(): String = joinToString(" ") { "%02X".format(it) }
}
