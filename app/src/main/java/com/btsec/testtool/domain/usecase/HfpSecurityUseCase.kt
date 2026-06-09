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
import javax.inject.Inject
import javax.inject.Singleton

/**
 * A single predefined HFP security test case.
 */
data class HfpTestCase(
    val name: String,
    val category: HfpTestCategory,
    val command: String,
    val expectedBehavior: String,
    val vulnerabilityIndicator: String,
    val severity: HfpSeverity,
    val recommendation: String
)

/**
 * Use case for HFP (Hands-Free Profile) security testing.
 *
 * Provides a comprehensive test suite for AT command injection,
 * call manipulation, format string attacks, buffer overflow testing,
 * information disclosure, and authentication bypass detection.
 *
 * All testing operations MUST be performed with explicit AUTHORIZED consent.
 */
@Singleton
class HfpSecurityUseCase @Inject constructor() {

    /**
     * Returns the full list of HFP security test cases to run.
     */
    fun getTestSuite(): List<HfpTestCase> = predefinedTestCases

    /**
     * Analyze a response from an AT command and determine if a vulnerability exists.
     *
     * @param testCase The test case that was executed
     * @param response The raw response from the device (null if no response)
     * @return An [HfpTestResult] with vulnerability assessment
     */
    fun analyzeResponse(testCase: HfpTestCase, response: String?): HfpTestResult {
        val vulnerable = detectVulnerability(testCase, response)
        val confidence = computeConfidence(testCase, response, vulnerable)
        val evidence = buildEvidence(testCase, response, vulnerable)

        return HfpTestResult(
            category = testCase.category,
            testName = testCase.name,
            command = testCase.command,
            response = response,
            vulnerable = vulnerable,
            confidence = confidence,
            evidence = evidence,
            severity = testCase.severity,
            recommendation = testCase.recommendation
        )
    }

    /**
     * Compute the overall risk from a list of test results.
     *
     * Aggregation: if any CRITICAL → CRITICAL, else if any HIGH → HIGH, etc.
     * Empty results return INFO.
     */
    fun computeOverallRisk(results: List<HfpTestResult>): HfpSeverity {
        if (results.isEmpty()) return HfpSeverity.INFO

        val severities = results.filter { it.vulnerable }.map { it.severity }.toSet()

        return when {
            HfpSeverity.CRITICAL in severities -> HfpSeverity.CRITICAL
            HfpSeverity.HIGH in severities -> HfpSeverity.HIGH
            HfpSeverity.MEDIUM in severities -> HfpSeverity.MEDIUM
            HfpSeverity.LOW in severities -> HfpSeverity.LOW
            else -> HfpSeverity.INFO
        }
    }

    /**
     * Generate a text report from a completed test suite.
     */
    fun generateReport(suite: HfpTestSuite): String {
        val sb = StringBuilder()
        sb.appendLine("═".repeat(60))
        sb.appendLine("  HFP Security Test Report")
        sb.appendLine("═".repeat(60))
        sb.appendLine()
        sb.appendLine("Device: ${suite.deviceName ?: "Unknown"}")
        sb.appendLine("Address: ${suite.deviceAddress}")
        sb.appendLine("Test Duration: ${suite.testDurationMs}ms")
        sb.appendLine()
        sb.appendLine("── Summary ──")
        sb.appendLine("Overall Risk: ${suite.overallRisk}")
        sb.appendLine("Critical: ${suite.criticalCount}")
        sb.appendLine("High: ${suite.highCount}")
        sb.appendLine("Medium: ${suite.mediumCount}")
        sb.appendLine("Low: ${suite.lowCount}")
        sb.appendLine("Info: ${suite.infoCount}")
        sb.appendLine()

        val vulnerableResults = suite.results.filter { it.vulnerable }
        if (vulnerableResults.isNotEmpty()) {
            sb.appendLine("── Vulnerable Findings ──")
            vulnerableResults.forEach { result ->
                sb.appendLine()
                sb.appendLine("  [${result.severity}] ${result.testName}")
                sb.appendLine("  Category: ${result.category}")
                sb.appendLine("  Command: ${result.command}")
                sb.appendLine("  Evidence: ${result.evidence}")
                sb.appendLine("  Confidence: ${(result.confidence * 100).toInt()}%")
                sb.appendLine("  Recommendation: ${result.recommendation}")
            }
            sb.appendLine()
        }

        val allFindings = suite.results
        sb.appendLine("── All Test Results (${allFindings.size} tests) ──")
        allFindings.forEach { result ->
            val status = if (result.vulnerable) "VULNERABLE" else "SAFE"
            sb.appendLine("  [$status] ${result.testName} (${result.severity})")
        }

        sb.appendLine()
        sb.appendLine("═".repeat(60))
        sb.appendLine("  End of Report")
        sb.appendLine("═".repeat(60))
        return sb.toString()
    }

    // ── Private helpers ──

    private fun detectVulnerability(testCase: HfpTestCase, response: String?): Boolean {
        if (response.isNullOrBlank()) return false

        val trimmed = response.trim().uppercase()

        return when (testCase.category) {
            HfpTestCategory.CALL_MANIPULATION -> {
                trimmed.contains("OK") || trimmed.contains("CONNECT")
            }

            HfpTestCategory.FORMAT_STRING -> {
                // Format string leak: hex values, unexpected data, or no error
                val hexPattern = Regex("0x[0-9A-F]+")
                val hasHexLeak = hexPattern.containsMatchIn(trimmed)
                val hasUnexpectedData = !trimmed.contains("ERROR") &&
                        !trimmed.contains("NO CARRIER") &&
                        trimmed.length > 4
                hasHexLeak || hasUnexpectedData
            }

            HfpTestCategory.BUFFER_OVERFLOW -> {
                // If device didn't return an error to oversized input, it's vulnerable
                !trimmed.contains("ERROR") && !trimmed.contains("NO CARRIER")
            }

            HfpTestCategory.INFORMATION_DISCLOSURE -> {
                // If device returned info (not just OK/ERROR), data leaked
                trimmed.isNotEmpty() &&
                        !trimmed.equals("OK", ignoreCase = true) &&
                        !trimmed.equals("ERROR", ignoreCase = true)
            }

            HfpTestCategory.PHONEBOOK_ACCESS -> {
                // +CPBR or contact data in response
                trimmed.contains("+CPBR") ||
                        trimmed.contains("+CPBF") ||
                        (!trimmed.contains("ERROR") && trimmed.length > 10)
            }

            HfpTestCategory.SMS_ACCESS -> {
                // +CMGL, +CMGR in response or OK for CMGF
                trimmed.contains("+CMGL") ||
                        trimmed.contains("+CMGR") ||
                        trimmed.contains("OK")
            }

            HfpTestCategory.INJECTION -> {
                // Multiple OK responses indicate command chaining worked
                val okCount = trimmed.split("OK").size - 1
                okCount > 1 || (!trimmed.contains("ERROR") && trimmed.contains(";"))
            }

            HfpTestCategory.AUTHENTICATION_BYPASS -> {
                // Connected without pairing
                trimmed.contains("CONNECT") || trimmed.contains("OK")
            }

            HfpTestCategory.DOS -> {
                !trimmed.contains("ERROR")
            }

            HfpTestCategory.AUDIO_ROUTING -> {
                trimmed.contains("OK") || trimmed.contains("+BVRA")
            }
        }
    }

    private fun computeConfidence(
        testCase: HfpTestCase,
        response: String?,
        vulnerable: Boolean
    ): Double {
        if (!vulnerable) return 0.0
        if (response.isNullOrBlank()) return 0.0

        val trimmed = response.trim()
        var confidence = 0.5

        // Higher confidence for definitive indicators
        when (testCase.category) {
            HfpTestCategory.FORMAT_STRING -> {
                if (Regex("0x[0-9A-F]+").containsMatchIn(trimmed)) confidence = 0.95
                else if (!trimmed.contains("ERROR", ignoreCase = true)) confidence = 0.7
            }

            HfpTestCategory.CALL_MANIPULATION -> {
                if (trimmed.contains("OK", ignoreCase = true)) confidence = 0.85
            }

            HfpTestCategory.PHONEBOOK_ACCESS -> {
                if (trimmed.contains("+CPBR") || trimmed.contains("+CPBF")) confidence = 0.95
            }

            HfpTestCategory.SMS_ACCESS -> {
                if (trimmed.contains("+CMGL") || trimmed.contains("+CMGR")) confidence = 0.95
                else if (trimmed.contains("OK", ignoreCase = true)) confidence = 0.7
            }

            HfpTestCategory.INJECTION -> {
                val okCount = trimmed.split("OK").size - 1
                if (okCount > 1) confidence = 0.9
            }

            HfpTestCategory.BUFFER_OVERFLOW -> {
                if (!trimmed.contains("ERROR", ignoreCase = true)) confidence = 0.75
            }

            HfpTestCategory.AUTHENTICATION_BYPASS -> {
                if (trimmed.contains("CONNECT", ignoreCase = true)) confidence = 0.9
            }

            else -> {
                confidence = 0.7
            }
        }

        return confidence.coerceIn(0.0, 1.0)
    }

    private fun buildEvidence(
        testCase: HfpTestCase,
        response: String?,
        vulnerable: Boolean
    ): String {
        if (!vulnerable) {
            return "No vulnerability detected. Device responded appropriately."
        }
        if (response.isNullOrBlank()) {
            return "No response received."
        }
        return "Command '${testCase.command}' elicited response: ${response.take(200)}. " +
                testCase.vulnerabilityIndicator
    }

    companion object {
        private val predefinedTestCases: List<HfpTestCase> = listOf(

            // ── Call Manipulation ──
            HfpTestCase(
                name = "Call Origination",
                category = HfpTestCategory.CALL_MANIPULATION,
                command = "ATD+1234567890;",
                expectedBehavior = "Device should reject call origination from untrusted source",
                vulnerabilityIndicator = "Call was originated successfully",
                severity = HfpSeverity.CRITICAL,
                recommendation = "Require explicit user confirmation before originating calls"
            ),
            HfpTestCase(
                name = "Call Answer",
                category = HfpTestCategory.CALL_MANIPULATION,
                command = "ATA",
                expectedBehavior = "Device should reject answering calls from untrusted source",
                vulnerabilityIndicator = "Call was answered successfully",
                severity = HfpSeverity.HIGH,
                recommendation = "Require user interaction before answering incoming calls"
            ),
            HfpTestCase(
                name = "Call Hangup",
                category = HfpTestCategory.CALL_MANIPULATION,
                command = "ATH",
                expectedBehavior = "Device should restrict hangup to authorized endpoints",
                vulnerabilityIndicator = "Call was terminated successfully",
                severity = HfpSeverity.MEDIUM,
                recommendation = "Restrict call termination to paired devices only"
            ),
            HfpTestCase(
                name = "Call Reject",
                category = HfpTestCategory.CALL_MANIPULATION,
                command = "AT+CHUP",
                expectedBehavior = "Device should reject call reject command from untrusted source",
                vulnerabilityIndicator = "Call was rejected successfully",
                severity = HfpSeverity.MEDIUM,
                recommendation = "Restrict call rejection to authorized devices"
            ),
            HfpTestCase(
                name = "List Current Calls",
                category = HfpTestCategory.CALL_MANIPULATION,
                command = "AT+CLCC",
                expectedBehavior = "Device should not disclose call information to untrusted sources",
                vulnerabilityIndicator = "Call list was returned in +CLCC response",
                severity = HfpSeverity.MEDIUM,
                recommendation = "Restrict call status queries to paired devices"
            ),

            // ── Format String ──
            HfpTestCase(
                name = "Format String %x Leak",
                category = HfpTestCategory.FORMAT_STRING,
                command = "AT%x.%x.%x",
                expectedBehavior = "Device should return ERROR for invalid commands",
                vulnerabilityIndicator = "Hex values leaked in response (memory disclosure)",
                severity = HfpSeverity.CRITICAL,
                recommendation = "Sanitize all AT command inputs; reject format specifiers"
            ),
            HfpTestCase(
                name = "Format String %s Crash",
                category = HfpTestCategory.FORMAT_STRING,
                command = "AT%s%s%s%s",
                expectedBehavior = "Device should return ERROR for invalid commands",
                vulnerabilityIndicator = "Crash or unexpected data returned",
                severity = HfpSeverity.CRITICAL,
                recommendation = "Implement strict input validation for AT command parsing"
            ),
            HfpTestCase(
                name = "Format String %n Write",
                category = HfpTestCategory.FORMAT_STRING,
                command = "AT%n",
                expectedBehavior = "Device should return ERROR for invalid commands",
                vulnerabilityIndicator = "No error returned (potential memory write)",
                severity = HfpSeverity.CRITICAL,
                recommendation = "Block format string specifiers in AT command parser"
            ),

            // ── Buffer Overflow ──
            HfpTestCase(
                name = "Buffer Overflow 4KB",
                category = HfpTestCategory.BUFFER_OVERFLOW,
                command = "AT" + "A".repeat(4096),
                expectedBehavior = "Device should reject oversized commands with ERROR",
                vulnerabilityIndicator = "No error returned or device reconnected without reset",
                severity = HfpSeverity.HIGH,
                recommendation = "Enforce maximum command length in AT parser"
            ),
            HfpTestCase(
                name = "Phone Number Overflow",
                category = HfpTestCategory.BUFFER_OVERFLOW,
                command = "ATD" + "0".repeat(256) + ";",
                expectedBehavior = "Device should reject oversized phone numbers",
                vulnerabilityIndicator = "No error returned for oversized dial string",
                severity = HfpSeverity.HIGH,
                recommendation = "Validate phone number length before processing ATD command"
            ),

            // ── Information Disclosure ──
            HfpTestCase(
                name = "Device Info Leak (ATI)",
                category = HfpTestCategory.INFORMATION_DISCLOSURE,
                command = "ATI",
                expectedBehavior = "Device should not disclose detailed manufacturer info",
                vulnerabilityIndicator = "Manufacturer info returned in response",
                severity = HfpSeverity.LOW,
                recommendation = "Limit device identification information exposure"
            ),
            HfpTestCase(
                name = "Manufacturer Identification",
                category = HfpTestCategory.INFORMATION_DISCLOSURE,
                command = "AT+GMI",
                expectedBehavior = "Device should limit manufacturer information",
                vulnerabilityIndicator = "Manufacturer name returned in response",
                severity = HfpSeverity.LOW,
                recommendation = "Restrict manufacturer identification to paired devices"
            ),
            HfpTestCase(
                name = "Model Identification",
                category = HfpTestCategory.INFORMATION_DISCLOSURE,
                command = "AT+GMM",
                expectedBehavior = "Device should limit model information",
                vulnerabilityIndicator = "Model name returned in response",
                severity = HfpSeverity.LOW,
                recommendation = "Restrict model identification to paired devices"
            ),
            HfpTestCase(
                name = "Battery Level Query",
                category = HfpTestCategory.INFORMATION_DISCLOSURE,
                command = "AT+CBC",
                expectedBehavior = "Battery info should only be available to paired devices",
                vulnerabilityIndicator = "Battery level returned in response",
                severity = HfpSeverity.INFO,
                recommendation = "Restrict battery status to authenticated connections"
            ),
            HfpTestCase(
                name = "Signal Quality Query",
                category = HfpTestCategory.INFORMATION_DISCLOSURE,
                command = "AT+CSQ",
                expectedBehavior = "Signal info should only be available to paired devices",
                vulnerabilityIndicator = "Signal quality returned in response",
                severity = HfpSeverity.INFO,
                recommendation = "Restrict signal quality to authenticated connections"
            ),
            HfpTestCase(
                name = "Network Operator Query",
                category = HfpTestCategory.INFORMATION_DISCLOSURE,
                command = "AT+COPS?",
                expectedBehavior = "Network operator should only be disclosed to paired devices",
                vulnerabilityIndicator = "Operator name returned in response",
                severity = HfpSeverity.INFO,
                recommendation = "Restrict network operator disclosure to authenticated connections"
            ),

            // ── Phonebook Access ──
            HfpTestCase(
                name = "Phonebook Read Entry",
                category = HfpTestCategory.PHONEBOOK_ACCESS,
                command = "AT+CPBR=1",
                expectedBehavior = "Device should reject phonebook access from untrusted source",
                vulnerabilityIndicator = "Contact data returned in +CPBR response",
                severity = HfpSeverity.CRITICAL,
                recommendation = "Require pairing and user consent for phonebook access"
            ),
            HfpTestCase(
                name = "Phonebook Find",
                category = HfpTestCategory.PHONEBOOK_ACCESS,
                command = "AT+CPBF=\"\"",
                expectedBehavior = "Device should reject phonebook search from untrusted source",
                vulnerabilityIndicator = "Contacts found and returned in response",
                severity = HfpSeverity.CRITICAL,
                recommendation = "Require pairing and user consent for phonebook searches"
            ),

            // ── SMS Access ──
            HfpTestCase(
                name = "SMS Format Set",
                category = HfpTestCategory.SMS_ACCESS,
                command = "AT+CMGF=1",
                expectedBehavior = "Device should reject SMS configuration from untrusted source",
                vulnerabilityIndicator = "SMS text mode enabled (OK response)",
                severity = HfpSeverity.HIGH,
                recommendation = "Restrict SMS configuration to paired devices only"
            ),
            HfpTestCase(
                name = "SMS List All",
                category = HfpTestCategory.SMS_ACCESS,
                command = "AT+CMGL=\"ALL\"",
                expectedBehavior = "Device should reject SMS listing from untrusted source",
                vulnerabilityIndicator = "SMS messages returned in +CMGL response",
                severity = HfpSeverity.CRITICAL,
                recommendation = "Require explicit user consent for SMS access"
            ),

            // ── Injection ──
            HfpTestCase(
                name = "Command Chain Injection",
                category = HfpTestCategory.INJECTION,
                command = "ATD;+CMGF=1",
                expectedBehavior = "Device should reject chained commands",
                vulnerabilityIndicator = "Multiple commands executed (multiple OK responses)",
                severity = HfpSeverity.HIGH,
                recommendation = "Reject semicolon-separated command chains in AT parser"
            ),

            // ── More Injection / DOS ──
            HfpTestCase(
                name = "Null Byte Injection",
                category = HfpTestCategory.INJECTION,
                command = "AT\u0000D",
                expectedBehavior = "Device should reject commands with null bytes",
                vulnerabilityIndicator = "Unexpected behavior or crash from null byte",
                severity = HfpSeverity.MEDIUM,
                recommendation = "Strip null bytes from AT command input"
            ),

            // ── Buffer Overflow (extended) ──
            HfpTestCase(
                name = "Long AT Command 64KB",
                category = HfpTestCategory.BUFFER_OVERFLOW,
                command = "AT" + "A".repeat(65536),
                expectedBehavior = "Device should reject oversized commands with ERROR",
                vulnerabilityIndicator = "No error handling for oversized command",
                severity = HfpSeverity.HIGH,
                recommendation = "Enforce strict maximum input length with graceful error handling"
            ),

            // ── Authentication Bypass ──
            HfpTestCase(
                name = "HFP Auth Bypass (No Pairing)",
                category = HfpTestCategory.AUTHENTICATION_BYPASS,
                command = "CONNECT_HFP_UUID_WITHOUT_PAIRING",
                expectedBehavior = "Device should reject HFP connection without pairing",
                vulnerabilityIndicator = "Connected to HFP without authentication",
                severity = HfpSeverity.CRITICAL,
                recommendation = "Require pairing before accepting HFP connections"
            ),

            // ── Audio Routing ──
            HfpTestCase(
                name = "Audio Routing Without Consent",
                category = HfpTestCategory.AUDIO_ROUTING,
                command = "AT+BVRA=1",
                expectedBehavior = "Device should require user consent for audio routing",
                vulnerabilityIndicator = "Audio routed without explicit user consent",
                severity = HfpSeverity.HIGH,
                recommendation = "Require user confirmation before routing audio to HFP device"
            ),

            // ── Denial of Service ──
            HfpTestCase(
                name = "Call Flood DOS",
                category = HfpTestCategory.DOS,
                command = "ATD+1234567890;",
                expectedBehavior = "Device should rate-limit call origination attempts",
                vulnerabilityIndicator = "Device allows repeated call origination without rate limit",
                severity = HfpSeverity.HIGH,
                recommendation = "Implement rate limiting for call origination commands"
            )
        )
    }
}
