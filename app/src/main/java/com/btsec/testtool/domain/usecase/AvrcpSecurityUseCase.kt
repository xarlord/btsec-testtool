/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.AvrcpSeverity
import com.btsec.testtool.domain.model.AvrcpTestCategory
import com.btsec.testtool.domain.model.AvrcpTestReport
import com.btsec.testtool.domain.model.AvrcpTestResult
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for AVRCP security testing.
 *
 * Provides a suite of predefined test cases for detecting unauthorized
 * media control, directory traversal, and other AVRCP vulnerabilities.
 *
 * All testing must be performed on AUTHORIZED devices with proper consent.
 */
@Singleton
class AvrcpSecurityUseCase
    @Inject
    constructor() {
        /**
         * Returns the full predefined test suite for AVRCP security testing.
         * Contains 20 test cases covering all major AVRCP attack surfaces.
         */
        fun getTestSuite(): List<AvrcpTestCase> =
            listOf(
                // 1. Media control tests
                AvrcpTestCase(
                    name = "Play command without auth",
                    category = AvrcpTestCategory.MEDIA_CONTROL,
                    command = "AVRCP_PRESS:PLAY",
                    expectedBehavior = "Device should reject play command without authorization",
                    vulnerabilityIndicator = "Command accepted and playback started",
                    severity = AvrcpSeverity.HIGH,
                    recommendation = "Require authentication before accepting media control commands",
                ),
                // 2
                AvrcpTestCase(
                    name = "Pause command without auth",
                    category = AvrcpTestCategory.MEDIA_CONTROL,
                    command = "AVRCP_PRESS:PAUSE",
                    expectedBehavior = "Device should reject pause command without authorization",
                    vulnerabilityIndicator = "Command accepted and playback paused",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Require authentication before accepting media control commands",
                ),
                // 3
                AvrcpTestCase(
                    name = "Skip next without auth",
                    category = AvrcpTestCategory.MEDIA_CONTROL,
                    command = "AVRCP_PRESS:FORWARD",
                    expectedBehavior = "Device should reject skip command without authorization",
                    vulnerabilityIndicator = "Command accepted and track skipped",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Require authentication for track navigation commands",
                ),
                // 4
                AvrcpTestCase(
                    name = "Skip previous without auth",
                    category = AvrcpTestCategory.MEDIA_CONTROL,
                    command = "AVRCP_PRESS:BACKWARD",
                    expectedBehavior = "Device should reject skip command without authorization",
                    vulnerabilityIndicator = "Command accepted and track changed",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Require authentication for track navigation commands",
                ),
                // 5
                AvrcpTestCase(
                    name = "Volume up without auth",
                    category = AvrcpTestCategory.VOLUME_MANIPULATION,
                    command = "AVRCP_PRESS:VOLUME_UP",
                    expectedBehavior = "Device should reject volume change without authorization",
                    vulnerabilityIndicator = "Volume changed without auth",
                    severity = AvrcpSeverity.LOW,
                    recommendation = "Implement volume change authorization",
                ),
                // 6
                AvrcpTestCase(
                    name = "Volume down without auth",
                    category = AvrcpTestCategory.VOLUME_MANIPULATION,
                    command = "AVRCP_PRESS:VOLUME_DOWN",
                    expectedBehavior = "Device should reject volume change without authorization",
                    vulnerabilityIndicator = "Volume changed without auth",
                    severity = AvrcpSeverity.LOW,
                    recommendation = "Implement volume change authorization",
                ),
                // 7. Browsing tests
                AvrcpTestCase(
                    name = "Browse root folder",
                    category = AvrcpTestCategory.BROWSING,
                    command = "BROWSE:GetFolderItems(uid=0)",
                    expectedBehavior = "Device should restrict browsing to authorized controllers",
                    vulnerabilityIndicator = "Root folder contents listed",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Implement browsing access control",
                ),
                // 8
                AvrcpTestCase(
                    name = "Browse deep path with ../",
                    category = AvrcpTestCategory.PATH_TRAVERSAL,
                    command = "BROWSE:ChangePath(uid=0, direction=UP, depth=10)",
                    expectedBehavior = "Device should prevent navigation beyond media root",
                    vulnerabilityIndicator = "Successfully navigated above media root",
                    severity = AvrcpSeverity.HIGH,
                    recommendation = "Validate and restrict directory navigation paths",
                ),
                // 9
                AvrcpTestCase(
                    name = "Get item attributes",
                    category = AvrcpTestCategory.METADATA_EXTRACTION,
                    command = "BROWSE:GetItemAttributes(uid=1)",
                    expectedBehavior = "Device should limit metadata exposure to authorized controllers",
                    vulnerabilityIndicator = "Full metadata returned without auth",
                    severity = AvrcpSeverity.LOW,
                    recommendation = "Restrict metadata access to authenticated controllers",
                ),
                // 10. Notification tests
                AvrcpTestCase(
                    name = "Register notification - playback status",
                    category = AvrcpTestCategory.NOTIFICATION_INJECTION,
                    command = "NOTIFY:Register(event=PLAYBACK_STATUS_CHANGED)",
                    expectedBehavior = "Device should limit notification registration",
                    vulnerabilityIndicator = "Notification registered without auth",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Require authorization for notification registration",
                ),
                // 11
                AvrcpTestCase(
                    name = "Register notification - now playing",
                    category = AvrcpTestCategory.NOTIFICATION_INJECTION,
                    command = "NOTIFY:Register(event=NOW_PLAYING_CHANGED)",
                    expectedBehavior = "Device should limit notification registration",
                    vulnerabilityIndicator = "Notification registered without auth",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Require authorization for notification registration",
                ),
                // 12
                AvrcpTestCase(
                    name = "Register notification - volume changed",
                    category = AvrcpTestCategory.NOTIFICATION_INJECTION,
                    command = "NOTIFY:Register(event=VOLUME_CHANGED)",
                    expectedBehavior = "Device should limit notification registration",
                    vulnerabilityIndicator = "Notification registered without auth",
                    severity = AvrcpSeverity.LOW,
                    recommendation = "Require authorization for notification registration",
                ),
                // 13. Vendor-specific fuzz
                AvrcpTestCase(
                    name = "Vendor-specific command fuzz",
                    category = AvrcpTestCategory.VENDOR_COMMAND_FUZZ,
                    command = "VENDOR:Send(0x00-0xFF random)",
                    expectedBehavior = "Device should reject unknown vendor commands",
                    vulnerabilityIndicator = "Unexpected response or crash",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Validate and reject unknown vendor-specific commands",
                ),
                // 14
                AvrcpTestCase(
                    name = "Get total number of items",
                    category = AvrcpTestCategory.BROWSING,
                    command = "BROWSE:GetTotalNumberOfItems(scope=1)",
                    expectedBehavior = "Device should restrict item count queries",
                    vulnerabilityIndicator = "Full item count returned without auth",
                    severity = AvrcpSeverity.LOW,
                    recommendation = "Restrict item count queries to authorized controllers",
                ),
                // 15. Path traversal
                AvrcpTestCase(
                    name = "ChangePath with ../",
                    category = AvrcpTestCategory.PATH_TRAVERSAL,
                    command = "BROWSE:ChangePath(path=\"../\")",
                    expectedBehavior = "Device should reject parent directory navigation",
                    vulnerabilityIndicator = "Parent directory accessed successfully",
                    severity = AvrcpSeverity.HIGH,
                    recommendation = "Validate ChangePath input to prevent directory traversal",
                ),
                // 16
                AvrcpTestCase(
                    name = "ChangePath with /",
                    category = AvrcpTestCategory.PATH_TRAVERSAL,
                    command = "BROWSE:ChangePath(path=\"/\")",
                    expectedBehavior = "Device should reject absolute path navigation",
                    vulnerabilityIndicator = "Root filesystem accessed via absolute path",
                    severity = AvrcpSeverity.HIGH,
                    recommendation = "Reject absolute paths in ChangePath commands",
                ),
                // 17
                AvrcpTestCase(
                    name = "Search with SQL-like injection",
                    category = AvrcpTestCategory.BROWSING,
                    command = "BROWSE:Search(query=\"'; DROP TABLE media; --\")",
                    expectedBehavior = "Device should sanitize search input",
                    vulnerabilityIndicator = "Unexpected behavior or error indicating injection",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Sanitize all search input to prevent injection attacks",
                ),
                // 18
                AvrcpTestCase(
                    name = "Get play status",
                    category = AvrcpTestCategory.MEDIA_CONTROL,
                    command = "AVRCP:GetPlayStatus",
                    expectedBehavior = "Device should limit status queries to authorized controllers",
                    vulnerabilityIndicator = "Play status returned without auth",
                    severity = AvrcpSeverity.LOW,
                    recommendation = "Restrict status queries to authenticated controllers",
                ),
                // 19
                AvrcpTestCase(
                    name = "Set addressed player",
                    category = AvrcpTestCategory.MEDIA_CONTROL,
                    command = "AVRCP:SetAddressedPlayer(id=1)",
                    expectedBehavior = "Device should require auth to change active player",
                    vulnerabilityIndicator = "Player changed without authorization",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Require authorization to change addressed player",
                ),
                // 20
                AvrcpTestCase(
                    name = "Set browsed player",
                    category = AvrcpTestCategory.BROWSING,
                    command = "BROWSE:SetBrowsedPlayer(id=1)",
                    expectedBehavior = "Device should require auth to change browsed player",
                    vulnerabilityIndicator = "Browsed player changed without authorization",
                    severity = AvrcpSeverity.MEDIUM,
                    recommendation = "Require authorization to change browsed player",
                ),
            )

        /**
         * Analyze a test response and determine if the test case indicates a vulnerability.
         *
         * @param testCase The test case that was executed
         * @param response The raw response from the device (null if no response received)
         * @return An [AvrcpTestResult] with vulnerability assessment
         */
        fun analyzeResponse(
            testCase: AvrcpTestCase,
            response: String?,
        ): AvrcpTestResult {
            val vulnerable: Boolean
            val confidence: Double
            val evidence: String

            if (response == null) {
                vulnerable = false
                confidence = 0.9
                evidence = "No response received — command likely rejected or ignored"
            } else if (containsErrorResponse(response)) {
                vulnerable = false
                confidence = 0.95
                evidence = "Error response received: $response"
            } else if (isSuccessResponse(response)) {
                vulnerable = true
                confidence = 0.85
                evidence = "Success response: $response — ${testCase.vulnerabilityIndicator}"
            } else if (testCase.category == AvrcpTestCategory.PATH_TRAVERSAL &&
                detectPathTraversalIndicators(response)
            ) {
                vulnerable = true
                confidence = 0.9
                evidence = "Path traversal indicators found in response: $response"
            } else {
                vulnerable = true
                confidence = 0.4
                evidence = "Ambiguous response received: $response"
            }

            return AvrcpTestResult(
                category = testCase.category,
                testName = testCase.name,
                command = testCase.command,
                response = response,
                vulnerable = vulnerable,
                confidence = confidence,
                evidence = evidence,
                severity = testCase.severity,
                recommendation = testCase.recommendation,
            )
        }

        /**
         * Compute the overall risk severity from a list of test results.
         * Returns the highest severity found among vulnerable results.
         */
        fun computeOverallRisk(results: List<AvrcpTestResult>): AvrcpSeverity {
            if (results.isEmpty()) return AvrcpSeverity.INFO

            val vulnerableResults = results.filter { it.vulnerable }
            if (vulnerableResults.isEmpty()) return AvrcpSeverity.INFO

            return vulnerableResults.minOf { it.severity }
        }

        /**
         * Detect path traversal patterns in a given path string.
         *
         * Checks for: ../, ..\, null bytes, URL-encoded sequences (%2e%2e, %2f, %5c)
         *
         * @param path The path to check
         * @return true if path traversal patterns are detected
         */
        fun detectPathTraversal(path: String): Boolean {
            val normalized = path.lowercase()
            return normalized.contains("../") ||
                normalized.contains("..\\") ||
                normalized.contains("..%2f") ||
                normalized.contains("..%5c") ||
                normalized.contains("%2e%2e") ||
                normalized.contains("%00") ||
                path.contains('\u0000')
        }

        /**
         * Generate a human-readable report from test results.
         *
         * @param report The [AvrcpTestReport] to format
         * @return A formatted string report
         */
        fun generateReport(report: AvrcpTestReport): String =
            buildString {
                appendLine("=== AVRCP Security Test Report ===")
                appendLine("Target Device: ${report.targetDevice}")
                appendLine("Test Duration: ${report.testDurationMs}ms")
                appendLine("Media Items Extracted: ${report.mediaItemsExtracted}")
                appendLine()

                appendLine("--- Summary ---")
                appendLine("Total Tests: ${report.results.size}")
                appendLine("Critical Findings: ${report.criticalCount}")
                appendLine("High Findings: ${report.highCount}")
                val vulnCount = report.results.count { it.vulnerable }
                appendLine("Vulnerable Tests: $vulnCount")
                appendLine("Overall Risk: ${computeOverallRisk(report.results)}")
                appendLine()

                if (report.results.isNotEmpty()) {
                    appendLine("--- Findings ---")
                    report.results.forEachIndexed { idx, r ->
                        appendLine("  [${idx + 1}] ${r.testName}")
                        appendLine("      Category: ${r.category}")
                        appendLine("      Command: ${r.command}")
                        appendLine("      Vulnerable: ${r.vulnerable}")
                        appendLine("      Severity: ${r.severity}")
                        appendLine("      Confidence: ${"%.2f".format(r.confidence)}")
                        appendLine("      Evidence: ${r.evidence}")
                        appendLine("      Recommendation: ${r.recommendation}")
                        appendLine()
                    }
                }

                if (report.browseResults.isNotEmpty()) {
                    appendLine("--- Browse Results ---")
                    report.browseResults.forEach { b ->
                        appendLine("  Path: ${b.path}")
                        appendLine("  Depth: ${b.depth}, Items Found: ${b.itemsFound}")
                        appendLine("  Traversal Successful: ${b.traversalSuccessful}")
                        if (b.sensitivePaths.isNotEmpty()) {
                            appendLine("  Sensitive Paths: ${b.sensitivePaths.joinToString(", ")}")
                        }
                        appendLine()
                    }
                }

                appendLine("=== End of Report ===")
            }

        // ── Internal helpers ──

        private fun containsErrorResponse(response: String): Boolean {
            val indicators =
                listOf(
                    "error", "rejected", "denied", "unauthorized",
                    "not permitted", "forbidden", "invalid", "failed", "not supported",
                )
            val lower = response.lowercase()
            return indicators.any { lower.contains(it) }
        }

        private fun isSuccessResponse(response: String): Boolean {
            val indicators =
                listOf(
                    "ok",
                    "success",
                    "accepted",
                    "completed",
                    "acknowledged",
                    "done",
                )
            val lower = response.lowercase()
            return indicators.any { lower.contains(it) }
        }

        private fun detectPathTraversalIndicators(response: String): Boolean {
            val indicators =
                listOf(
                    "/etc/",
                    "/sys/",
                    "/proc/",
                    "/data/",
                    "/system/",
                    "passwd",
                    "shadow",
                )
            val lower = response.lowercase()
            return indicators.any { lower.contains(it) }
        }
    }

/**
 * A single predefined AVRCP security test case.
 */
data class AvrcpTestCase(
    val name: String,
    val category: AvrcpTestCategory,
    val command: String,
    val expectedBehavior: String,
    val vulnerabilityIndicator: String,
    val severity: AvrcpSeverity,
    val recommendation: String,
)
