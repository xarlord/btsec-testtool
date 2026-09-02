/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.report

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.ReportConfig
import com.btsec.testtool.domain.repository.VulnerabilityTestResult
import java.time.Instant
import java.time.temporal.ChronoUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Generates security reports from test results.
 */
@Singleton
class ReportGenerator
    @Inject
    constructor() {
        /**
         * Generate a full security report from test results.
         */
        fun generateReport(
            authId: String,
            config: ReportConfig,
            targetDevices: List<BluetoothDevice>,
            vulnerabilityResults: List<VulnerabilityTestResult>,
            fuzzingResults: List<FuzzResult>,
            keyExtractionResults: List<KeyExtractionResult>,
            evidenceLedger: List<EvidenceLedgerEntry> = emptyList(),
        ): SecurityReport {
            val now = Instant.now()

            // Build findings — group by category+severity
            val findings =
                vulnerabilityResults
                    .filter { it.outcome == EvidenceOutcome.VULNERABLE }
                    .groupBy { Pair(mapCategory(it.vulnerability.category), it.vulnerability.severity) }
                    .map { (catSev, results) ->
                        ReportFinding(
                            category = catSev.first,
                            severity = catSev.second,
                            count = results.size,
                            description = results.map { it.vulnerability.name }.distinct().joinToString(", "),
                            affectedDevices = targetDevices.map { it.address },
                        )
                    }

            // Build recommendations from detected vulnerabilities
            val recommendations =
                vulnerabilityResults
                    .filter { it.outcome == EvidenceOutcome.VULNERABLE }
                    .sortedByDescending { it.vulnerability.cvssScore }
                    .map { result ->
                        Recommendation(
                            priority = mapPriority(result.vulnerability.severity),
                            title = "Remediate ${result.vulnerability.name}",
                            description = result.vulnerability.description,
                            affectedDevices = targetDevices.map { it.address },
                            implementation = result.vulnerability.mitigation,
                            verification = "Re-scan after applying fix to confirm vulnerability is resolved.",
                        )
                    }
                    .distinctBy { it.title }

            // Build executive summary
            val detectedCount = vulnerabilityResults.count { it.outcome == EvidenceOutcome.VULNERABLE }
            val unresolvedResults =
                vulnerabilityResults.filter {
                    it.outcome in
                        setOf(
                            EvidenceOutcome.INCONCLUSIVE,
                            EvidenceOutcome.UNSUPPORTED,
                            EvidenceOutcome.ERROR,
                            EvidenceOutcome.CANCELLED,
                        )
                }
            val totalScanned = vulnerabilityResults.size
            val criticalCount =
                vulnerabilityResults.count {
                    it.outcome == EvidenceOutcome.VULNERABLE && it.vulnerability.severity == VulnerabilitySeverity.CRITICAL
                }
            val highCount =
                vulnerabilityResults.count {
                    it.outcome == EvidenceOutcome.VULNERABLE && it.vulnerability.severity == VulnerabilitySeverity.HIGH
                }

            val executiveSummary =
                buildString {
                    appendLine("Bluetooth Security Assessment Report")
                    appendLine("Generated: $now")
                    appendLine("Target devices: ${targetDevices.size}")
                    appendLine("Vulnerabilities scanned: $totalScanned")
                    appendLine("Vulnerabilities detected: $detectedCount")
                    if (criticalCount > 0) appendLine("⚠️ Critical: $criticalCount")
                    if (highCount > 0) appendLine("🔴 High: $highCount")
                    appendLine()
                    appendLine("Fuzzing sessions: ${fuzzingResults.size}")
                    appendLine("Key extraction attempts: ${keyExtractionResults.size}")
                    if (unresolvedResults.isNotEmpty() || totalScanned == 0) {
                        val unresolvedOutcomes = unresolvedResults.groupingBy { it.outcome }.eachCount()
                        appendLine("This is not a clean conclusion: ${if (totalScanned == 0) "no persisted scan records" else "${unresolvedResults.size} checks are unresolved"}.")
                        if (unresolvedOutcomes.isNotEmpty()) appendLine("Unresolved outcomes: $unresolvedOutcomes")
                    } else if (detectedCount == 0) {
                        appendLine("No vulnerabilities detected by the supported checks. Continue monitoring.")
                    } else {
                        appendLine("IMMEDIATE ACTION REQUIRED: $detectedCount vulnerabilities need remediation.")
                    }
                }

            // Build appendix
            val appendix =
                ReportAppendix(
                    toolsUsed = listOf("BTSec TestTool v1.2.1", "BLE Fuzzing Engine", "Vulnerability Scanner"),
                    testMethodology = "Automated scanning using CVE-specific test vectors, BLE packet fuzzing, and key extraction analysis.",
                    limitations =
                        buildList {
                            add("Tests performed from Android device perspective only")
                            add("Some vulnerabilities require specific hardware/firmware to exploit")
                            add("Results represent point-in-time assessment")
                            if (totalScanned == 0) add("No persisted vulnerability scan records were available")
                            unresolvedResults.forEach { result ->
                                add("${result.vulnerability.cveId}: ${result.outcome} — ${result.limitation ?: result.details}")
                                result.capabilityBoundary?.let { boundary -> add("${result.vulnerability.cveId} capability boundary: $boundary") }
                            }
                            evidenceLedger.filter { it.outcome != EvidenceOutcome.VULNERABLE && it.outcome != EvidenceOutcome.NOT_VULNERABLE }
                                .forEach { entry -> add("${entry.definitionId}: ${entry.outcome} — ${entry.limitation}") }
                        },
                    glossary =
                        mapOf(
                            "CVSS" to "Common Vulnerability Scoring System",
                            "CVE" to "Common Vulnerabilities and Exposures",
                            "BLE" to "Bluetooth Low Energy",
                            "GATT" to "Generic Attribute Profile",
                            "SMP" to "Security Manager Protocol",
                            "CTKD" to "Cross-Transport Key Derivation",
                        ),
                    references = vulnerabilityResults.flatMap { it.vulnerability.references }.distinct(),
                )

            // Map detected vulnerabilities to domain Vulnerability objects
            val vulnerabilities =
                vulnerabilityResults.filter { it.outcome == EvidenceOutcome.VULNERABLE }.map { result ->
                    val def = result.vulnerability
                    Vulnerability(
                        id = "vuln-${def.cveId}",
                        cveId = def.cveId,
                        name = def.name,
                        description = def.description,
                        severity = def.severity,
                        cvssScore = def.cvssScore,
                        affectedDevice =
                            targetDevices.firstOrNull() ?: BluetoothDevice(
                                address = "00:00:00:00:00:00",
                                name = "Unknown",
                                type = BluetoothType.UNKNOWN,
                                deviceClass = null,
                                bondState = BondState.NONE,
                                rssi = null,
                                txPower = null,
                                firstSeen = now,
                                lastSeen = now,
                            ),
                        discoveredAt = now,
                        category = def.category,
                        affectedBluetoothVersions = def.affectedVersions.split(","),
                        references = def.references,
                        mitigation = def.mitigation,
                        verified = false,
                        notes = "Detected via automated scan. Confidence: ${result.confidence}",
                    )
                }

            return SecurityReport(
                id = "rpt-${System.currentTimeMillis()}",
                authId = authId,
                title = "BTSec Assessment - ${targetDevices.firstOrNull()?.name ?: "Unknown"}",
                generatedAt = now,
                testPeriod =
                    ReportPeriod(
                        start = now.minus(1, ChronoUnit.HOURS),
                        end = now,
                    ),
                targetDevices = targetDevices,
                vulnerabilities = vulnerabilities,
                fuzzingResults = fuzzingResults,
                keyExtractionResults = keyExtractionResults,
                executiveSummary = executiveSummary.trim(),
                findings = findings,
                recommendations = recommendations,
                appendix = appendix,
                status = ReportStatus.DRAFT,
                evidenceLedger = evidenceLedger,
            )
        }

        /** A report cannot become final without an explicit reviewer action. */
        fun finalizeReport(
            report: SecurityReport,
            reviewer: String,
            reviewedAt: Instant = Instant.now(),
        ): Result<SecurityReport> {
            if (reviewer.isBlank()) return Result.failure(IllegalArgumentException("Reviewer is required"))
            val unresolved =
                report.evidenceLedger.filter {
                    it.outcome != EvidenceOutcome.VULNERABLE && it.outcome != EvidenceOutcome.NOT_VULNERABLE
                }
            if (unresolved.isNotEmpty()) {
                return Result.failure(
                    IllegalStateException("Cannot finalize report with unresolved evidence: ${unresolved.map { it.outcome }.distinct()}"),
                )
            }
            return Result.success(report.copy(status = ReportStatus.FINAL, reviewedBy = reviewer, reviewedAt = reviewedAt))
        }

        /**
         * Calculate overall risk score from vulnerability results.
         */
        fun calculateRiskScore(vulnerabilityResults: List<VulnerabilityTestResult>): Double {
            if (vulnerabilityResults.isEmpty()) return 0.0
            val unresolved =
                vulnerabilityResults.any {
                    it.outcome == EvidenceOutcome.INCONCLUSIVE ||
                        it.outcome == EvidenceOutcome.UNSUPPORTED ||
                        it.outcome == EvidenceOutcome.ERROR ||
                        it.outcome == EvidenceOutcome.CANCELLED
                }
            val detected = vulnerabilityResults.filter { it.outcome == EvidenceOutcome.VULNERABLE }
            if (detected.isEmpty()) return if (unresolved) Double.NaN else 0.0

            val weightedScore =
                detected.sumOf { result ->
                    when (result.vulnerability.severity) {
                        VulnerabilitySeverity.CRITICAL -> result.vulnerability.cvssScore * 1.5
                        VulnerabilitySeverity.HIGH -> result.vulnerability.cvssScore * 1.2
                        VulnerabilitySeverity.MEDIUM -> result.vulnerability.cvssScore * 1.0
                        VulnerabilitySeverity.LOW -> result.vulnerability.cvssScore * 0.5
                        VulnerabilitySeverity.NONE -> 0.0
                        VulnerabilitySeverity.INFORMATIONAL -> result.vulnerability.cvssScore * 0.2
                    }
                }
            return (weightedScore / vulnerabilityResults.size).coerceIn(0.0, 10.0)
        }

        /**
         * Get risk level label from score.
         */
        fun getRiskLabel(score: Double): String =
            when {
                score.isNaN() -> "INCONCLUSIVE"
                score >= 9.0 -> "CRITICAL"
                score >= 7.0 -> "HIGH"
                score >= 4.0 -> "MEDIUM"
                score >= 1.0 -> "LOW"
                else -> "NONE"
            }

        // ── Mapping helpers ──

        private fun mapCategory(category: VulnerabilityCategory): FindingCategory =
            when (category) {
                VulnerabilityCategory.PAIRING -> FindingCategory.STATE_ERROR
                VulnerabilityCategory.ENCRYPTION -> FindingCategory.INFORMATION_LEAK
                VulnerabilityCategory.AUTHENTICATION -> FindingCategory.BYPASS
                VulnerabilityCategory.IMPLEMENTATION -> FindingCategory.CRASH
                VulnerabilityCategory.CONFIGURATION -> FindingCategory.UNEXPECTED_RESPONSE
                VulnerabilityCategory.DENIAL_OF_SERVICE -> FindingCategory.HANG
                VulnerabilityCategory.INFORMATION_DISCLOSURE -> FindingCategory.INFORMATION_LEAK
                VulnerabilityCategory.PROTOCOL -> FindingCategory.UNEXPECTED_RESPONSE
                VulnerabilityCategory.PRIVILEGE_ESCALATION -> FindingCategory.BYPASS
                VulnerabilityCategory.AUTHORIZATION -> FindingCategory.BYPASS
                VulnerabilityCategory.OTHER -> FindingCategory.UNEXPECTED_RESPONSE
            }

        private fun mapPriority(severity: VulnerabilitySeverity): RecommendationPriority =
            when (severity) {
                VulnerabilitySeverity.CRITICAL -> RecommendationPriority.CRITICAL
                VulnerabilitySeverity.HIGH -> RecommendationPriority.HIGH
                VulnerabilitySeverity.MEDIUM -> RecommendationPriority.MEDIUM
                VulnerabilitySeverity.LOW -> RecommendationPriority.LOW
                VulnerabilitySeverity.NONE -> RecommendationPriority.LOW
                VulnerabilitySeverity.INFORMATIONAL -> RecommendationPriority.LOW
            }
    }
