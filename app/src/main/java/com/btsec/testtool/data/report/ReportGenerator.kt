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
import com.btsec.testtool.domain.repository.ExportFormat
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
class ReportGenerator @Inject constructor() {

    /**
     * Generate a full security report from test results.
     */
    fun generateReport(
        authId: String,
        config: ReportConfig,
        targetDevices: List<BluetoothDevice>,
        vulnerabilityResults: List<VulnerabilityTestResult>,
        fuzzingResults: List<FuzzResult>,
        keyExtractionResults: List<KeyExtractionResult>
    ): SecurityReport {
        val now = Instant.now()
        val findings = buildFindings(vulnerabilityResults, targetDevices)
        val recommendations = buildRecommendations(vulnerabilityResults, targetDevices)
        val executiveSummary = buildExecutiveSummary(
            now, targetDevices, vulnerabilityResults, fuzzingResults, keyExtractionResults
        )
        val appendix = buildAppendix(vulnerabilityResults)
        val vulnerabilities = mapDetectedVulnerabilities(vulnerabilityResults, targetDevices, now)

        return SecurityReport(
            id = "rpt-${System.currentTimeMillis()}",
            authId = authId,
            title = "BTSec Assessment - ${targetDevices.firstOrNull()?.name ?: "Unknown"}",
            generatedAt = now,
            testPeriod = ReportPeriod(now.minus(1, ChronoUnit.HOURS), now),
            targetDevices = targetDevices,
            vulnerabilities = vulnerabilities,
            fuzzingResults = fuzzingResults,
            keyExtractionResults = keyExtractionResults,
            executiveSummary = executiveSummary.trim(),
            findings = findings,
            recommendations = recommendations,
            appendix = appendix,
            status = ReportStatus.FINAL
        )
    }

    private fun buildFindings(
        vulnerabilityResults: List<VulnerabilityTestResult>,
        targetDevices: List<BluetoothDevice>
    ): List<ReportFinding> {
        return vulnerabilityResults
            .groupBy { Pair(mapCategory(it.vulnerability.category), it.vulnerability.severity) }
            .map { (catSev, results) ->
                ReportFinding(
                    category = catSev.first,
                    severity = catSev.second,
                    count = results.size,
                    description = results.map { it.vulnerability.name }.distinct().joinToString(", "),
                    affectedDevices = targetDevices.map { it.address }
                )
            }
    }

    private fun buildRecommendations(
        vulnerabilityResults: List<VulnerabilityTestResult>,
        targetDevices: List<BluetoothDevice>
    ): List<Recommendation> {
        return vulnerabilityResults
            .filter { it.detected }
            .sortedByDescending { it.vulnerability.cvssScore }
            .map { result ->
                Recommendation(
                    priority = mapPriority(result.vulnerability.severity),
                    title = "Remediate ${result.vulnerability.name}",
                    description = result.vulnerability.description,
                    affectedDevices = targetDevices.map { it.address },
                    implementation = result.vulnerability.mitigation,
                    verification = "Re-scan after applying fix to confirm vulnerability is resolved."
                )
            }
            .distinctBy { it.title }
    }

    private fun buildExecutiveSummary(
        now: Instant,
        targetDevices: List<BluetoothDevice>,
        vulnerabilityResults: List<VulnerabilityTestResult>,
        fuzzingResults: List<FuzzResult>,
        keyExtractionResults: List<KeyExtractionResult>
    ): String = buildString {
        val detectedCount = vulnerabilityResults.count { it.detected }
        val totalScanned = vulnerabilityResults.size
        val criticalCount = vulnerabilityResults.count {
            it.detected && it.vulnerability.severity == VulnerabilitySeverity.CRITICAL
        }
        val highCount = vulnerabilityResults.count {
            it.detected && it.vulnerability.severity == VulnerabilitySeverity.HIGH
        }

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
        if (detectedCount == 0) {
            appendLine("No critical vulnerabilities detected. Continue monitoring.")
        } else {
            appendLine("IMMEDIATE ACTION REQUIRED: $detectedCount vulnerabilities need remediation.")
        }
    }

    private fun buildAppendix(vulnerabilityResults: List<VulnerabilityTestResult>): ReportAppendix {
        return ReportAppendix(
            toolsUsed = listOf("BTSec TestTool v1.2.1", "BLE Fuzzing Engine", "Vulnerability Scanner"),
            testMethodology = "Automated scanning using CVE-specific test vectors, BLE packet fuzzing, and key extraction analysis.",
            limitations = listOf(
                "Tests performed from Android device perspective only",
                "Some vulnerabilities require specific hardware/firmware to exploit",
                "Results represent point-in-time assessment"
            ),
            glossary = mapOf(
                "CVSS" to "Common Vulnerability Scoring System",
                "CVE" to "Common Vulnerabilities and Exposures",
                "BLE" to "Bluetooth Low Energy",
                "GATT" to "Generic Attribute Profile",
                "SMP" to "Security Manager Protocol",
                "CTKD" to "Cross-Transport Key Derivation"
            ),
            references = vulnerabilityResults.flatMap { it.vulnerability.references }.distinct()
        )
    }

    private fun mapDetectedVulnerabilities(
        vulnerabilityResults: List<VulnerabilityTestResult>,
        targetDevices: List<BluetoothDevice>,
        now: Instant
    ): List<Vulnerability> {
        val fallbackDevice = BluetoothDevice(
            address = "00:00:00:00:00:00", name = "Unknown",
            type = BluetoothType.UNKNOWN, deviceClass = null, bondState = BondState.NONE,
            rssi = null, txPower = null, firstSeen = now, lastSeen = now
        )
        return vulnerabilityResults.filter { it.detected }.map { result ->
            val def = result.vulnerability
            Vulnerability(
                id = "vuln-${def.cveId}", cveId = def.cveId, name = def.name,
                description = def.description, severity = def.severity,
                cvssScore = def.cvssScore,
                affectedDevice = targetDevices.firstOrNull() ?: fallbackDevice,
                discoveredAt = now, category = def.category,
                affectedBluetoothVersions = def.affectedVersions.split(","),
                references = def.references, mitigation = def.mitigation,
                verified = false, notes = "Detected via automated scan. Confidence: ${result.confidence}"
            )
        }
    }

    /**
     * Calculate overall risk score from vulnerability results.
     */
    fun calculateRiskScore(vulnerabilityResults: List<VulnerabilityTestResult>): Double {
        if (vulnerabilityResults.isEmpty()) return 0.0
        val detected = vulnerabilityResults.filter { it.detected }
        if (detected.isEmpty()) return 0.0

        val weightedScore = detected.sumOf { result ->
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
    fun getRiskLabel(score: Double): String = when {
        score >= 9.0 -> "CRITICAL"
        score >= 7.0 -> "HIGH"
        score >= 4.0 -> "MEDIUM"
        score >= 1.0 -> "LOW"
        else -> "NONE"
    }

    // ── Mapping helpers ──

    private fun mapCategory(category: VulnerabilityCategory): FindingCategory = when (category) {
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

    private fun mapPriority(severity: VulnerabilitySeverity): RecommendationPriority = when (severity) {
        VulnerabilitySeverity.CRITICAL -> RecommendationPriority.CRITICAL
        VulnerabilitySeverity.HIGH -> RecommendationPriority.HIGH
        VulnerabilitySeverity.MEDIUM -> RecommendationPriority.MEDIUM
        VulnerabilitySeverity.LOW -> RecommendationPriority.LOW
        VulnerabilitySeverity.NONE -> RecommendationPriority.LOW
        VulnerabilitySeverity.INFORMATIONAL -> RecommendationPriority.LOW
    }
}
