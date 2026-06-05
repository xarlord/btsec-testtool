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
import java.time.Instant
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Generates comprehensive security assessment reports from test data.
 *
 * Aggregates vulnerability scan results, fuzzing findings, and key extraction
 * results into structured SecurityReport objects with risk scoring and
 * actionable recommendations.
 */
@Singleton
class ReportGenerator @Inject constructor() {

    /**
     * Generate a security report from collected test data.
     */
    suspend fun generateReport(
        config: ReportConfig,
        authId: String,
        devices: List<BluetoothDevice>,
        vulns: List<Vulnerability>,
        fuzzResults: List<FuzzResult>,
        keyResults: List<KeyExtractionResult>
    ): SecurityReport {
        val filteredVulns = if (config.includeVulnerabilities) {
            vulns.filter { it.severity.ordinal <= config.minSeverity.ordinal }
        } else emptyList()

        val riskScore = calculateRiskScore(vulns)
        val sections = buildSections(config, filteredVulns, fuzzResults, keyResults, riskScore)
        val summary = if (config.includeExecutiveSummary) buildExecutiveSummary(filteredVulns, fuzzResults, keyResults, riskScore) else null
        val recommendations = if (config.includeRecommendations) buildRecommendations(filteredVulns) else emptyList()

        return SecurityReport(
            id = UUID.randomUUID().toString(),
            title = config.title,
            generatedAt = Instant.now(),
            generatedBy = "BTSec TestTool v1.2.1",
            targetDevices = devices,
            vulnerabilities = filteredVulns,
            fuzzingResults = if (config.includeFuzzingResults) fuzzResults else emptyList(),
            keyExtractionResults = if (config.includeKeyExtraction) keyResults else emptyList(),
            executiveSummary = summary,
            recommendations = recommendations,
            status = ReportStatus.DRAFT,
            authId = authId,
            templateId = config.templateId,
            sections = sections,
            totalRiskScore = riskScore
        )
    }

    /**
     * Calculate risk score (0-10) based on discovered vulnerabilities.
     */
    fun calculateRiskScore(vulns: List<Vulnerability>): Double {
        if (vulns.isEmpty()) return 0.0

        val weights = mapOf(
            VulnerabilitySeverity.CRITICAL to 3.0,
            VulnerabilitySeverity.HIGH to 2.0,
            VulnerabilitySeverity.MEDIUM to 1.0,
            VulnerabilitySeverity.LOW to 0.5,
            VulnerabilitySeverity.INFORMATIONAL to 0.1,
            VulnerabilitySeverity.NONE to 0.0
        )

        val rawScore = vulns.sumOf { vuln ->
            val baseWeight = weights[vuln.severity] ?: 0.0
            val verifiedMultiplier = if (vuln.verified) 1.0 else 0.7
            val cvssContribution = vuln.cvssScore?.div(10.0) ?: 0.5
            baseWeight * verifiedMultiplier * cvssContribution
        }

        // Normalize to 0-10 scale with diminishing returns for many vulns
        val normalized = rawScore * 10.0 / (rawScore + vulns.size * 0.5)
        return (normalized * 10.0).toInt() / 10.0  // Round to 1 decimal
    }

    private fun buildSections(
        config: ReportConfig,
        vulns: List<Vulnerability>,
        fuzzResults: List<FuzzResult>,
        keyResults: List<KeyExtractionResult>,
        riskScore: Double
    ): List<ReportSection> {
        val sections = mutableListOf<ReportSection>()
        var order = 0

        // Risk Assessment section
        sections.add(ReportSection(
            title = "Risk Assessment",
            content = "Overall risk score: $riskScore/10.0\n" +
                    when {
                        riskScore >= 8.0 -> "CRITICAL: Immediate remediation required."
                        riskScore >= 5.0 -> "HIGH: Remediation should be prioritized."
                        riskScore >= 2.5 -> "MODERATE: Address findings within standard timeline."
                        else -> "LOW: Findings are informational, routine review recommended."
                    },
            severity = when {
                riskScore >= 8.0 -> VulnerabilitySeverity.CRITICAL
                riskScore >= 5.0 -> VulnerabilitySeverity.HIGH
                riskScore >= 2.5 -> VulnerabilitySeverity.MEDIUM
                else -> VulnerabilitySeverity.LOW
            },
            order = order++
        ))

        if (config.includeVulnerabilities && vulns.isNotEmpty()) {
            val bySeverity = vulns.groupBy { it.severity }
            sections.add(ReportSection(
                title = "Vulnerability Findings",
                content = buildString {
                    appendLine("Total vulnerabilities discovered: ${vulns.size}")
                    VulnerabilitySeverity.entries.reversed().forEach { sev ->
                        val count = bySeverity[sev]?.size ?: 0
                        if (count > 0) appendLine("  ${sev.name}: $count")
                    }
                    appendLine()
                    vulns.forEach { v ->
                        appendLine("• ${v.cveId ?: v.name} [${v.severity}]")
                        appendLine("  ${v.description}")
                        if (v.remediation != null) appendLine("  Fix: ${v.remediation}")
                        appendLine()
                    }
                },
                severity = vulns.maxByOrNull { it.severity.ordinal }?.severity,
                order = order++
            ))
        }

        if (config.includeFuzzingResults && fuzzResults.isNotEmpty()) {
            val totalFindings = fuzzResults.sumOf { it.findings.size }
            sections.add(ReportSection(
                title = "Fuzzing Results",
                content = buildString {
                    appendLine("Fuzzing sessions: ${fuzzResults.size}")
                    appendLine("Total packets sent: ${fuzzResults.sumOf { it.packetsSent }}")
                    appendLine("Total findings: $totalFindings")
                    fuzzResults.forEach { r ->
                        appendLine("\nSession ${r.id.take(8)}: ${r.status.name}")
                        appendLine("  Method: ${r.config.fuzzMethod.name}")
                        appendLine("  Packets: ${r.packetsSent} sent, ${r.packetsReceived} received")
                        r.findings.forEach { f ->
                            appendLine("  Finding: ${f.description} [${f.severity}]")
                        }
                    }
                },
                severity = fuzzResults.flatMap { it.findings }.maxByOrNull { it.severity.ordinal }?.severity,
                order = order++
            ))
        }

        if (config.includeKeyExtraction && keyResults.isNotEmpty()) {
            sections.add(ReportSection(
                title = "Key Extraction Analysis",
                content = buildString {
                    appendLine("Key extraction attempts: ${keyResults.size}")
                    keyResults.forEach { r ->
                        appendLine("  ${r.keyType.name} via ${r.method.name}: " +
                                if (r.extracted) "EXTRACTED (${r.confidence.name} confidence)" else "Not extracted")
                    }
                },
                severity = if (keyResults.any { it.extracted }) VulnerabilitySeverity.CRITICAL else null,
                order = order++
            ))
        }

        return sections
    }

    private fun buildExecutiveSummary(
        vulns: List<Vulnerability>,
        fuzzResults: List<FuzzResult>,
        keyResults: List<KeyExtractionResult>,
        riskScore: Double
    ): String {
        val criticalVulns = vulns.count { it.severity == VulnerabilitySeverity.CRITICAL }
        val highVulns = vulns.count { it.severity == VulnerabilitySeverity.HIGH }
        val fuzzFindings = fuzzResults.sumOf { it.findings.size }
        val keysExtracted = keyResults.count { it.extracted }

        return buildString {
            appendLine("Bluetooth Security Assessment — Executive Summary")
            appendLine()
            appendLine("This report presents the findings of an authorized Bluetooth security assessment.")
            appendLine()
            append("Risk Score: $riskScore/10.0 — ")
            appendLine(when {
                riskScore >= 8.0 -> "CRITICAL risk level. Multiple serious vulnerabilities require immediate attention."
                riskScore >= 5.0 -> "HIGH risk level. Significant security issues identified."
                riskScore >= 2.5 -> "MODERATE risk level. Some concerns identified, standard remediation recommended."
                else -> "LOW risk level. No significant security issues detected."
            })
            appendLine()
            appendLine("Key Findings:")
            if (criticalVulns > 0) appendLine("  ⚠ $criticalVulns CRITICAL vulnerabilities detected")
            if (highVulns > 0) appendLine("  ⚠ $highVulns HIGH severity vulnerabilities detected")
            appendLine("  • ${vulns.size} total vulnerabilities identified")
            appendLine("  • $fuzzFindings fuzzing anomalies detected")
            if (keysExtracted > 0) appendLine("  ⚠ $keysExtracted encryption keys extracted — CRITICAL")
            appendLine("  • ${fuzzResults.size} fuzzing sessions completed")
            appendLine("  • ${keyResults.size} key extraction tests performed")
        }
    }

    private fun buildRecommendations(vulns: List<Vulnerability>): List<String> {
        val recs = mutableListOf<String>()

        val categories = vulns.groupBy { it.category }
        if (categories.containsKey(VulnerabilityCategory.ENCRYPTION)) {
            recs.add("Upgrade to Bluetooth 5.2+ with LE Secure Connections. Enforce minimum 128-bit encryption keys.")
        }
        if (categories.containsKey(VulnerabilityCategory.AUTHENTICATION)) {
            recs.add("Implement mutual authentication on every connection. Disable legacy pairing where possible.")
        }
        if (categories.containsKey(VulnerabilityCategory.IMPLEMENTATION)) {
            recs.add("Apply latest firmware patches. Test with fuzzing tools regularly. Enable stack canaries and ASLR.")
        }
        if (categories.containsKey(VulnerabilityCategory.DENIAL_OF_SERVICE)) {
            recs.add("Implement rate limiting and connection throttling. Monitor for abnormal disconnection patterns.")
        }
        if (categories.containsKey(VulnerabilityCategory.PAIRING)) {
            recs.add("Use Numeric Comparison or Passkey Entry pairing. Disable Just Works for sensitive devices.")
        }
        if (categories.containsKey(VulnerabilityCategory.PRIVACY)) {
            recs.add("Enable LE Privacy 1.2 with resolving list. Use random resolvable addresses.")
        }

        // General recommendations
        recs.add("Disable Bluetooth when not actively in use.")
        recs.add("Regularly update device firmware to patch known vulnerabilities.")
        recs.add("Maintain an inventory of all Bluetooth-capable devices and their firmware versions.")

        return recs.distinct()
    }
}
