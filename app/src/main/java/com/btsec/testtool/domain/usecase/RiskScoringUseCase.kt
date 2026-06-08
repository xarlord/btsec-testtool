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
import java.time.Instant
import javax.inject.Inject

/**
 * Use case for automated risk scoring of scan/vulnerability findings.
 *
 * Produces a risk score aligned with OWASP Top 10 (2021) and BISTF
 * (Bluetooth Implementation Security Testing Framework) categories.
 *
 * Score range: 0.0 to 10.0 (CVSS-like).
 * Thresholds: 9.0+ CRITICAL, 7.0+ HIGH, 4.0+ MEDIUM, 1.0+ LOW, else INFO.
 */
class RiskScoringUseCase @Inject constructor() {

    /**
     * Assess risk for a list of fuzz findings against an optional Bluetooth device.
     *
     * @param findings List of fuzz findings to evaluate
     * @param device Optional target device (used for context in recommendations)
     * @return A comprehensive [RiskAssessment]
     */
    fun assessRisk(
        findings: List<FuzzFinding>,
        device: BluetoothDevice?
    ): RiskAssessment {
        if (findings.isEmpty()) {
            return RiskAssessment(
                overallScore = 0.0,
                severity = RiskSeverity.INFO,
                owaspMappings = emptyList(),
                bistfMappings = emptyList(),
                factors = emptyList(),
                recommendations = listOf("No findings to assess. Device appears secure."),
                timestamp = Instant.now()
            )
        }

        // Build risk factors from findings
        val factors = buildRiskFactors(findings)

        // Calculate weighted score (0.0 to 10.0)
        val overallScore = calculateWeightedScore(factors)

        // Map findings to OWASP categories
        val owaspMappings = mapToOwasp(findings)

        // Map findings to BISTF categories
        val bistfMappings = mapToBistf(findings)

        // Generate recommendations
        val recommendations = generateRecommendations(owaspMappings, bistfMappings, findings)

        return RiskAssessment(
            overallScore = overallScore.coerceIn(0.0, 10.0),
            severity = classifySeverity(overallScore),
            owaspMappings = owaspMappings,
            bistfMappings = bistfMappings,
            factors = factors,
            recommendations = recommendations,
            timestamp = Instant.now()
        )
    }

    /**
     * Build risk factors from findings based on category and severity.
     */
    internal fun buildRiskFactors(findings: List<FuzzFinding>): List<RiskFactor> {
        val factors = mutableListOf<RiskFactor>()

        // Group findings by category
        val crashes = findings.filter { it.category == FindingCategory.CRASH }
        val memoryCorruption = findings.filter {
            it.category == FindingCategory.MEMORY_CORRUPTION ||
                it.category == FindingCategory.BUFFER_OVERFLOW
        }
        val infoLeaks = findings.filter { it.category == FindingCategory.INFORMATION_LEAK }
        val bypasses = findings.filter { it.category == FindingCategory.BYPASS }
        val unexpectedResponses = findings.filter {
            it.category == FindingCategory.UNEXPECTED_RESPONSE ||
                it.category == FindingCategory.STATE_ERROR
        }
        val hangs = findings.filter {
            it.category == FindingCategory.HANG ||
                it.category == FindingCategory.NO_RESPONSE
        }
        val delayedResponses = findings.filter {
            it.category == FindingCategory.DELAYED_RESPONSE
        }

        // Crash findings → HIGH weight (injection/buffer overflow)
        if (crashes.isNotEmpty()) {
            factors.add(
                RiskFactor(
                    name = "Device/Service Crashes",
                    weight = WEIGHT_HIGH,
                    score = scoreFromCountAndSeverity(crashes),
                    description = "${crashes.size} crash(es) detected during fuzzing"
                )
            )
        }

        // Memory corruption → HIGH weight (data integrity)
        if (memoryCorruption.isNotEmpty()) {
            factors.add(
                RiskFactor(
                    name = "Memory Corruption",
                    weight = WEIGHT_HIGH,
                    score = scoreFromCountAndSeverity(memoryCorruption),
                    description = "${memoryCorruption.size} memory corruption/buffer overflow finding(s)"
                )
            )
        }

        // Security bypasses → HIGH weight (broken access control)
        if (bypasses.isNotEmpty()) {
            factors.add(
                RiskFactor(
                    name = "Security Bypass",
                    weight = WEIGHT_HIGH,
                    score = scoreFromCountAndSeverity(bypasses),
                    description = "${bypasses.size} security bypass finding(s)"
                )
            )
        }

        // Information leaks → MEDIUM weight (broken access control)
        if (infoLeaks.isNotEmpty()) {
            factors.add(
                RiskFactor(
                    name = "Information Disclosure",
                    weight = WEIGHT_MEDIUM,
                    score = scoreFromCountAndSeverity(infoLeaks),
                    description = "${infoLeaks.size} information leak(s) detected"
                )
            )
        }

        // Hangs/No response → MEDIUM weight (denial of service)
        if (hangs.isNotEmpty()) {
            factors.add(
                RiskFactor(
                    name = "Denial of Service",
                    weight = WEIGHT_MEDIUM,
                    score = scoreFromCountAndSeverity(hangs),
                    description = "${hangs.size} hang/no-response finding(s)"
                )
            )
        }

        // Unexpected responses → LOW weight (misconfiguration)
        if (unexpectedResponses.isNotEmpty()) {
            factors.add(
                RiskFactor(
                    name = "Unexpected Responses",
                    weight = WEIGHT_LOW,
                    score = scoreFromCountAndSeverity(unexpectedResponses),
                    description = "${unexpectedResponses.size} unexpected response(s)"
                )
            )
        }

        // Delayed responses → LOW weight
        if (delayedResponses.isNotEmpty()) {
            factors.add(
                RiskFactor(
                    name = "Delayed Responses",
                    weight = WEIGHT_LOW,
                    score = scoreFromCountAndSeverity(delayedResponses),
                    description = "${delayedResponses.size} abnormally delayed response(s)"
                )
            )
        }

        return factors
    }

    /**
     * Calculate overall weighted score from risk factors.
     *
     * Formula: sum(score * weight) / sum(weight) * 10
     * This normalizes to a 0-10 scale.
     */
    internal fun calculateWeightedScore(factors: List<RiskFactor>): Double {
        if (factors.isEmpty()) return 0.0

        val totalWeight = factors.sumOf { it.weight }
        if (totalWeight == 0.0) return 0.0

        val weightedSum = factors.sumOf { it.score * it.weight }
        return (weightedSum / totalWeight) * 10.0
    }

    /**
     * Classify overall score into a risk severity.
     */
    internal fun classifySeverity(score: Double): RiskSeverity {
        return when {
            score >= 9.0 -> RiskSeverity.CRITICAL
            score >= 7.0 -> RiskSeverity.HIGH
            score >= 4.0 -> RiskSeverity.MEDIUM
            score >= 1.0 -> RiskSeverity.LOW
            else -> RiskSeverity.INFO
        }
    }

    /**
     * Map findings to OWASP Top 10 categories.
     */
    internal fun mapToOwasp(findings: List<FuzzFinding>): List<OwaspMapping> {
        val mapping = mutableMapOf<OwaspCategory, MutableList<FuzzFinding>>()

        for (finding in findings) {
            val category = when (finding.category) {
                FindingCategory.CRASH -> OwaspCategory.A03_INJECTION
                FindingCategory.BUFFER_OVERFLOW -> OwaspCategory.A03_INJECTION
                FindingCategory.MEMORY_CORRUPTION -> OwaspCategory.A08_DATA_INTEGRITY
                FindingCategory.INFORMATION_LEAK -> OwaspCategory.A01_BROKEN_ACCESS_CONTROL
                FindingCategory.BYPASS -> OwaspCategory.A01_BROKEN_ACCESS_CONTROL
                FindingCategory.UNEXPECTED_RESPONSE -> OwaspCategory.A05_MISCONFIG
                FindingCategory.STATE_ERROR -> OwaspCategory.A04_INSECURE_DESIGN
                FindingCategory.HANG -> OwaspCategory.A04_INSECURE_DESIGN
                FindingCategory.NO_RESPONSE -> OwaspCategory.A04_INSECURE_DESIGN
                FindingCategory.DELAYED_RESPONSE -> OwaspCategory.A05_MISCONFIG
            }
            mapping.getOrPut(category) { mutableListOf() }.add(finding)
        }

        return mapping.map { (category, categoryFindings) ->
            OwaspMapping(
                category = category,
                findings = categoryFindings.map { it.description },
                contribution = calculateCategoryContribution(categoryFindings)
            )
        }.sortedByDescending { it.contribution }
    }

    /**
     * Map findings to BISTF categories based on BLE-specific characteristics.
     */
    internal fun mapToBistf(findings: List<FuzzFinding>): List<BistfMapping> {
        val mapping = mutableMapOf<BistfCategory, MutableList<FuzzFinding>>()

        for (finding in findings) {
            val category = mapFindingToBistf(finding)
            mapping.getOrPut(category) { mutableListOf() }.add(finding)
        }

        return mapping.map { (category, categoryFindings) ->
            BistfMapping(
                category = category,
                findings = categoryFindings.map { it.description },
                contribution = calculateCategoryContribution(categoryFindings)
            )
        }.sortedByDescending { it.contribution }
    }

    /**
     * Map a single finding to a BISTF category.
     *
     * Uses the finding description and category to infer the most likely
     * BLE protocol layer affected.
     */
    private fun mapFindingToBistf(finding: FuzzFinding): BistfCategory {
        val desc = finding.description.lowercase()

        return when {
            desc.contains("l2cap") -> BistfCategory.L2CAP_VULN
            desc.contains("gatt") || desc.contains("service") || desc.contains("characteristic") ->
                BistfCategory.GATT_VULN
            desc.contains("smp") || desc.contains("pairing") || desc.contains("bonding") ->
                BistfCategory.SMP_VULN
            desc.contains("att") || desc.contains("attribute") || desc.contains("notification") ->
                BistfCategory.ATT_VULN
            desc.contains("hci") || desc.contains("command") ->
                BistfCategory.HCI_VULN
            desc.contains("privacy") || desc.contains("tracking") || desc.contains("address") ->
                BistfCategory.PRIVACY
            // Default mapping based on finding category
            else -> when (finding.category) {
                FindingCategory.CRASH, FindingCategory.BUFFER_OVERFLOW,
                FindingCategory.MEMORY_CORRUPTION -> BistfCategory.L2CAP_VULN
                FindingCategory.INFORMATION_LEAK, FindingCategory.BYPASS ->
                    BistfCategory.GATT_VULN
                FindingCategory.UNEXPECTED_RESPONSE, FindingCategory.STATE_ERROR ->
                    BistfCategory.ATT_VULN
                FindingCategory.HANG, FindingCategory.NO_RESPONSE ->
                    BistfCategory.HCI_VULN
                FindingCategory.DELAYED_RESPONSE -> BistfCategory.L2CAP_VULN
            }
        }
    }

    /**
     * Generate recommendations based on OWASP and BISTF mappings.
     */
    private fun generateRecommendations(
        owaspMappings: List<OwaspMapping>,
        bistfMappings: List<BistfMapping>,
        findings: List<FuzzFinding>
    ): List<String> {
        val recommendations = mutableListOf<String>()

        for (mapping in owaspMappings) {
            when (mapping.category) {
                OwaspCategory.A01_BROKEN_ACCESS_CONTROL ->
                    recommendations.add(
                        "[${mapping.category.id}] Review access control mechanisms. " +
                            "${mapping.findings.size} finding(s) indicate potential unauthorized access."
                    )
                OwaspCategory.A03_INJECTION ->
                    recommendations.add(
                        "[${mapping.category.id}] Strengthen input validation and bounds checking. " +
                            "${mapping.findings.size} finding(s) suggest injection or overflow vulnerabilities."
                    )
                OwaspCategory.A04_INSECURE_DESIGN ->
                    recommendations.add(
                        "[${mapping.category.id}] Review protocol state machine design. " +
                            "${mapping.findings.size} finding(s) indicate design-level weaknesses."
                    )
                OwaspCategory.A05_MISCONFIG ->
                    recommendations.add(
                        "[${mapping.category.id}] Audit device configuration and default settings. " +
                            "${mapping.findings.size} finding(s) suggest misconfiguration."
                    )
                OwaspCategory.A08_DATA_INTEGRITY ->
                    recommendations.add(
                        "[${mapping.category.id}] Improve memory safety and data integrity checks. " +
                            "${mapping.findings.size} finding(s) indicate data integrity issues."
                    )
                else -> {
                    // General recommendation for other categories
                    recommendations.add(
                        "[${mapping.category.id}] ${mapping.category.displayName}: " +
                            "${mapping.findings.size} finding(s) require further investigation."
                    )
                }
            }
        }

        for (mapping in bistfMappings) {
            recommendations.add(
                "[${mapping.category.id}] ${mapping.category.displayName}: " +
                    "${mapping.findings.size} BLE-specific finding(s) identified."
            )
        }

        // Add general recommendations based on finding count
        val criticalCount = findings.count {
            it.severity == VulnerabilitySeverity.CRITICAL || it.severity == VulnerabilitySeverity.HIGH
        }
        if (criticalCount > 3) {
            recommendations.add(
                "URGENT: $criticalCount critical/high findings detected. " +
                    "Immediate firmware review recommended."
            )
        }

        if (findings.any { it.reproducible }) {
            recommendations.add(
                "Reproducible findings detected. Prioritize these for remediation as they " +
                    "indicate reliably exploitable vulnerabilities."
            )
        }

        return recommendations
    }

    /**
     * Calculate a 0-1 score from finding count and severity.
     *
     * More findings and higher severities produce higher scores.
     */
    private fun scoreFromCountAndSeverity(findings: List<FuzzFinding>): Double {
        if (findings.isEmpty()) return 0.0

        val severityScores = mapOf(
            VulnerabilitySeverity.CRITICAL to 1.0,
            VulnerabilitySeverity.HIGH to 0.8,
            VulnerabilitySeverity.MEDIUM to 0.6,
            VulnerabilitySeverity.LOW to 0.4,
            VulnerabilitySeverity.NONE to 0.1,
            VulnerabilitySeverity.INFORMATIONAL to 0.1
        )

        val maxSeverityScore = findings.maxOf { severityScores[it.severity] ?: 0.4 }
        val countBonus = (findings.size - 1) * 0.05  // Each additional finding adds 5%
        val reproducibleBonus = if (findings.any { it.reproducible }) 0.1 else 0.0

        return (maxSeverityScore + countBonus + reproducibleBonus).coerceIn(0.0, 1.0)
    }

    /**
     * Calculate the relative contribution of findings in a category (0.0 to 1.0).
     */
    private fun calculateCategoryContribution(findings: List<FuzzFinding>): Double {
        val totalScore = findings.sumOf {
            when (it.severity) {
                VulnerabilitySeverity.CRITICAL -> 1.0
                VulnerabilitySeverity.HIGH -> 0.8
                VulnerabilitySeverity.MEDIUM -> 0.6
                VulnerabilitySeverity.LOW -> 0.4
                VulnerabilitySeverity.NONE -> 0.1
                VulnerabilitySeverity.INFORMATIONAL -> 0.1
            }
        }
        // Normalize: max possible is count * 1.0, return as proportion
        return if (findings.isNotEmpty()) {
            (totalScore / findings.size).coerceIn(0.0, 1.0)
        } else {
            0.0
        }
    }

    companion object {
        internal const val WEIGHT_HIGH = 3.0
        internal const val WEIGHT_MEDIUM = 2.0
        internal const val WEIGHT_LOW = 1.0
    }
}
