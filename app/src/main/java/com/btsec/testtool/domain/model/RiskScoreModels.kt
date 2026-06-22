/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import kotlinx.serialization.Serializable
import java.time.Instant

/**
 * OWASP Top 10 (2021) categories with BLE-specific extension.
 */
@Serializable
enum class OwaspCategory(val id: String, val displayName: String) {
    A01_BROKEN_ACCESS_CONTROL("A01", "Broken Access Control"),
    A02_CRYPTO_FAILURES("A02", "Cryptographic Failures"),
    A03_INJECTION("A03", "Injection"),
    A04_INSECURE_DESIGN("A04", "Insecure Design"),
    A05_MISCONFIG("A05", "Security Misconfiguration"),
    A06_VULN_COMPONENTS("A06", "Vulnerable Components"),
    A07_AUTH_FAIL("A07", "Identification and Authentication Failures"),
    A08_DATA_INTEGRITY("A08", "Software and Data Integrity Failures"),
    A09_LOGGING_FAIL("A09", "Security Logging and Monitoring Failures"),
    A10_SSRF("A10", "Server-Side Request Forgery"),
    BLE_SPECIFIC("BLE", "BLE-Specific Vulnerability"),
}

/**
 * BISTF (Bluetooth Implementation Security Testing Framework) categories.
 */
@Serializable
enum class BistfCategory(val id: String, val displayName: String) {
    L2CAP_VULN("BISTF-01", "L2CAP Vulnerability"),
    GATT_VULN("BISTF-02", "GATT Vulnerability"),
    SMP_VULN("BISTF-03", "SMP/Pairing Vulnerability"),
    ATT_VULN("BISTF-04", "ATT Vulnerability"),
    HCI_VULN("BISTF-05", "HCI Vulnerability"),
    PRIVACY("BISTF-06", "Privacy/Tracking"),
}

/**
 * Individual risk factor contributing to the overall risk score.
 */
@Serializable
data class RiskFactor(
    val name: String,
    val weight: Double,
    // 0.0 to 1.0
    val score: Double,
    val description: String,
)

/**
 * Overall risk assessment result.
 */
@Serializable
data class RiskAssessment(
    // 0.0 to 10.0 (CVSS-like)
    val overallScore: Double,
    val severity: RiskSeverity,
    val owaspMappings: List<OwaspMapping>,
    val bistfMappings: List<BistfMapping>,
    val factors: List<RiskFactor>,
    val recommendations: List<String>,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val timestamp: Instant,
)

/**
 * Risk severity levels based on CVSS-like thresholds.
 */
@Serializable
enum class RiskSeverity {
    CRITICAL, // 9.0+
    HIGH, // 7.0-8.9
    MEDIUM, // 4.0-6.9
    LOW, // 1.0-3.9
    INFO, // < 1.0
}

/**
 * Mapping of findings to an OWASP category with contribution score.
 */
@Serializable
data class OwaspMapping(
    val category: OwaspCategory,
    val findings: List<String>,
    val contribution: Double,
)

/**
 * Mapping of findings to a BISTF category with contribution score.
 */
@Serializable
data class BistfMapping(
    val category: BistfCategory,
    val findings: List<String>,
    val contribution: Double,
)
