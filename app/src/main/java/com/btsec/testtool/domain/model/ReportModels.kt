/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import java.time.Instant

/**
 * Security assessment report.
 */
data class SecurityReport(
    val id: String,
    val authId: String,
    val title: String,
    val generatedAt: Instant,
    val testPeriod: ReportPeriod,
    val targetDevices: List<BluetoothDevice>,
    val vulnerabilities: List<Vulnerability>,
    val fuzzingResults: List<FuzzResult>,
    val keyExtractionResults: List<KeyExtractionResult>,
    val executiveSummary: String,
    val findings: List<ReportFinding>,
    val recommendations: List<Recommendation>,
    val appendix: ReportAppendix,
    val status: ReportStatus
)

/**
 * Report time period.
 */
data class ReportPeriod(
    val start: Instant,
    val end: Instant
)

/**
 * Report finding summary.
 */
data class ReportFinding(
    val category: FindingCategory,
    val severity: VulnerabilitySeverity,
    val count: Int,
    val description: String,
    val affectedDevices: List<String>  // Device addresses
)

/**
 * Security recommendations.
 */
data class Recommendation(
    val priority: RecommendationPriority,
    val title: String,
    val description: String,
    val affectedDevices: List<String>,
    val implementation: String,
    val verification: String
)

/**
 * Recommendation priority levels.
 */
enum class RecommendationPriority {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW
}

/**
 * Report appendix information.
 */
data class ReportAppendix(
    val toolsUsed: List<String>,
    val testMethodology: String,
    val limitations: List<String>,
    val glossary: Map<String, String>,
    val references: List<String>
)

/**
 * Report status.
 */
enum class ReportStatus {
    DRAFT,
    REVIEW,
    FINAL,
    ARCHIVED
}
