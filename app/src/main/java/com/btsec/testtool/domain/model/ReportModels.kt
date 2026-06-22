/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import kotlinx.serialization.Serializable
import java.time.Instant

/**
 * Security assessment report.
 */
@Serializable
data class SecurityReport(
    val id: String,
    val authId: String,
    val title: String,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val generatedAt: Instant,
    val testPeriod: ReportPeriod,
    val targetDevices: List<BluetoothDevice> = emptyList(),
    val vulnerabilities: List<Vulnerability> = emptyList(),
    val fuzzingResults: List<FuzzResult> = emptyList(),
    val keyExtractionResults: List<KeyExtractionResult> = emptyList(),
    val executiveSummary: String = "",
    val findings: List<ReportFinding> = emptyList(),
    val recommendations: List<Recommendation> = emptyList(),
    val appendix: ReportAppendix,
    val status: ReportStatus = ReportStatus.DRAFT,
)

/**
 * Report time period.
 */
@Serializable
data class ReportPeriod(
    @Serializable(with = InstantAsEpochMillisSerializer::class) val start: Instant,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val end: Instant,
)

/**
 * Report finding summary.
 */
@Serializable
data class ReportFinding(
    val category: FindingCategory,
    val severity: VulnerabilitySeverity,
    val count: Int = 0,
    val description: String = "",
    // Device addresses
    val affectedDevices: List<String> = emptyList(),
)

/**
 * Security recommendations.
 */
@Serializable
data class Recommendation(
    val priority: RecommendationPriority = RecommendationPriority.MEDIUM,
    val title: String = "",
    val description: String = "",
    val affectedDevices: List<String> = emptyList(),
    val implementation: String = "",
    val verification: String = "",
)

/**
 * Recommendation priority levels.
 */
@Serializable
enum class RecommendationPriority {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
}

/**
 * Report appendix information.
 */
@Serializable
data class ReportAppendix(
    val toolsUsed: List<String> = emptyList(),
    val testMethodology: String = "",
    val limitations: List<String> = emptyList(),
    val glossary: Map<String, String> = emptyMap(),
    val references: List<String> = emptyList(),
)

/**
 * Report status.
 */
@Serializable
enum class ReportStatus {
    DRAFT,
    REVIEW,
    FINAL,
    ARCHIVED,
}
