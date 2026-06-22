/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.*

/**
 * Composite repository for security assessment report generation and management.
 *
 * Extends [ReportReader] and [ReportWriter] to provide the full set of report
 * capabilities while adhering to the Interface Segregation Principle (ISP).
 * Existing implementations remain compatible since this interface inherits all
 * methods from its parent interfaces.
 *
 * Handles creation, storage, and export of security assessment reports.
 * All reports are tied to an authorization ID for audit purposes.
 *
 * @see ReportReader
 * @see ReportWriter
 */
interface ReportRepository : ReportReader, ReportWriter

/**
 * Report configuration.
 */
data class ReportConfig(
    val title: String,
    val includeVulnerabilities: Boolean = true,
    val includeFuzzingResults: Boolean = true,
    val includeKeyExtraction: Boolean = true,
    val includePacketCaptures: Boolean = false,
    val includeExecutiveSummary: Boolean = true,
    val includeRecommendations: Boolean = true,
    val includeAppendix: Boolean = true,
    val templateId: String? = null,
    val customSections: List<CustomReportSection> = emptyList(),
    val minSeverity: VulnerabilitySeverity = VulnerabilitySeverity.LOW,
)

/**
 * Custom report section.
 */
data class CustomReportSection(
    val title: String,
    val content: String,
    val order: Int,
)

/**
 * Report generation progress.
 */
data class ReportGenerationProgress(
    val reportId: String,
    val status: ReportGenerationStatus,
    val currentStep: GenerationStep,
    val progressPercentage: Int,
    val estimatedCompletionTime: java.time.Instant?,
    val error: String? = null,
)

/**
 * Report generation status.
 */
enum class ReportGenerationStatus {
    PENDING,
    GENERATING,
    COMPLETED,
    FAILED,
    CANCELLED,
}

/**
 * Report generation steps.
 */
enum class GenerationStep {
    INITIALIZING,
    GATHERING_DATA,
    ANALYZING_VULNERABILITIES,
    GENERATING_SUMMARY,
    CREATING_RECOMMENDATIONS,
    FORMATTING_REPORT,
    SAVING_REPORT,
    COMPLETED,
}

/**
 * Export format enumeration.
 */
enum class ExportFormat {
    PDF,
    HTML,
    JSON,
    CSV,
    XML,
    MARKDOWN,
}

/**
 * Report template.
 */
data class ReportTemplate(
    val id: String,
    val name: String,
    val description: String?,
    val format: ExportFormat,
    val includeExecutiveSummary: Boolean,
    val includeVulnerabilities: Boolean,
    val includeFuzzingResults: Boolean,
    val includeKeyExtraction: Boolean,
    val includeRecommendations: Boolean,
    val includeAppendix: Boolean,
    val customCss: String? = null,
    val logoPath: String? = null,
    val isDefault: Boolean = false,
)

/**
 * Report statistics.
 */
data class ReportStatistics(
    val totalReports: Int,
    val reportsByStatus: Map<ReportStatus, Int>,
    val reportsByMonth: Map<String, Int>,
    val averageVulnerabilitiesPerReport: Double,
    val mostCommonSeverity: VulnerabilitySeverity,
    val dateRange: DateRange,
)

/**
 * Reports summary for dashboard.
 */
data class ReportsSummary(
    val totalReports: Int,
    val draftReports: Int,
    val finalReports: Int,
    val recentReports: List<SecurityReport>,
    val criticalVulnerabilitiesTotal: Int,
    val highVulnerabilitiesTotal: Int,
    val pendingActions: Int,
)

/**
 * Report operation log entry.
 */
data class ReportOperation(
    val id: String,
    val timestamp: java.time.Instant,
    val operationType: ReportOperationType,
    val reportId: String?,
    val success: Boolean,
    val errorMessage: String?,
    val durationMs: Long?,
    val metadata: Map<String, String> = emptyMap(),
)

/**
 * Report operation types.
 */
enum class ReportOperationType {
    GENERATE,
    SAVE,
    DELETE,
    ARCHIVE,
    EXPORT,
    SHARE,
    UPLOAD,
    TEMPLATE_CREATE,
    TEMPLATE_UPDATE,
    TEMPLATE_DELETE,
}
