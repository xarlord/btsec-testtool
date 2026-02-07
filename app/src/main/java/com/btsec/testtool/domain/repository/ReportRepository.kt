/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.Flow
import java.io.File

/**
 * Repository for security assessment report generation and management.
 *
 * Handles creation, storage, and export of security assessment reports.
 * All reports are tied to an authorization ID for audit purposes.
 */
interface ReportRepository {

    // ========== Report Generation ==========

    /**
     * Generate a comprehensive security assessment report.
     *
     * @param authId Authorization ID for this report
     * @param config Report configuration
     * @return Flow of generation progress
     */
    fun generateReport(
        authId: String,
        config: ReportConfig
    ): Flow<ReportGenerationProgress>

    /**
     * Generate a quick summary report.
     *
     * @param authId Authorization ID
     * @param deviceAddress Optional device address (null for all devices)
     * @return Generated report
     */
    suspend fun generateSummaryReport(
        authId: String,
        deviceAddress: String? = null
    ): Result<SecurityReport>

    /**
     * Generate a detailed vulnerability report.
     *
     * @param authId Authorization ID
     * @param vulnerabilities Specific vulnerabilities to include
     * @return Generated report
     */
    suspend fun generateVulnerabilityReport(
        authId: String,
        vulnerabilities: List<Vulnerability>
    ): Result<SecurityReport>

    /**
     * Generate a fuzzing test report.
     *
     * @param authId Authorization ID
     * @param fuzzingResults Fuzzing results to include
     * @return Generated report
     */
    suspend fun generateFuzzingReport(
        authId: String,
        fuzzingResults: List<FuzzResult>
    ): Result<SecurityReport>

    /**
     * Generate a key extraction report.
     *
     * @param authId Authorization ID
     * @param extractionResults Key extraction results
     * @return Generated report
     */
    suspend fun generateKeyExtractionReport(
        authId: String,
        extractionResults: List<KeyExtractionResult>
    ): Result<SecurityReport>

    // ========== Report Storage ==========

    /**
     * Save a generated report.
     */
    suspend fun saveReport(report: SecurityReport): Result<Unit>

    /**
     * Get a report by ID.
     */
    suspend fun getReportById(id: String): SecurityReport?

    /**
     * Get all reports.
     */
    fun getAllReports(): Flow<List<SecurityReport>>

    /**
     * Get reports by authorization ID.
     */
    fun getReportsByAuthId(authId: String): Flow<List<SecurityReport>>

    /**
     * Get reports by status.
     */
    fun getReportsByStatus(status: ReportStatus): Flow<List<SecurityReport>>

    /**
     * Get reports within a date range.
     */
    fun getReportsInRange(start: java.time.Instant, end: java.time.Instant): Flow<List<SecurityReport>>

    /**
     * Delete a report.
     */
    suspend fun deleteReport(reportId: String): Result<Unit>

    /**
     * Archive a report (move to archived status).
     */
    suspend fun archiveReport(reportId: String): Result<Unit>

    // ========== Report Export ==========

    /**
     * Export a report to PDF format.
     *
     * @param reportId Report to export
     * @param outputPath Output file path
     * @return Exported file
     */
    suspend fun exportToPdf(reportId: String, outputPath: String): Result<File>

    /**
     * Export a report to HTML format.
     *
     * @param reportId Report to export
     * @param outputPath Output file path
     * @return Exported file
     */
    suspend fun exportToHtml(reportId: String, outputPath: String): Result<File>

    /**
     * Export a report to JSON format.
     *
     * @param reportId Report to export
     * @param outputPath Output file path
     * @return Exported file
     */
    suspend fun exportToJson(reportId: String, outputPath: String): Result<File>

    /**
     * Export a report to CSV format (findings only).
     *
     * @param reportId Report to export
     * @param outputPath Output file path
     * @return Exported file
     */
    suspend fun exportToCsv(reportId: String, outputPath: String): Result<File>

    /**
     * Get available export formats.
     */
    fun getAvailableExportFormats(): List<ExportFormat>

    /**
     * Export to multiple formats at once.
     *
     * @param reportId Report to export
     * @param outputDirectory Output directory
     * @param formats Formats to export
     * @return List of exported files
     */
    suspend fun exportToMultipleFormats(
        reportId: String,
        outputDirectory: String,
        formats: List<ExportFormat>
    ): Result<List<File>>

    // ========== Report Templates ==========

    /**
     * Get available report templates.
     */
    fun getAvailableTemplates(): Flow<List<ReportTemplate>>

    /**
     * Get a specific template by ID.
     */
    suspend fun getTemplate(templateId: String): ReportTemplate?

    /**
     * Create a custom report template.
     */
    suspend fun createTemplate(template: ReportTemplate): Result<Unit>

    /**
     * Update a report template.
     */
    suspend fun updateTemplate(template: ReportTemplate): Result<Unit>

    /**
     * Delete a report template.
     */
    suspend fun deleteTemplate(templateId: String): Result<Unit>

    // ========== Report Sharing ==========

    /**
     * Prepare a report for sharing.
     *
     * Encrypts and packages the report for secure sharing.
     *
     * @param reportId Report to share
     * @return URI for sharing
     */
    suspend fun prepareReportForSharing(reportId: String): Result<android.net.Uri>

    /**
     * Share a report via Android share sheet.
     *
     * @param reportId Report to share
     * @param format Export format
     */
    suspend fun shareReport(reportId: String, format: ExportFormat): Result<Unit>

    /**
     * Upload a report to a remote server.
     *
     * @param reportId Report to upload
     * @param serverUrl Server URL
     * @param apiKey API key for authentication
     */
    suspend fun uploadReport(
        reportId: String,
        serverUrl: String,
        apiKey: String
    ): Result<String>

    // ========== Report Statistics ==========

    /**
     * Get report generation statistics.
     */
    fun getReportStatistics(): Flow<ReportStatistics>

    /**
     * Get reports summary for dashboard.
     */
    fun getReportsSummary(): Flow<ReportsSummary>

    // ========== Logging ==========

    /**
     * Log a report operation for audit purposes.
     */
    suspend fun logReportOperation(operation: ReportOperation)

    /**
     * Get report operation logs.
     */
    fun getReportLogs(): Flow<List<ReportOperation>>
}

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
    val minSeverity: VulnerabilitySeverity = VulnerabilitySeverity.LOW
)

/**
 * Custom report section.
 */
data class CustomReportSection(
    val title: String,
    val content: String,
    val order: Int
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
    val error: String? = null
)

/**
 * Report generation status.
 */
enum class ReportGenerationStatus {
    PENDING,
    GENERATING,
    COMPLETED,
    FAILED,
    CANCELLED
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
    COMPLETED
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
    MARKDOWN
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
    val isDefault: Boolean = false
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
    val dateRange: DateRange
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
    val pendingActions: Int
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
    val metadata: Map<String, String> = emptyMap()
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
    TEMPLATE_DELETE
}
