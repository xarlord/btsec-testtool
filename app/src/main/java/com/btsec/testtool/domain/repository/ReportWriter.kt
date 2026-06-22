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
import kotlinx.coroutines.flow.Flow
import java.io.File

/**
 * Write/mutation interface for security assessment report operations.
 *
 * Provides methods to generate, save, delete, archive, export, share,
 * upload reports, and manage templates and audit logs.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only mutation/action operations, allowing components that only
 * need to create or modify reports to depend on a narrow contract.
 */
interface ReportWriter {
    /**
     * Generate a comprehensive security assessment report.
     *
     * @param authId Authorization ID for this report
     * @param config Report configuration
     * @return Flow of generation progress
     */
    fun generateReport(
        authId: String,
        config: ReportConfig,
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
        deviceAddress: String? = null,
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
        vulnerabilities: List<Vulnerability>,
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
        fuzzingResults: List<FuzzResult>,
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
        extractionResults: List<KeyExtractionResult>,
    ): Result<SecurityReport>

    /**
     * Save a generated report.
     */
    suspend fun saveReport(report: SecurityReport): Result<Unit>

    /**
     * Delete a report.
     */
    suspend fun deleteReport(reportId: String): Result<Unit>

    /**
     * Archive a report (move to archived status).
     */
    suspend fun archiveReport(reportId: String): Result<Unit>

    /**
     * Export a report to PDF format.
     *
     * @param reportId Report to export
     * @param outputPath Output file path
     * @return Exported file
     */
    suspend fun exportToPdf(
        reportId: String,
        outputPath: String,
    ): Result<File>

    /**
     * Export a report to HTML format.
     *
     * @param reportId Report to export
     * @param outputPath Output file path
     * @return Exported file
     */
    suspend fun exportToHtml(
        reportId: String,
        outputPath: String,
    ): Result<File>

    /**
     * Export a report to JSON format.
     *
     * @param reportId Report to export
     * @param outputPath Output file path
     * @return Exported file
     */
    suspend fun exportToJson(
        reportId: String,
        outputPath: String,
    ): Result<File>

    /**
     * Export a report to CSV format (findings only).
     *
     * @param reportId Report to export
     * @param outputPath Output file path
     * @return Exported file
     */
    suspend fun exportToCsv(
        reportId: String,
        outputPath: String,
    ): Result<File>

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
        formats: List<ExportFormat>,
    ): Result<List<File>>

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
    suspend fun shareReport(
        reportId: String,
        format: ExportFormat,
    ): Result<Unit>

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
        apiKey: String,
    ): Result<String>

    /**
     * Log a report operation for audit purposes.
     */
    suspend fun logReportOperation(operation: ReportOperation)
}
