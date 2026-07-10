/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.File
import javax.inject.Inject

/**
 * Use case for security report generation and management.
 *
 * Handles creation, storage, export, and sharing of security assessment reports.
 */
class ReportGenerationUseCase
    @Inject
    constructor(
        private val reportRepository: ReportRepository,
        private val vulnerabilityRepository: VulnerabilityRepository,
        private val fuzzingRepository: FuzzingRepository,
        private val keyExtractionRepository: KeyExtractionRepository,
    ) {
        /**
         * Generate a comprehensive security assessment report.
         *
         * @param config Report configuration
         * @return Result of report generation
         */
        suspend fun generateReport(config: ReportConfig): ReportGenerationResult {
            // Generate report directly — no authorization gating
            val authId = "local"
            reportRepository.generateReport(authId, config)
            return ReportGenerationResult.Started(authId)
        }

        /**
         * Generate a quick summary report.
         *
         * @param deviceAddress Optional device address
         * @return Generated report or error
         */
        suspend fun generateSummaryReport(deviceAddress: String? = null): Result<SecurityReport> {
            return reportRepository.generateSummaryReport("local", deviceAddress)
        }

        /**
         * Generate a vulnerability-focused report.
         *
         * @return Generated report or error
         */
        suspend fun generateVulnerabilityReport(): Result<SecurityReport> {
            val vulnerabilities = vulnerabilityRepository.getAllDiscoveredVulnerabilities().first()

            return reportRepository.generateVulnerabilityReport("local", vulnerabilities)
        }

        /**
         * Generate a fuzzing test report.
         *
         * @return Generated report or error
         */
        suspend fun generateFuzzingReport(): Result<SecurityReport> {
            val fuzzingResults = fuzzingRepository.getAllFuzzingResults().first()

            return reportRepository.generateFuzzingReport("local", fuzzingResults)
        }

        /**
         * Get report generation progress.
         */
        fun getReportGenerationProgress(reportId: String): Flow<ReportGenerationProgress?> {
            // This would be implemented to track progress for a specific report
            return reportRepository.getReportsByAuthId("").map { null }
        }

        /**
         * Get all reports.
         */
        fun getAllReports(): Flow<List<SecurityReport>> {
            return reportRepository.getAllReports()
        }

        /**
         * Get reports by authorization ID.
         */
        fun getReportsByAuthId(authId: String): Flow<List<SecurityReport>> {
            return reportRepository.getReportsByAuthId(authId)
        }

        /**
         * Get reports by status.
         */
        fun getReportsByStatus(status: ReportStatus): Flow<List<SecurityReport>> {
            return reportRepository.getReportsByStatus(status)
        }

        /**
         * Get a specific report by ID.
         */
        suspend fun getReportById(reportId: String): SecurityReport? {
            return reportRepository.getReportById(reportId)
        }

        /**
         * Delete a report.
         */
        suspend fun deleteReport(reportId: String): Result<Unit> {
            return reportRepository.deleteReport(reportId)
        }

        /**
         * Archive a report.
         */
        suspend fun archiveReport(reportId: String): Result<Unit> {
            return reportRepository.archiveReport(reportId)
        }

        /**
         * Export a report to PDF.
         */
        suspend fun exportToPdf(
            reportId: String,
            outputPath: String,
        ): Result<File> {
            return reportRepository.exportToPdf(reportId, outputPath)
        }

        /**
         * Export a report to HTML.
         */
        suspend fun exportToHtml(
            reportId: String,
            outputPath: String,
        ): Result<File> {
            return reportRepository.exportToHtml(reportId, outputPath)
        }

        /**
         * Export a report to JSON.
         */
        suspend fun exportToJson(
            reportId: String,
            outputPath: String,
        ): Result<File> {
            return reportRepository.exportToJson(reportId, outputPath)
        }

        /**
         * Export a report to CSV.
         */
        suspend fun exportToCsv(
            reportId: String,
            outputPath: String,
        ): Result<File> {
            return reportRepository.exportToCsv(reportId, outputPath)
        }

        /**
         * Get available export formats.
         */
        fun getAvailableExportFormats(): List<ExportFormat> {
            return reportRepository.getAvailableExportFormats()
        }

        /**
         * Export to multiple formats at once.
         */
        suspend fun exportToMultipleFormats(
            reportId: String,
            outputDirectory: String,
            formats: List<ExportFormat>,
        ): Result<List<File>> {
            return reportRepository.exportToMultipleFormats(reportId, outputDirectory, formats)
        }

        /**
         * Share a report via Android share sheet.
         */
        suspend fun shareReport(
            reportId: String,
            format: ExportFormat,
        ): Result<Unit> {
            return reportRepository.shareReport(reportId, format)
        }

        /**
         * Upload a report to a remote server.
         */
        suspend fun uploadReport(
            reportId: String,
            serverUrl: String,
            apiKey: String,
        ): Result<String> {
            return reportRepository.uploadReport(reportId, serverUrl, apiKey)
        }

        /**
         * Get report statistics.
         */
        fun getReportStatistics(): Flow<ReportStatistics> {
            return reportRepository.getReportStatistics()
        }

        /**
         * Get reports summary for dashboard.
         */
        fun getReportsSummary(): Flow<ReportsSummary> {
            return reportRepository.getReportsSummary()
        }

        /**
         * Get available report templates.
         */
        fun getAvailableTemplates(): Flow<List<ReportTemplate>> {
            return reportRepository.getAvailableTemplates()
        }

        /**
         * Create a custom report template.
         */
        suspend fun createTemplate(template: ReportTemplate): Result<Unit> {
            return reportRepository.createTemplate(template)
        }

        /**
         * Update a report template.
         */
        suspend fun updateTemplate(template: ReportTemplate): Result<Unit> {
            return reportRepository.updateTemplate(template)
        }

        /**
         * Delete a report template.
         */
        suspend fun deleteTemplate(templateId: String): Result<Unit> {
            return reportRepository.deleteTemplate(templateId)
        }

        /**
         * Create default report configuration.
         */
        fun createDefaultConfig(): ReportConfig {
            return ReportConfig(
                title = "Bluetooth Security Assessment Report",
                includeVulnerabilities = true,
                includeFuzzingResults = true,
                includeKeyExtraction = true,
                includePacketCaptures = false,
                includeExecutiveSummary = true,
                includeRecommendations = true,
                includeAppendix = true,
                templateId = null,
                customSections = emptyList(),
                minSeverity = VulnerabilitySeverity.LOW,
            )
        }

        /**
         * Create minimal report configuration.
         */
        fun createMinimalConfig(): ReportConfig {
            return ReportConfig(
                title = "Security Assessment Summary",
                includeVulnerabilities = true,
                includeFuzzingResults = false,
                includeKeyExtraction = false,
                includePacketCaptures = false,
                includeExecutiveSummary = true,
                includeRecommendations = true,
                includeAppendix = false,
                templateId = null,
                customSections = emptyList(),
                minSeverity = VulnerabilitySeverity.HIGH,
            )
        }

        /**
         * Create comprehensive report configuration.
         */
        fun createComprehensiveConfig(): ReportConfig {
            return ReportConfig(
                title = "Comprehensive Bluetooth Security Assessment",
                includeVulnerabilities = true,
                includeFuzzingResults = true,
                includeKeyExtraction = true,
                includePacketCaptures = true,
                includeExecutiveSummary = true,
                includeRecommendations = true,
                includeAppendix = true,
                templateId = null,
                customSections = emptyList(),
                minSeverity = VulnerabilitySeverity.NONE,
            )
        }

        /**
         * Get report dashboard data.
         */
        suspend fun getReportDashboardData(): ReportDashboardData {
            val summary = reportRepository.getReportsSummary().first()
            val stats = reportRepository.getReportStatistics().first()
            val recentReports = reportRepository.getAllReports().first().take(5)

            return ReportDashboardData(
                totalReports = summary.totalReports,
                draftReports = summary.draftReports,
                finalReports = summary.finalReports,
                criticalVulnerabilities = summary.criticalVulnerabilitiesTotal,
                highVulnerabilities = summary.highVulnerabilitiesTotal,
                pendingActions = summary.pendingActions,
                recentReports = recentReports,
                reportsByMonth = stats.reportsByMonth,
                averageVulnerabilities = stats.averageVulnerabilitiesPerReport,
            )
        }

        private fun getDeviceInfo(): DeviceInfo {
            return DeviceInfo(
                platform = android.os.Build.MANUFACTURER,
                model = android.os.Build.MODEL,
                androidVersion = android.os.Build.VERSION.RELEASE,
                appVersion = "1.0.0",
                bluetoothAddress = "TESTING",
            )
        }
    }

/**
 * Result of report generation request.
 */
sealed class ReportGenerationResult {
    data class Started(val authId: String) : ReportGenerationResult()

    data class Error(val message: String) : ReportGenerationResult()
}

/**
 * Report dashboard data.
 */
data class ReportDashboardData(
    val totalReports: Int,
    val draftReports: Int,
    val finalReports: Int,
    val criticalVulnerabilities: Int,
    val highVulnerabilities: Int,
    val pendingActions: Int,
    val recentReports: List<SecurityReport>,
    val reportsByMonth: Map<String, Int>,
    val averageVulnerabilities: Double,
)
