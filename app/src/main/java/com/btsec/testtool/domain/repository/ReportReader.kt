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

/**
 * Read-only interface for security assessment report queries.
 *
 * Provides methods to retrieve, search, and observe reports, templates,
 * export formats, statistics, and audit logs without mutating state.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only read/observation operations, allowing dashboard and
 * analytics components to depend on a narrow, query-only contract.
 */
interface ReportReader {

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
     * Get available export formats.
     */
    fun getAvailableExportFormats(): List<ExportFormat>

    /**
     * Get available report templates.
     */
    fun getAvailableTemplates(): Flow<List<ReportTemplate>>

    /**
     * Get a specific template by ID.
     */
    suspend fun getTemplate(templateId: String): ReportTemplate?

    /**
     * Get report generation statistics.
     */
    fun getReportStatistics(): Flow<ReportStatistics>

    /**
     * Get reports summary for dashboard.
     */
    fun getReportsSummary(): Flow<ReportsSummary>

    /**
     * Get report operation logs.
     */
    fun getReportLogs(): Flow<List<ReportOperation>>
}
