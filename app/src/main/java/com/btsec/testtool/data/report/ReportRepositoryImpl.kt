/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.report

import android.content.Context
import android.net.Uri
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.DateRange
import com.btsec.testtool.domain.repository.ExportFormat
import com.btsec.testtool.domain.repository.GenerationStep
import com.btsec.testtool.domain.repository.ReportConfig
import com.btsec.testtool.domain.repository.ReportGenerationProgress
import com.btsec.testtool.domain.repository.ReportGenerationStatus
import com.btsec.testtool.domain.repository.ReportOperation
import com.btsec.testtool.domain.repository.ReportRepository
import com.btsec.testtool.domain.repository.ReportStatistics
import com.btsec.testtool.domain.repository.ReportTemplate
import com.btsec.testtool.domain.repository.ReportsSummary
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import java.io.File
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of report repository.
 *
 * Handles creation, storage, export, and sharing of security assessment reports.
 */
@Singleton
class ReportRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : ReportRepository {
        private val reports = MutableStateFlow<List<SecurityReport>>(emptyList())
        private val templates = MutableStateFlow<List<ReportTemplate>>(emptyList())
        private val logs = MutableStateFlow<List<ReportOperation>>(emptyList())

        override fun generateReport(
            authId: String,
            config: ReportConfig,
        ): Flow<ReportGenerationProgress> {
            return flow {
                val reportId = generateId()

                emit(
                    ReportGenerationProgress(
                        reportId = reportId,
                        status = ReportGenerationStatus.GENERATING,
                        currentStep = GenerationStep.INITIALIZING,
                        progressPercentage = 0,
                        estimatedCompletionTime = Instant.now().plusSeconds(30),
                        error = null,
                    ),
                )

                // Simulate report generation steps
                GenerationStep.entries.forEach { step ->
                    kotlinx.coroutines.delay(500)
                    emit(
                        ReportGenerationProgress(
                            reportId = reportId,
                            status = ReportGenerationStatus.GENERATING,
                            currentStep = step,
                            progressPercentage = 50,
                            estimatedCompletionTime = Instant.now().plusSeconds(15),
                            error = null,
                        ),
                    )
                }

                // Create mock report
                val report =
                    SecurityReport(
                        id = reportId,
                        authId = authId,
                        title = config.title,
                        generatedAt = Instant.now(),
                        testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
                        targetDevices = emptyList(),
                        vulnerabilities = emptyList(),
                        fuzzingResults = emptyList(),
                        keyExtractionResults = emptyList(),
                        executiveSummary = "Mock executive summary",
                        findings = emptyList(),
                        recommendations = emptyList(),
                        appendix =
                            ReportAppendix(
                                toolsUsed = listOf("BTSec Test Tool v1.0.0"),
                                testMethodology = "Standard Bluetooth security assessment",
                                limitations = emptyList(),
                                glossary = emptyMap(),
                                references = emptyList(),
                            ),
                        status = ReportStatus.DRAFT,
                    )

                saveReport(report)

                emit(
                    ReportGenerationProgress(
                        reportId = reportId,
                        status = ReportGenerationStatus.COMPLETED,
                        currentStep = GenerationStep.COMPLETED,
                        progressPercentage = 100,
                        estimatedCompletionTime = Instant.now(),
                        error = null,
                    ),
                )
            }
        }

        override suspend fun generateSummaryReport(
            authId: String,
            deviceAddress: String?,
        ): Result<SecurityReport> {
            val report =
                SecurityReport(
                    id = generateId(),
                    authId = authId,
                    title = "Security Assessment Summary",
                    generatedAt = Instant.now(),
                    testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
                    targetDevices = emptyList(),
                    vulnerabilities = emptyList(),
                    fuzzingResults = emptyList(),
                    keyExtractionResults = emptyList(),
                    executiveSummary = "Summary report",
                    findings = emptyList(),
                    recommendations = emptyList(),
                    appendix =
                        ReportAppendix(
                            toolsUsed = emptyList(),
                            testMethodology = "",
                            limitations = emptyList(),
                            glossary = emptyMap(),
                            references = emptyList(),
                        ),
                    status = ReportStatus.DRAFT,
                )
            return Result.success(report)
        }

        override suspend fun generateVulnerabilityReport(
            authId: String,
            vulnerabilities: List<Vulnerability>,
        ): Result<SecurityReport> {
            val report =
                SecurityReport(
                    id = generateId(),
                    authId = authId,
                    title = "Vulnerability Assessment Report",
                    generatedAt = Instant.now(),
                    testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
                    targetDevices = vulnerabilities.map { it.affectedDevice }.distinctBy { it.address },
                    vulnerabilities = vulnerabilities,
                    fuzzingResults = emptyList(),
                    keyExtractionResults = emptyList(),
                    executiveSummary = "Found ${vulnerabilities.size} vulnerabilities",
                    findings = emptyList(),
                    recommendations = emptyList(),
                    appendix =
                        ReportAppendix(
                            toolsUsed = emptyList(),
                            testMethodology = "",
                            limitations = emptyList(),
                            glossary = emptyMap(),
                            references = emptyList(),
                        ),
                    status = ReportStatus.DRAFT,
                )
            return Result.success(report)
        }

        override suspend fun generateFuzzingReport(
            authId: String,
            fuzzingResults: List<FuzzResult>,
        ): Result<SecurityReport> {
            val report =
                SecurityReport(
                    id = generateId(),
                    authId = authId,
                    title = "Fuzzing Test Report",
                    generatedAt = Instant.now(),
                    testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
                    targetDevices = fuzzingResults.map { it.config.targetDevice }.distinctBy { it.address },
                    vulnerabilities = emptyList(),
                    fuzzingResults = fuzzingResults,
                    keyExtractionResults = emptyList(),
                    executiveSummary = "Executed ${fuzzingResults.size} fuzzing tests",
                    findings = emptyList(),
                    recommendations = emptyList(),
                    appendix =
                        ReportAppendix(
                            toolsUsed = emptyList(),
                            testMethodology = "",
                            limitations = emptyList(),
                            glossary = emptyMap(),
                            references = emptyList(),
                        ),
                    status = ReportStatus.DRAFT,
                )
            return Result.success(report)
        }

        override suspend fun generateKeyExtractionReport(
            authId: String,
            extractionResults: List<KeyExtractionResult>,
        ): Result<SecurityReport> {
            val report =
                SecurityReport(
                    id = generateId(),
                    authId = authId,
                    title = "Key Extraction Report",
                    generatedAt = Instant.now(),
                    testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
                    targetDevices = extractionResults.map { it.targetDevice }.distinctBy { it.address },
                    vulnerabilities = emptyList(),
                    fuzzingResults = emptyList(),
                    keyExtractionResults = extractionResults,
                    executiveSummary = "Analyzed ${extractionResults.size} key extraction attempts",
                    findings = emptyList(),
                    recommendations = emptyList(),
                    appendix =
                        ReportAppendix(
                            toolsUsed = emptyList(),
                            testMethodology = "",
                            limitations = emptyList(),
                            glossary = emptyMap(),
                            references = emptyList(),
                        ),
                    status = ReportStatus.DRAFT,
                )
            return Result.success(report)
        }

        override suspend fun saveReport(report: SecurityReport): Result<Unit> {
            val current = reports.value.toMutableList()
            // Remove existing report with same ID
            current.removeAll { it.id == report.id }
            current.add(report)
            reports.value = current
            return Result.success(Unit)
        }

        override suspend fun getReportById(id: String): SecurityReport? {
            return reports.value.find { it.id == id }
        }

        override fun getAllReports(): Flow<List<SecurityReport>> {
            return reports
        }

        override fun getReportsByAuthId(authId: String): Flow<List<SecurityReport>> {
            return reports.map { it.filter { it.authId == authId } }
        }

        override fun getReportsByStatus(status: ReportStatus): Flow<List<SecurityReport>> {
            return reports.map { it.filter { it.status == status } }
        }

        override fun getReportsInRange(
            start: Instant,
            end: Instant,
        ): Flow<List<SecurityReport>> {
            return reports.map { it.filter { it.generatedAt in start..end } }
        }

        override suspend fun deleteReport(reportId: String): Result<Unit> {
            val updated = reports.value.filter { it.id != reportId }
            reports.value = updated
            return Result.success(Unit)
        }

        override suspend fun archiveReport(reportId: String): Result<Unit> {
            val updated =
                reports.value.map { report ->
                    if (report.id == reportId) {
                        report.copy(status = ReportStatus.ARCHIVED)
                    } else {
                        report
                    }
                }
            reports.value = updated
            return Result.success(Unit)
        }

        override suspend fun exportToPdf(
            reportId: String,
            outputPath: String,
        ): Result<File> {
            // In production, would generate actual PDF
            return getSafeFile(outputPath).onSuccess { file ->
                file.writeText("Mock PDF report: $reportId")
            }
        }

        override suspend fun exportToHtml(
            reportId: String,
            outputPath: String,
        ): Result<File> {
            return getSafeFile(outputPath).onSuccess { file ->
                file.writeText("<html><body>Mock HTML report: $reportId</body></html>")
            }
        }

        override suspend fun exportToJson(
            reportId: String,
            outputPath: String,
        ): Result<File> {
            return getSafeFile(outputPath).onSuccess { file ->
                file.writeText("{\"reportId\": \"$reportId\"}")
            }
        }

        override suspend fun exportToCsv(
            reportId: String,
            outputPath: String,
        ): Result<File> {
            return getSafeFile(outputPath).onSuccess { file ->
                file.writeText("report_id\n$reportId")
            }
        }

        override fun getAvailableExportFormats(): List<ExportFormat> {
            return listOf(
                ExportFormat.PDF,
                ExportFormat.HTML,
                ExportFormat.JSON,
                ExportFormat.CSV,
                ExportFormat.MARKDOWN,
            )
        }

        override suspend fun exportToMultipleFormats(
            reportId: String,
            outputDirectory: String,
            formats: List<ExportFormat>,
        ): Result<List<File>> {
            val results = mutableListOf<File>()
            formats.forEach { format ->
                val outputPath = "$outputDirectory/report_$reportId.${format.name.lowercase()}"
                when (format) {
                    ExportFormat.PDF -> exportToPdf(reportId, outputPath).getOrNull()?.let { results.add(it) }
                    ExportFormat.HTML -> exportToHtml(reportId, outputPath).getOrNull()?.let { results.add(it) }
                    ExportFormat.JSON -> exportToJson(reportId, outputPath).getOrNull()?.let { results.add(it) }
                    ExportFormat.CSV -> exportToCsv(reportId, outputPath).getOrNull()?.let { results.add(it) }
                    else -> {}
                }
            }
            return Result.success(results)
        }

        override suspend fun prepareReportForSharing(reportId: String): Result<Uri> {
            // In production, would create secure URI for file provider
            return Result.success(Uri.EMPTY)
        }

        override suspend fun shareReport(
            reportId: String,
            format: ExportFormat,
        ): Result<Unit> {
            // In production, would invoke Android share sheet
            return Result.success(Unit)
        }

        override suspend fun uploadReport(
            reportId: String,
            serverUrl: String,
            apiKey: String,
        ): Result<String> {
            // In production, would upload to server
            return Result.success("upload_id")
        }

        override fun getReportStatistics(): Flow<ReportStatistics> {
            return flow {
                val allReports = reports.value
                emit(
                    ReportStatistics(
                        totalReports = allReports.size,
                        reportsByStatus = allReports.groupBy { it.status }.mapValues { it.value.size },
                        reportsByMonth =
                            allReports.groupBy {
                                val instant = it.generatedAt
                                "${instant.toString().substring(0, 7)}" // YYYY-MM format
                            }.mapValues { it.value.size },
                        averageVulnerabilitiesPerReport = allReports.map { it.vulnerabilities.size }.average(),
                        mostCommonSeverity = VulnerabilitySeverity.MEDIUM,
                        dateRange =
                            DateRange(
                                start = allReports.minByOrNull { it.generatedAt }?.generatedAt ?: Instant.now(),
                                end = allReports.maxByOrNull { it.generatedAt }?.generatedAt ?: Instant.now(),
                            ),
                    ),
                )
            }
        }

        override fun getReportsSummary(): Flow<ReportsSummary> {
            return flow {
                val allReports = reports.value

                var draftCount = 0
                var finalCount = 0
                var criticalTotal = 0
                var highTotal = 0

                allReports.forEach { report ->
                    if (report.status == ReportStatus.DRAFT) draftCount++
                    if (report.status == ReportStatus.FINAL) finalCount++

                    report.vulnerabilities.forEach { vuln ->
                        if (vuln.severity == VulnerabilitySeverity.CRITICAL) criticalTotal++
                        if (vuln.severity == VulnerabilitySeverity.HIGH) highTotal++
                    }
                }

                emit(
                    ReportsSummary(
                        totalReports = allReports.size,
                        draftReports = draftCount,
                        finalReports = finalCount,
                        recentReports = allReports.take(5),
                        criticalVulnerabilitiesTotal = criticalTotal,
                        highVulnerabilitiesTotal = highTotal,
                        pendingActions = 0,
                    ),
                )
            }
        }

        override fun getAvailableTemplates(): Flow<List<ReportTemplate>> {
            return templates
        }

        override suspend fun getTemplate(templateId: String): ReportTemplate? {
            return templates.value.find { it.id == templateId }
        }

        override suspend fun createTemplate(template: ReportTemplate): Result<Unit> {
            val current = templates.value.toMutableList()
            current.add(template)
            templates.value = current
            return Result.success(Unit)
        }

        override suspend fun updateTemplate(template: ReportTemplate): Result<Unit> {
            val updated =
                templates.value.map { t ->
                    if (t.id == template.id) template else t
                }
            templates.value = updated
            return Result.success(Unit)
        }

        override suspend fun deleteTemplate(templateId: String): Result<Unit> {
            val updated = templates.value.filter { it.id != templateId }
            templates.value = updated
            return Result.success(Unit)
        }

        override suspend fun logReportOperation(operation: ReportOperation) {
            val current = logs.value.toMutableList()
            current.add(operation)
            logs.value = current
        }

        override fun getReportLogs(): Flow<List<ReportOperation>> {
            return logs
        }

        private fun getSafeFile(outputPath: String): Result<File> {
            val file = File(outputPath)
            return try {
                val canonicalPath = file.canonicalPath
                val allowedDirs =
                    listOfNotNull(
                        context.filesDir,
                        context.cacheDir,
                        File(System.getProperty("java.io.tmpdir")),
                        File("/tmp"),
                    ).map { it.canonicalPath }

                val isSafe =
                    allowedDirs.any { base ->
                        canonicalPath.startsWith(base + File.separator) || canonicalPath == base
                    }

                if (isSafe) {
                    Result.success(file)
                } else {
                    Result.failure(SecurityException("Invalid output path: Path traversal detected or path outside allowed directories"))
                }
            } catch (e: Exception) {
                Result.failure(SecurityException("Invalid output path", e))
            }
        }

        private fun generateId(): String {
            return java.util.UUID.randomUUID().toString()
        }
    }
