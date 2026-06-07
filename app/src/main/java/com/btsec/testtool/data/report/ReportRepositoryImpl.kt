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
import com.btsec.testtool.data.common.PathValidator
import com.btsec.testtool.data.local.dao.BluetoothDao
import com.btsec.testtool.data.local.dao.FuzzingDao
import com.btsec.testtool.data.local.dao.KeyExtractionDao
import com.btsec.testtool.data.local.dao.ReportDao
import com.btsec.testtool.data.local.dao.VulnerabilityDao
import com.btsec.testtool.data.local.toDomain
import com.btsec.testtool.data.local.toDomainDevices
import com.btsec.testtool.data.local.toDomainFuzzResults
import com.btsec.testtool.data.local.toDomainKeyResults
import com.btsec.testtool.data.local.toDomainReports
import com.btsec.testtool.data.local.toDomainDefinitions
import com.btsec.testtool.data.local.toEntity
import kotlinx.coroutines.flow.first
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.ReportRepository
import com.btsec.testtool.domain.repository.VulnerabilityTestResult
import com.btsec.testtool.domain.repository.DetectionConfidence
import com.btsec.testtool.domain.repository.ReportTemplate
import com.btsec.testtool.domain.repository.ReportOperation
import com.btsec.testtool.domain.repository.ReportConfig
import com.btsec.testtool.domain.repository.ReportGenerationProgress
import com.btsec.testtool.domain.repository.ReportGenerationStatus
import com.btsec.testtool.domain.repository.GenerationStep
import com.btsec.testtool.domain.repository.ExportFormat
import com.btsec.testtool.domain.repository.ReportStatistics
import com.btsec.testtool.domain.repository.ReportsSummary
import com.btsec.testtool.domain.repository.DateRange
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import timber.log.Timber
import java.io.File
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of report repository.
 *
 * Handles creation, storage, export, and sharing of security assessment reports.
 * Report persistence is backed by Room via [ReportDao].
 */
@Singleton
class ReportRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context,
    private val reportDao: ReportDao,
    private val bluetoothDao: BluetoothDao,
    private val vulnerabilityDao: VulnerabilityDao,
    private val fuzzingDao: FuzzingDao,
    private val keyExtractionDao: KeyExtractionDao,
    private val reportGenerator: com.btsec.testtool.data.report.ReportGenerator,
    private val exportFormatters: com.btsec.testtool.data.report.ExportFormatters
) : ReportRepository {

    // In-memory stores for templates and logs (not Room-backed yet)
    private val templates = MutableStateFlow<List<ReportTemplate>>(emptyList())
    private val logs = MutableStateFlow<List<ReportOperation>>(emptyList())

    override fun generateReport(
        authId: String,
        config: ReportConfig
    ): Flow<ReportGenerationProgress> {
        return flow {
            val reportId = generateId()
            emitInitializing(reportId)
            emitProgressSteps(reportId)
            val report = buildReportFromData(authId, config, reportId)
            saveReport(report)
            emitCompleted(reportId)
        }
    }

    private suspend fun FlowCollector<ReportGenerationProgress>.emitInitializing(reportId: String) {
        emit(ReportGenerationProgress(
            reportId = reportId,
            status = ReportGenerationStatus.GENERATING,
            currentStep = GenerationStep.INITIALIZING,
            progressPercentage = 0,
            estimatedCompletionTime = Instant.now().plusSeconds(30),
            error = null
        ))
    }

    private suspend fun FlowCollector<ReportGenerationProgress>.emitProgressSteps(reportId: String) {
        GenerationStep.entries.forEachIndexed { index, step ->
            emit(ReportGenerationProgress(
                reportId = reportId,
                status = ReportGenerationStatus.GENERATING,
                currentStep = step,
                progressPercentage = ((index + 1) * 100 / GenerationStep.entries.size),
                estimatedCompletionTime = Instant.now().plusSeconds(15),
                error = null
            ))
        }
    }

    private suspend fun buildReportFromData(
        authId: String, config: ReportConfig, reportId: String
    ): SecurityReport {
        return try {
            val targetDevices = loadTargetDevices()
            val vulnResults = loadVulnerabilityResults()
            val fuzzResults = loadFuzzResults()
            val keyResults = loadKeyResults()

            reportGenerator.generateReport(
                authId = authId, config = config,
                targetDevices = targetDevices, vulnerabilityResults = vulnResults,
                fuzzingResults = fuzzResults, keyExtractionResults = keyResults
            )
        } catch (e: Exception) {
            Timber.e(e, "ReportGenerator failed, creating basic report")
            createFallbackReport(reportId, authId, config, e)
        }
    }

    private suspend fun loadTargetDevices(): List<BluetoothDevice> {
        return try {
            bluetoothDao.getAllDevices().first().toDomainDevices()
        } catch (e: Exception) {
            Timber.w(e, "Failed to load devices for report")
            emptyList()
        }
    }

    private suspend fun loadVulnerabilityResults(): List<VulnerabilityTestResult> {
        return try {
            vulnerabilityDao.getAllDefinitions().first().toDomainDefinitions().map { def ->
                VulnerabilityTestResult(
                    vulnerability = def, detected = false,
                    confidence = DetectionConfidence.LOW,
                    details = "Included from vulnerability definitions database",
                    evidence = emptyList(), timestamp = Instant.now()
                )
            }
        } catch (e: Exception) {
            Timber.w(e, "Failed to load vulnerabilities for report")
            emptyList()
        }
    }

    private suspend fun loadFuzzResults(): List<FuzzResult> {
        return try {
            fuzzingDao.getAllFuzzResults().first().toDomainFuzzResults()
        } catch (e: Exception) {
            Timber.w(e, "Failed to load fuzz results for report")
            emptyList()
        }
    }

    private suspend fun loadKeyResults(): List<KeyExtractionResult> {
        return try {
            keyExtractionDao.getAllKeyExtractionResults().first().toDomainKeyResults()
        } catch (e: Exception) {
            Timber.w(e, "Failed to load key extraction results for report")
            emptyList()
        }
    }

    private fun createFallbackReport(
        reportId: String, authId: String, config: ReportConfig, e: Exception
    ): SecurityReport {
        return SecurityReport(
            id = reportId, authId = authId, title = config.title,
            generatedAt = Instant.now(),
            testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
            targetDevices = emptyList(), vulnerabilities = emptyList(),
            fuzzingResults = emptyList(), keyExtractionResults = emptyList(),
            executiveSummary = "Report generation encountered an error: ${e.message}",
            findings = emptyList(), recommendations = emptyList(),
            appendix = ReportAppendix(
                toolsUsed = listOf("BTSec Test Tool v1.0.0"),
                testMethodology = "Standard Bluetooth security assessment",
                limitations = listOf("Report generator error: ${e.message}"),
                glossary = emptyMap(), references = emptyList()
            ),
            status = ReportStatus.DRAFT
        )
    }

    private suspend fun FlowCollector<ReportGenerationProgress>.emitCompleted(reportId: String) {
        emit(ReportGenerationProgress(
            reportId = reportId,
            status = ReportGenerationStatus.COMPLETED,
            currentStep = GenerationStep.COMPLETED,
            progressPercentage = 100,
            estimatedCompletionTime = Instant.now(),
            error = null
        ))
    }

    override suspend fun generateSummaryReport(
        authId: String,
        deviceAddress: String?
    ): Result<SecurityReport> {
        val report = SecurityReport(
            id = generateId(), authId = authId,
            title = "Security Assessment Summary",
            generatedAt = Instant.now(),
            testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
            targetDevices = emptyList(), vulnerabilities = emptyList(),
            fuzzingResults = emptyList(), keyExtractionResults = emptyList(),
            executiveSummary = "Summary report", findings = emptyList(),
            recommendations = emptyList(),
            appendix = ReportAppendix(emptyList(), "", emptyList(), emptyMap(), emptyList()),
            status = ReportStatus.DRAFT
        )
        return Result.success(report)
    }

    override suspend fun generateVulnerabilityReport(
        authId: String,
        vulnerabilities: List<Vulnerability>
    ): Result<SecurityReport> {
        val report = SecurityReport(
            id = generateId(), authId = authId,
            title = "Vulnerability Assessment Report",
            generatedAt = Instant.now(),
            testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
            targetDevices = vulnerabilities.map { it.affectedDevice }.distinctBy { it.address },
            vulnerabilities = vulnerabilities, fuzzingResults = emptyList(),
            keyExtractionResults = emptyList(),
            executiveSummary = "Found ${vulnerabilities.size} vulnerabilities",
            findings = emptyList(), recommendations = emptyList(),
            appendix = ReportAppendix(emptyList(), "", emptyList(), emptyMap(), emptyList()),
            status = ReportStatus.DRAFT
        )
        return Result.success(report)
    }

    override suspend fun generateFuzzingReport(
        authId: String,
        fuzzingResults: List<FuzzResult>
    ): Result<SecurityReport> {
        val report = SecurityReport(
            id = generateId(), authId = authId, title = "Fuzzing Test Report",
            generatedAt = Instant.now(),
            testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
            targetDevices = fuzzingResults.map { it.config.targetDevice }.distinctBy { it.address },
            vulnerabilities = emptyList(), fuzzingResults = fuzzingResults,
            keyExtractionResults = emptyList(),
            executiveSummary = "Executed ${fuzzingResults.size} fuzzing tests",
            findings = emptyList(), recommendations = emptyList(),
            appendix = ReportAppendix(emptyList(), "", emptyList(), emptyMap(), emptyList()),
            status = ReportStatus.DRAFT
        )
        return Result.success(report)
    }

    override suspend fun generateKeyExtractionReport(
        authId: String,
        extractionResults: List<KeyExtractionResult>
    ): Result<SecurityReport> {
        val report = SecurityReport(
            id = generateId(), authId = authId, title = "Key Extraction Report",
            generatedAt = Instant.now(),
            testPeriod = ReportPeriod(Instant.now().minusSeconds(86400), Instant.now()),
            targetDevices = extractionResults.map { it.targetDevice }.distinctBy { it.address },
            vulnerabilities = emptyList(), fuzzingResults = emptyList(),
            keyExtractionResults = extractionResults,
            executiveSummary = "Analyzed ${extractionResults.size} key extraction attempts",
            findings = emptyList(), recommendations = emptyList(),
            appendix = ReportAppendix(emptyList(), "", emptyList(), emptyMap(), emptyList()),
            status = ReportStatus.DRAFT
        )
        return Result.success(report)
    }

    override suspend fun saveReport(report: SecurityReport): Result<Unit> {
        return try {
            reportDao.insertReport(report.toEntity())
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to save report to Room")
            Result.failure(e)
        }
    }

    override suspend fun getReportById(id: String): SecurityReport? {
        return try { reportDao.getReportById(id)?.toDomain() }
        catch (e: Exception) { Timber.e(e, "Failed to get report by id"); null }
    }

    override fun getAllReports(): Flow<List<SecurityReport>> =
        reportDao.getAllReports().map { it.toDomainReports() }

    override fun getReportsByAuthId(authId: String): Flow<List<SecurityReport>> =
        reportDao.getReportsByAuthId(authId).map { it.toDomainReports() }

    override fun getReportsByStatus(status: ReportStatus): Flow<List<SecurityReport>> =
        reportDao.getReportsByStatus(status.name).map { it.toDomainReports() }

    override fun getReportsInRange(start: Instant, end: Instant): Flow<List<SecurityReport>> =
        reportDao.getReportsInRange(start.toEpochMilli(), end.toEpochMilli()).map { it.toDomainReports() }

    override suspend fun deleteReport(reportId: String): Result<Unit> = try {
        reportDao.deleteReportById(reportId); Result.success(Unit)
    } catch (e: Exception) { Timber.e(e, "Failed to delete report"); Result.failure(e) }

    override suspend fun archiveReport(reportId: String): Result<Unit> = try {
        reportDao.updateReportStatus(reportId, ReportStatus.ARCHIVED.name); Result.success(Unit)
    } catch (e: Exception) { Timber.e(e, "Failed to archive report"); Result.failure(e) }

    override suspend fun exportToPdf(reportId: String, outputPath: String): Result<File> = try {
        val report = reportDao.getReportById(reportId) ?: return Result.failure(Exception("Report not found"))
        val html = exportFormatters.toHtml(report.toDomain())
        getSafeFile(outputPath).onSuccess { it.writeText(html) }
    } catch (e: Exception) { Timber.e(e, "exportToPdf failed"); Result.failure(e) }

    override suspend fun exportToHtml(reportId: String, outputPath: String): Result<File> = try {
        val report = reportDao.getReportById(reportId) ?: return Result.failure(Exception("Report not found"))
        val html = exportFormatters.toHtml(report.toDomain())
        getSafeFile(outputPath).onSuccess { it.writeText(html) }
    } catch (e: Exception) { Timber.e(e, "exportToHtml failed"); Result.failure(e) }

    override suspend fun exportToJson(reportId: String, outputPath: String): Result<File> = try {
        val report = reportDao.getReportById(reportId) ?: return Result.failure(Exception("Report not found"))
        val json = exportFormatters.toJson(report.toDomain())
        getSafeFile(outputPath).onSuccess { it.writeText(json) }
    } catch (e: Exception) { Timber.e(e, "exportToJson failed"); Result.failure(e) }

    override suspend fun exportToCsv(reportId: String, outputPath: String): Result<File> = try {
        val report = reportDao.getReportById(reportId) ?: return Result.failure(Exception("Report not found"))
        val csv = exportFormatters.toCsv(report.toDomain())
        getSafeFile(outputPath).onSuccess { it.writeText(csv) }
    } catch (e: Exception) { Timber.e(e, "exportToCsv failed"); Result.failure(e) }

    override fun getAvailableExportFormats(): List<ExportFormat> =
        listOf(ExportFormat.PDF, ExportFormat.HTML, ExportFormat.JSON, ExportFormat.CSV, ExportFormat.MARKDOWN)

    override suspend fun exportToMultipleFormats(
        reportId: String, outputDirectory: String, formats: List<ExportFormat>
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

    override suspend fun prepareReportForSharing(reportId: String): Result<Uri> = try {
        val report = reportDao.getReportById(reportId) ?: return Result.failure(Exception("Report not found"))
        val exportDir = File(context.cacheDir, "shared_reports").apply { mkdirs() }
        val htmlFile = File(exportDir, "report_$reportId.html")
        htmlFile.writeText(exportFormatters.toHtml(report.toDomain()))
        val uri = androidx.core.content.FileProvider.getUriForFile(
            context, "${context.packageName}.fileprovider", htmlFile
        )
        Result.success(uri)
    } catch (e: Exception) { Timber.e(e, "prepareReportForSharing failed"); Result.failure(e) }

    override suspend fun shareReport(reportId: String, format: ExportFormat): Result<Unit> =
        Result.success(Unit)

    /**
     * Upload a report to a remote server.
     *
     * Security notes (Issue #231):
     * - [apiKey] is NEVER logged in any form (redacted in all log statements).
     * - [apiKey] is transmitted ONLY via the Authorization HTTP header — never in URL query params.
     * - [apiKey] is NOT stored in any persistent storage.
     * - Error messages NEVER include the API key or any portion of it.
     */
    override suspend fun uploadReport(reportId: String, serverUrl: String, apiKey: String): Result<String> {
        // Security: apiKey must never appear in logs or error messages
        if (reportId.isBlank()) {
            return Result.failure(Exception("Invalid report ID"))
        }
        if (serverUrl.isBlank()) {
            return Result.failure(Exception("Invalid server URL"))
        }
        if (apiKey.isBlank()) {
            Timber.w("uploadReport: authentication credential missing for report %s", reportId)
            return Result.failure(Exception("Authentication failed"))
        }

        return try {
            // TODO: Replace stub with actual HTTP call. When implementing:
            // - Pass apiKey ONLY in the "Authorization: Bearer <apiKey>" header
            // - NEVER append apiKey as a URL query parameter
            // - NEVER log apiKey at any level (debug, info, error)
            // - NEVER store apiKey in SharedPreferences, Room, or any other storage
            // - If persistent storage is needed, use EncryptedSharedPreferences
            Timber.d("uploadReport: uploading report %s to server", reportId)
            Result.success("upload_id")
        } catch (e: Exception) {
            // Security: ensure apiKey is never included in error messages or crash reports
            Timber.e(e, "uploadReport: failed to upload report %s", reportId)
            Result.failure(Exception("Upload failed for report $reportId"))
        }
    }

    override fun getReportStatistics(): Flow<ReportStatistics> =
        reportDao.getAllReports().map { entities ->
            val allReports = entities.toDomainReports()
            ReportStatistics(
                totalReports = allReports.size,
                reportsByStatus = allReports.groupBy { it.status }.mapValues { it.value.size },
                reportsByMonth = allReports.groupBy { it.generatedAt.toString().substring(0, 7) }
                    .mapValues { it.value.size },
                averageVulnerabilitiesPerReport = allReports.map { it.vulnerabilities.size }.average(),
                mostCommonSeverity = VulnerabilitySeverity.MEDIUM,
                dateRange = DateRange(
                    start = allReports.minByOrNull { it.generatedAt }?.generatedAt ?: Instant.now(),
                    end = allReports.maxByOrNull { it.generatedAt }?.generatedAt ?: Instant.now()
                )
            )
        }

    override fun getReportsSummary(): Flow<ReportsSummary> =
        reportDao.getAllReports().map { entities ->
            val allReports = entities.toDomainReports()
            ReportsSummary(
                totalReports = allReports.size,
                draftReports = allReports.count { it.status == ReportStatus.DRAFT },
                finalReports = allReports.count { it.status == ReportStatus.FINAL },
                recentReports = allReports.take(5),
                criticalVulnerabilitiesTotal = allReports.sumOf {
                    it.vulnerabilities.count { it.severity == VulnerabilitySeverity.CRITICAL }
                },
                highVulnerabilitiesTotal = allReports.sumOf {
                    it.vulnerabilities.count { it.severity == VulnerabilitySeverity.HIGH }
                },
                pendingActions = 0
            )
        }

    override fun getAvailableTemplates(): Flow<List<ReportTemplate>> = templates

    override suspend fun getTemplate(templateId: String): ReportTemplate? =
        templates.value.find { it.id == templateId }

    override suspend fun createTemplate(template: ReportTemplate): Result<Unit> {
        templates.value = templates.value.toMutableList().apply { add(template) }
        return Result.success(Unit)
    }

    override suspend fun updateTemplate(template: ReportTemplate): Result<Unit> {
        templates.value = templates.value.map { if (it.id == template.id) template else it }
        return Result.success(Unit)
    }

    override suspend fun deleteTemplate(templateId: String): Result<Unit> {
        templates.value = templates.value.filter { it.id != templateId }
        return Result.success(Unit)
    }

    override suspend fun logReportOperation(operation: ReportOperation) {
        logs.value = logs.value.toMutableList().apply { add(operation) }
    }

    override fun getReportLogs(): Flow<List<ReportOperation>> = logs

    private fun getSafeFile(outputPath: String): Result<File> =
        PathValidator.getSafeFile(context, outputPath)

    private fun generateId(): String = java.util.UUID.randomUUID().toString()
}
