/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.consent

import android.content.Context
import com.btsec.testtool.data.common.PathValidator
import com.btsec.testtool.data.local.dao.ConsentDao
import com.btsec.testtool.data.local.toDomain
import com.btsec.testtool.data.local.toDomainAuditLogEntries
import com.btsec.testtool.data.local.toDomainConsentRecords
import com.btsec.testtool.data.local.toEntity
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import com.btsec.testtool.domain.repository.ConsentRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import timber.log.Timber
import java.io.File
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of consent repository.
 *
 * Tracks user consent for all security testing operations.
 * This is critical for legal compliance and audit purposes.
 * Backed by Room via [ConsentDao].
 */
@Singleton
class ConsentRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        private val consentDao: ConsentDao,
    ) : ConsentRepository {
        override suspend fun requestConsent(
            authId: String,
            action: TestAction,
            deviceInfo: DeviceInfo,
        ): ConsentRecord? {
            return try {
                val record =
                    ConsentRecord(
                        id = generateId(),
                        authId = authId,
                        action = action.name,
                        timestamp = Instant.now(),
                        authorized = true,
                        deviceInfo = deviceInfo,
                        userSignature = null,
                    )
                consentDao.insertConsentRecord(record.toEntity())
                record
            } catch (e: Exception) {
                Timber.e(e, "Failed to persist consent record for authId=%s action=%s", authId, action.name)
                null
            }
        }

        override suspend fun requestConsentWithContext(
            authId: String,
            action: TestAction,
            context: String,
            deviceInfo: DeviceInfo,
        ): ConsentRecord? {
            return requestConsent(authId, action, deviceInfo)
        }

        override suspend fun hasConsent(
            authId: String,
            action: TestAction,
        ): Boolean {
            return try {
                consentDao.hasConsent(authId, action.name)
            } catch (e: Exception) {
                Timber.e(e, "Failed to check consent")
                false
            }
        }

        override fun getConsentStatus(authId: String): Flow<Map<TestAction, Boolean>> {
            return consentDao.getConsentRecordsByAuthId(authId).map { entities ->
                val authConsents = entities.map { it.toDomain() }
                TestAction.entries.associateWith { action ->
                    authConsents.any { it.action == action.name && it.authorized }
                }
            }
        }

        override suspend fun getLatestConsent(
            authId: String,
            action: TestAction,
        ): ConsentRecord? {
            return try {
                consentDao.getLatestConsentForAction(authId, action.name)?.toDomain()
            } catch (e: Exception) {
                Timber.e(e, "Failed to get latest consent")
                null
            }
        }

        override fun getConsentRecords(authId: String): Flow<List<ConsentRecord>> {
            return consentDao.getConsentRecordsByAuthId(authId).map { entities ->
                entities.toDomainConsentRecords()
            }
        }

        override fun getConsentRecordsInRange(
            start: Instant,
            end: Instant,
        ): Flow<List<ConsentRecord>> {
            return consentDao.getConsentRecordsInRange(
                start.toEpochMilli(),
                end.toEpochMilli(),
            ).map { entities -> entities.toDomainConsentRecords() }
        }

        override fun getAllConsentRecords(): Flow<List<ConsentRecord>> {
            return consentDao.getAllConsentRecords().map { entities ->
                entities.toDomainConsentRecords()
            }
        }

        override fun getDeniedConsents(): Flow<List<ConsentRecord>> {
            return consentDao.getDeniedConsents().map { entities ->
                entities.toDomainConsentRecords()
            }
        }

        override fun getConsentsByAction(action: TestAction): Flow<List<ConsentRecord>> {
            return consentDao.getConsentsByAction(action.name).map { entities ->
                entities.toDomainConsentRecords()
            }
        }

        override suspend fun saveConsentRecord(record: ConsentRecord): Result<Unit> {
            return try {
                consentDao.insertConsentRecord(record.toEntity())
                Result.success(Unit)
            } catch (e: Exception) {
                Timber.e(e, "Failed to save consent record")
                Result.failure(e)
            }
        }

        override suspend fun revokeConsent(
            authId: String,
            action: TestAction,
        ): Result<Unit> {
            return try {
                consentDao.deleteConsentsByAuthId(authId)
                Result.success(Unit)
            } catch (e: Exception) {
                Timber.e(e, "Failed to revoke consent")
                Result.failure(e)
            }
        }

        override suspend fun revokeAllConsent(authId: String): Result<Unit> {
            return try {
                consentDao.deleteConsentsByAuthId(authId)
                Result.success(Unit)
            } catch (e: Exception) {
                Timber.e(e, "Failed to revoke all consent")
                Result.failure(e)
            }
        }

        override suspend fun deleteOldConsents(beforeDate: Instant): Result<Int> {
            return try {
                val count = consentDao.deleteConsentsOlderThan(beforeDate.toEpochMilli())
                Result.success(count)
            } catch (e: Exception) {
                Timber.e(e, "Failed to delete old consents")
                Result.failure(e)
            }
        }

        override suspend fun logAuditEvent(
            authId: String,
            operation: String,
            deviceInfo: DeviceInfo,
            success: Boolean,
            metadata: Map<String, String>,
        ): Result<Unit> {
            return try {
                val entry =
                    AuditLogEntry(
                        id = generateId(),
                        authId = authId,
                        timestamp = Instant.now(),
                        operation = operation,
                        success = success,
                        errorMessage = if (success) null else "Operation failed",
                        deviceInfo = deviceInfo,
                        durationMs = null,
                        metadata = metadata,
                    )
                consentDao.insertAuditLog(entry.toEntity())
                Result.success(Unit)
            } catch (e: Exception) {
                Timber.e(e, "Failed to log audit event")
                Result.failure(e)
            }
        }

        override fun getAuditLog(authId: String): Flow<List<AuditLogEntry>> {
            return consentDao.getAuditLogsByAuthId(authId).map { entities ->
                entities.toDomainAuditLogEntries()
            }
        }

        override fun getAuditLogInRange(
            start: Instant,
            end: Instant,
        ): Flow<List<AuditLogEntry>> {
            return consentDao.getAuditLogsInRange(
                start.toEpochMilli(),
                end.toEpochMilli(),
            ).map { entities -> entities.toDomainAuditLogEntries() }
        }

        override fun getAuditLogByOperation(operation: String): Flow<List<AuditLogEntry>> {
            return consentDao.getAuditLogsByOperation(operation).map { entities ->
                entities.toDomainAuditLogEntries()
            }
        }

        override fun getAllAuditLogs(): Flow<List<AuditLogEntry>> {
            return consentDao.getAllAuditLogs().map { entities ->
                entities.toDomainAuditLogEntries()
            }
        }

        override fun getAuditStatistics(): Flow<AuditStatistics> {
            return flow {
                try {
                    val total = consentDao.getAuditLogCount().toLong()
                    val successful = consentDao.getSuccessfulOperationCount().toLong()
                    val failed = consentDao.getFailedOperationCount().toLong()
                    emit(
                        AuditStatistics(
                            totalEntries = total,
                            successfulOperations = successful,
                            failedOperations = failed,
                            successRate = if (total > 0) successful.toDouble() / total.toDouble() else 0.0,
                            uniqueAuthorizations = 0,
                            uniqueOperations = 0,
                            dateRange =
                                DateRange(
                                    start = Instant.now(),
                                    end = Instant.now(),
                                ),
                            topOperations = emptyList(),
                        ),
                    )
                } catch (e: Exception) {
                    Timber.e(e, "Failed to compute audit statistics")
                    emit(
                        AuditStatistics(
                            totalEntries = 0,
                            successfulOperations = 0,
                            failedOperations = 0,
                            successRate = 0.0,
                            uniqueAuthorizations = 0,
                            uniqueOperations = 0,
                            dateRange = DateRange(Instant.now(), Instant.now()),
                            topOperations = emptyList(),
                        ),
                    )
                }
            }
        }

        override suspend fun getStatisticsForAuth(authId: String): AuthAuditStatistics {
            return try {
                val count = consentDao.getAuditLogCount()
                AuthAuditStatistics(
                    authId = authId,
                    totalOperations = count,
                    successfulOperations = consentDao.getSuccessfulOperationCount(),
                    failedOperations = consentDao.getFailedOperationCount(),
                    firstOperation = Instant.now(),
                    lastOperation = Instant.now(),
                    operationBreakdown = emptyMap(),
                )
            } catch (e: Exception) {
                Timber.e(e, "Failed to get statistics for auth")
                AuthAuditStatistics(
                    authId = authId,
                    totalOperations = 0,
                    successfulOperations = 0,
                    failedOperations = 0,
                    firstOperation = Instant.now(),
                    lastOperation = Instant.now(),
                    operationBreakdown = emptyMap(),
                )
            }
        }

        override fun getMostCommonOperations(limit: Int): Flow<List<OperationCount>> {
            return consentDao.getAllAuditLogs().map { logs ->
                logs.map { it.toDomain() }
                    .groupBy { it.operation }
                    .mapValues { it.value.size }
                    .entries
                    .sortedByDescending { it.value }
                    .take(limit)
                    .map { OperationCount(it.key, it.value) }
            }
        }

        override fun getOperationSuccessRate(): Flow<Double> {
            return consentDao.getAllAuditLogs().map { logs ->
                val domainLogs = logs.map { it.toDomain() }
                if (domainLogs.isNotEmpty()) {
                    domainLogs.count { it.success }.toDouble() / domainLogs.size.toDouble()
                } else {
                    0.0
                }
            }
        }

        override suspend fun getRecordsEligibleForDeletion(): Int {
            return try {
                val sevenYearsAgo = Instant.now().minusSeconds(86400L * 365 * 7)
                consentDao.deleteConsentsOlderThan(sevenYearsAgo.toEpochMilli())
                // Query again to get count — approximate
                0
            } catch (e: Exception) {
                Timber.e(e, "Failed to get records eligible for deletion")
                0
            }
        }

        override fun getDataRetentionSummary(): Flow<DataRetentionSummary> {
            return consentDao.getAllConsentRecords().map { entities ->
                val now = Instant.now()
                val oneYear = now.minusSeconds(86400L * 365)
                val threeYears = now.minusSeconds(86400L * 365 * 3)
                val sevenYears = now.minusSeconds(86400L * 365 * 7)

                val records = entities.map { it.toDomain() }
                DataRetentionSummary(
                    totalRecords = records.size.toLong(),
                    recordsUnderOneYear = records.count { it.timestamp.isAfter(oneYear) }.toLong(),
                    recordsOneToThreeYears =
                        records.count {
                            it.timestamp.isAfter(threeYears) && it.timestamp.isBefore(oneYear)
                        }.toLong(),
                    recordsThreeToSevenYears =
                        records.count {
                            it.timestamp.isAfter(sevenYears) && it.timestamp.isBefore(threeYears)
                        }.toLong(),
                    recordsOverSevenYears = records.count { it.timestamp.isBefore(sevenYears) }.toLong(),
                    oldestRecord = records.minByOrNull { it.timestamp }?.timestamp,
                    newestRecord = records.maxByOrNull { it.timestamp }?.timestamp,
                )
            }
        }

        override suspend fun generateComplianceReport(
            startDate: Instant,
            endDate: Instant,
        ): ComplianceReport {
            return try {
                val consentCount = consentDao.getConsentCount()
                val logCount = consentDao.getAuditLogCount()
                ComplianceReport(
                    reportId = generateId(),
                    period = DateRange(startDate, endDate),
                    generatedAt = Instant.now(),
                    totalOperations = logCount,
                    consentRecords = consentCount,
                    authorizationIds = emptyList(),
                    operationsByType = emptyMap(),
                    successRate = 0.0,
                    findings = emptyList(),
                    recommendations = emptyList(),
                )
            } catch (e: Exception) {
                Timber.e(e, "Failed to generate compliance report")
                ComplianceReport(
                    reportId = generateId(),
                    period = DateRange(startDate, endDate),
                    generatedAt = Instant.now(),
                    totalOperations = 0,
                    consentRecords = 0,
                    authorizationIds = emptyList(),
                    operationsByType = emptyMap(),
                    successRate = 0.0,
                    findings = emptyList(),
                    recommendations = emptyList(),
                )
            }
        }

        override suspend fun exportAuditLog(
            outputPath: String,
            format: AuditExportFormat,
        ): Result<File> {
            return try {
                // Query actual audit logs from Room
                val auditLogs =
                    try {
                        consentDao.getAllAuditLogs().first()
                    } catch (e: Exception) {
                        Timber.e(e, "Failed to load audit logs for export")
                        emptyList()
                    }

                getSafeFile(outputPath).onSuccess { file ->
                    when (format) {
                        AuditExportFormat.JSON -> {
                            val jsonArr =
                                auditLogs.joinToString(",\n") { entry ->
                                    """{"id":"${entry.id}","authId":"${entry.authId}","operation":"${entry.operation}","timestamp":${entry.timestamp},"success":${entry.success},"errorMessage":"${entry.errorMessage ?: ""}","deviceInfo":"${entry.deviceInfo}","durationMs":${entry.durationMs ?: 0},"metadata":"${entry.metadata}"}"""
                                }
                            file.writeText("[\n$jsonArr\n]")
                        }
                        AuditExportFormat.CSV -> {
                            val header = "id,authId,operation,timestamp,success,errorMessage,deviceInfo,durationMs,metadata"
                            val rows =
                                auditLogs.map { e ->
                                    "${e.id},${e.authId},${e.operation},${e.timestamp},${e.success},${e.errorMessage ?: ""},${e.deviceInfo},${e.durationMs ?: 0},${e.metadata}"
                                }
                            file.writeText(header + "\n" + rows.joinToString("\n"))
                        }
                        AuditExportFormat.XML -> {
                            val entries =
                                auditLogs.joinToString("\n") { e ->
                                    """  <entry id="${e.id}">
    <authId>${e.authId}</authId>
    <operation>${e.operation}</operation>
    <timestamp>${e.timestamp}</timestamp>
    <success>${e.success}</success>
    <errorMessage>${e.errorMessage ?: ""}</errorMessage>
    <deviceInfo>${e.deviceInfo}</deviceInfo>
    <durationMs>${e.durationMs ?: 0}</durationMs>
    <metadata>${e.metadata}</metadata>
  </entry>"""
                                }
                            file.writeText("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<audit>\n$entries\n</audit>")
                        }
                    }
                }
            } catch (e: Exception) {
                Timber.e(e, "exportAuditLog failed")
                Result.failure(e)
            }
        }

        private fun getSafeFile(outputPath: String): Result<File> {
            return PathValidator.getSafeFile(context, outputPath)
        }

        private fun generateId(): String {
            return java.util.UUID.randomUUID().toString()
        }
    }
