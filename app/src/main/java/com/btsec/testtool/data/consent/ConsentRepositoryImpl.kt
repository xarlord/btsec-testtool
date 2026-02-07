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
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.ConsentRepository
import com.btsec.testtool.domain.repository.*
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import java.io.Path
import java.nio.file.Paths
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of consent repository.
 *
 * Tracks user consent for all security testing operations.
 * This is critical for legal compliance and audit purposes.
 */
@Singleton
class ConsentRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context
) : ConsentRepository {

    private val consentRecords = MutableStateFlow<List<ConsentRecord>>(emptyList())
    private val auditLogs = MutableStateFlow<List<AuditLogEntry>>(emptyList())

    override suspend fun requestConsent(
        authId: String,
        action: TestAction,
        deviceInfo: DeviceInfo
    ): ConsentRecord? {
        // In production, would show consent dialog to user
        // For now, simulate consent grant
        val record = ConsentRecord(
            id = generateId(),
            authId = authId,
            action = action.name,
            timestamp = Instant.now(),
            authorized = true,
            deviceInfo = deviceInfo,
            userSignature = null
        )
        val current = consentRecords.value.toMutableList()
        current.add(record)
        consentRecords.value = current
        return record
    }

    override suspend fun requestConsentWithContext(
        authId: String,
        action: TestAction,
        context: String,
        deviceInfo: DeviceInfo
    ): ConsentRecord? {
        return requestConsent(authId, action, deviceInfo)
    }

    override suspend fun hasConsent(authId: String, action: TestAction): Boolean {
        return consentRecords.value.any {
            it.authId == authId && it.action == action.name && it.authorized
        }
    }

    override fun getConsentStatus(authId: String): Flow<Map<TestAction, Boolean>> {
        return flow {
            val authConsents = consentRecords.value.filter { it.authId == authId }
            val status = TestAction.entries.associateWith { action ->
                authConsents.any { it.action == action.name && it.authorized }
            }
            emit(status)
        }
    }

    override suspend fun getLatestConsent(authId: String, action: TestAction): ConsentRecord? {
        return consentRecords.value
            .filter { it.authId == authId && it.action == action.name }
            .maxByOrNull { it.timestamp }
    }

    override fun getConsentRecords(authId: String): Flow<List<ConsentRecord>> {
        return consentRecords.map { it.filter { record -> record.authId == authId } }
    }

    override fun getConsentRecordsInRange(
        start: Instant,
        end: Instant
    ): Flow<List<ConsentRecord>> {
        return consentRecords.map { it.filter { it.timestamp in start..end } }
    }

    override fun getAllConsentRecords(): Flow<List<ConsentRecord>> {
        return consentRecords
    }

    override fun getDeniedConsents(): Flow<List<ConsentRecord>> {
        return consentRecords.map { it.filter { !it.authorized } }
    }

    override fun getConsentsByAction(action: TestAction): Flow<List<ConsentRecord>> {
        return consentRecords.map { it.filter { it.action == action.name } }
    }

    override suspend fun saveConsentRecord(record: ConsentRecord): Result<Unit> {
        val current = consentRecords.value.toMutableList()
        current.add(record)
        consentRecords.value = current
        return Result.success(Unit)
    }

    override suspend fun revokeConsent(authId: String, action: TestAction): Result<Unit> {
        val updated = consentRecords.value.map { record ->
            if (record.authId == authId && record.action == action.name) {
                record.copy(authorized = false)
            } else {
                record
            }
        }
        consentRecords.value = updated
        return Result.success(Unit)
    }

    override suspend fun revokeAllConsent(authId: String): Result<Unit> {
        val updated = consentRecords.value.map { record ->
            if (record.authId == authId) {
                record.copy(authorized = false)
            } else {
                record
            }
        }
        consentRecords.value = updated
        return Result.success(Unit)
    }

    override suspend fun deleteOldConsents(beforeDate: Instant): Result<Int> {
        val filtered = consentRecords.value.filter { it.timestamp.isBefore(beforeDate) }
        val remaining = consentRecords.value.filter { !it.timestamp.isBefore(beforeDate) }
        consentRecords.value = remaining
        return Result.success(filtered.size)
    }

    override suspend fun logAuditEvent(
        authId: String,
        operation: String,
        deviceInfo: DeviceInfo,
        success: Boolean,
        metadata: Map<String, String>
    ): Result<Unit> {
        val entry = AuditLogEntry(
            id = generateId(),
            authId = authId,
            timestamp = Instant.now(),
            operation = operation,
            success = success,
            errorMessage = if (success) null else "Operation failed",
            deviceInfo = deviceInfo,
            durationMs = null,
            metadata = metadata
        )
        val current = auditLogs.value.toMutableList()
        current.add(entry)
        auditLogs.value = current
        return Result.success(Unit)
    }

    override fun getAuditLog(authId: String): Flow<List<AuditLogEntry>> {
        return auditLogs.map { it.filter { it.authId == authId } }
    }

    override fun getAuditLogInRange(start: Instant, end: Instant): Flow<List<AuditLogEntry>> {
        return auditLogs.map { it.filter { it.timestamp in start..end } }
    }

    override fun getAuditLogByOperation(operation: String): Flow<List<AuditLogEntry>> {
        return auditLogs.map { it.filter { it.operation == operation } }
    }

    override fun getAllAuditLogs(): Flow<List<AuditLogEntry>> {
        return auditLogs
    }

    override fun getAuditStatistics(): Flow<AuditStatistics> {
        return flow {
            val logs = auditLogs.value
            emit(AuditStatistics(
                totalEntries = logs.size.toLong(),
                successfulOperations = logs.count { it.success }.toLong(),
                failedOperations = logs.count { !it.success }.toLong(),
                successRate = if (logs.isNotEmpty()) {
                    logs.count { it.success }.toDouble() / logs.size.toDouble()
                } else 0.0,
                uniqueAuthorizations = logs.map { it.authId }.distinct().size,
                uniqueOperations = logs.map { it.operation }.distinct().size,
                dateRange = DateRange(
                    start = logs.minByOrNull { it.timestamp }?.timestamp ?: Instant.now(),
                    end = logs.maxByOrNull { it.timestamp }?.timestamp ?: Instant.now()
                ),
                topOperations = logs.groupBy { it.operation }
                    .mapValues { it.value.size }
                    .entries
                    .sortedByDescending { it.value }
                    .take(10)
                    .map { OperationCount(it.key, it.value) }
            ))
        }
    }

    override suspend fun getStatisticsForAuth(authId: String): AuthAuditStatistics {
        val logs = auditLogs.value.filter { it.authId == authId }
        return AuthAuditStatistics(
            authId = authId,
            totalOperations = logs.size,
            successfulOperations = logs.count { it.success },
            failedOperations = logs.count { !it.success },
            firstOperation = logs.minByOrNull { it.timestamp }?.timestamp ?: Instant.now(),
            lastOperation = logs.maxByOrNull { it.timestamp }?.timestamp ?: Instant.now(),
            operationBreakdown = logs.groupBy { it.operation }.mapValues { it.value.size }
        )
    }

    override fun getMostCommonOperations(limit: Int): Flow<List<OperationCount>> {
        return auditLogs.map { logs ->
            logs.groupBy { it.operation }
                .mapValues { it.value.size }
                .entries
                .sortedByDescending { it.value }
                .take(limit)
                .map { OperationCount(it.key, it.value) }
        }
    }

    override fun getOperationSuccessRate(): Flow<Double> {
        return auditLogs.map { logs ->
            if (logs.isNotEmpty()) {
                logs.count { it.success }.toDouble() / logs.size.toDouble()
            } else 0.0
        }
    }

    override suspend fun getRecordsEligibleForDeletion(): Int {
        val sevenYearsAgo = Instant.now().minusSeconds(86400 * 365 * 7)
        return consentRecords.value.count { it.timestamp.isBefore(sevenYearsAgo) }
    }

    override fun getDataRetentionSummary(): Flow<DataRetentionSummary> {
        return flow {
            val now = Instant.now()
            val oneYear = now.minusSeconds(86400 * 365)
            val threeYears = now.minusSeconds(86400 * 365 * 3)
            val sevenYears = now.minusSeconds(86400 * 365 * 7)

            val records = consentRecords.value
            emit(DataRetentionSummary(
                totalRecords = records.size.toLong(),
                recordsUnderOneYear = records.count { it.timestamp.isAfter(oneYear) }.toLong(),
                recordsOneToThreeYears = records.count {
                    it.timestamp.isAfter(threeYears) && it.timestamp.isBefore(oneYear)
                }.toLong(),
                recordsThreeToSevenYears = records.count {
                    it.timestamp.isAfter(sevenYears) && it.timestamp.isBefore(threeYears)
                }.toLong(),
                recordsOverSevenYears = records.count { it.timestamp.isBefore(sevenYears) }.toLong(),
                oldestRecord = records.minByOrNull { it.timestamp }?.timestamp,
                newestRecord = records.maxByOrNull { it.timestamp }?.timestamp
            ))
        }
    }

    override suspend fun generateComplianceReport(
        startDate: Instant,
        endDate: Instant
    ): ComplianceReport {
        val logs = auditLogs.value.filter { it.timestamp in startDate..endDate }
        return ComplianceReport(
            reportId = generateId(),
            period = DateRange(startDate, endDate),
            generatedAt = Instant.now(),
            totalOperations = logs.size,
            consentRecords = consentRecords.value.count { it.timestamp in startDate..endDate },
            authorizationIds = logs.map { it.authId }.distinct(),
            operationsByType = logs.groupBy { it.operation }.mapValues { it.value.size },
            successRate = if (logs.isNotEmpty()) {
                logs.count { it.success }.toDouble() / logs.size.toDouble()
            } else 0.0,
            findings = emptyList(),
            recommendations = emptyList()
        )
    }

    override suspend fun exportAuditLog(
        outputPath: String,
        format: AuditExportFormat
    ): Result<Path> {
        // In production, would write to file
        return Result.success(Paths.get(outputPath))
    }

    private fun generateId(): String {
        return java.util.UUID.randomUUID().toString()
    }
}
