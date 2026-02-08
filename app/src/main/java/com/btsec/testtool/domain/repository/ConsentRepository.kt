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

/**
 * Repository for consent tracking and audit logging.
 *
 * Tracks user consent for all security testing operations.
 * This is critical for legal compliance and audit purposes.
 *
 * All testing operations require explicit user consent that is:
 * 1. Specific to the action being performed
 * 2. Time-stamped
 * 3. Linked to the authorization ID
 * 4. Stored for 7 years (audit requirement)
 * 5. Tamper-evident
 */
interface ConsentRepository {

    // ========== Consent Management ==========

    /**
     * Request user consent for a specific action.
     *
     * @param authId Current authorization ID
     * @param action Action requiring consent
     * @param deviceInfo Device information for logging
     * @return Consent record if granted, null if denied
     */
    suspend fun requestConsent(
        authId: String,
        action: TestAction,
        deviceInfo: DeviceInfo
    ): ConsentRecord?

    /**
     * Request consent with additional context.
     *
     * @param authId Current authorization ID
     * @param action Action requiring consent
     * @param context Additional context about the action
     * @param deviceInfo Device information for logging
     * @return Consent record if granted, null if denied
     */
    suspend fun requestConsentWithContext(
        authId: String,
        action: TestAction,
        context: String,
        deviceInfo: DeviceInfo
    ): ConsentRecord?

    /**
     * Check if consent exists for a specific action.
     *
     * @param authId Authorization ID
     * @param action Action to check
     * @return true if consent has been granted
     */
    suspend fun hasConsent(authId: String, action: TestAction): Boolean

    /**
     * Get consent status for all actions.
     *
     * @param authId Authorization ID
     * @return Map of actions to consent status
     */
    fun getConsentStatus(authId: String): Flow<Map<TestAction, Boolean>>

    /**
     * Get the most recent consent record for an action.
     *
     * @param authId Authorization ID
     * @param action Action to check
     * @return Most recent consent record or null
     */
    suspend fun getLatestConsent(authId: String, action: TestAction): ConsentRecord?

    // ========== Consent Records ==========

    /**
     * Get all consent records for an authorization.
     */
    fun getConsentRecords(authId: String): Flow<List<ConsentRecord>>

    /**
     * Get consent records within a date range.
     */
    fun getConsentRecordsInRange(
        start: java.time.Instant,
        end: java.time.Instant
    ): Flow<List<ConsentRecord>>

    /**
     * Get all consent records (admin only).
     */
    fun getAllConsentRecords(): Flow<List<ConsentRecord>>

    /**
     * Get denied consent records.
     * Useful for understanding user concerns.
     */
    fun getDeniedConsents(): Flow<List<ConsentRecord>>

    /**
     * Get consent records by action type.
     */
    fun getConsentsByAction(action: TestAction): Flow<List<ConsentRecord>>

    // ========== Consent Storage ==========

    /**
     * Save a consent record.
     */
    suspend fun saveConsentRecord(record: ConsentRecord): Result<Unit>

    /**
     * Revoke consent for a specific action.
     *
     * @param authId Authorization ID
     * @param action Action to revoke
     */
    suspend fun revokeConsent(authId: String, action: TestAction): Result<Unit>

    /**
     * Revoke all consent for an authorization.
     *
     * @param authId Authorization ID
     */
    suspend fun revokeAllConsent(authId: String): Result<Unit>

    /**
     * Delete old consent records.
     *
     * CAUTION: Only use after retention period (7 years).
     */
    suspend fun deleteOldConsents(beforeDate: java.time.Instant): Result<Int>

    // ========== Audit Logging ==========

    /**
     * Log any operation for audit purposes.
     *
     * @param authId Authorization ID
     * @param operation Operation that was performed
     * @param deviceInfo Device information
     * @param success Whether operation succeeded
     * @param metadata Additional metadata
     */
    suspend fun logAuditEvent(
        authId: String,
        operation: String,
        deviceInfo: DeviceInfo,
        success: Boolean,
        metadata: Map<String, String> = emptyMap()
    ): Result<Unit>

    /**
     * Get audit log for an authorization.
     */
    fun getAuditLog(authId: String): Flow<List<AuditLogEntry>>

    /**
     * Get audit log within a date range.
     */
    fun getAuditLogInRange(
        start: java.time.Instant,
        end: java.time.Instant
    ): Flow<List<AuditLogEntry>>

    /**
     * Get audit log by operation type.
     */
    fun getAuditLogByOperation(operation: String): Flow<List<AuditLogEntry>>

    /**
     * Get all audit log entries (admin only).
     */
    fun getAllAuditLogs(): Flow<List<AuditLogEntry>>

    // ========== Audit Statistics ==========

    /**
     * Get audit statistics summary.
     */
    fun getAuditStatistics(): Flow<AuditStatistics>

    /**
     * Get statistics for a specific authorization.
     */
    suspend fun getStatisticsForAuth(authId: String): AuthAuditStatistics

    /**
     * Get most common operations.
     */
    fun getMostCommonOperations(limit: Int = 10): Flow<List<OperationCount>>

    /**
     * Get operation success rate.
     */
    fun getOperationSuccessRate(): Flow<Double>

    // ========== Data Retention ==========

    /**
     * Check if any records are eligible for deletion.
     *
     * @return Count of records that can be deleted
     */
    suspend fun getRecordsEligibleForDeletion(): Int

    /**
     * Get data retention summary.
     */
    fun getDataRetentionSummary(): Flow<DataRetentionSummary>

    // ========== Compliance ==========

    /**
     * Generate compliance report for audit purposes.
     *
     * @param startDate Start of reporting period
     * @param endDate End of reporting period
     * @return Compliance report
     */
    suspend fun generateComplianceReport(
        startDate: java.time.Instant,
        endDate: java.time.Instant
    ): ComplianceReport

    /**
     * Export audit log for external review.
     *
     * @param outputPath Output file path
     * @param format Export format
     */
    suspend fun exportAuditLog(
        outputPath: String,
        format: AuditExportFormat
    ): Result<java.io.File>
}

/**
 * Audit log entry.
 */
data class AuditLogEntry(
    val id: String,
    val authId: String,
    val timestamp: java.time.Instant,
    val operation: String,
    val success: Boolean,
    val errorMessage: String?,
    val deviceInfo: DeviceInfo,
    val durationMs: Long?,
    val metadata: Map<String, String>
)

/**
 * Audit statistics summary.
 */
data class AuditStatistics(
    val totalEntries: Long,
    val successfulOperations: Long,
    val failedOperations: Long,
    val successRate: Double,
    val uniqueAuthorizations: Int,
    val uniqueOperations: Int,
    val dateRange: DateRange,
    val topOperations: List<OperationCount>
)

/**
 * Authorization-specific audit statistics.
 */
data class AuthAuditStatistics(
    val authId: String,
    val totalOperations: Int,
    val successfulOperations: Int,
    val failedOperations: Int,
    val firstOperation: java.time.Instant,
    val lastOperation: java.time.Instant,
    val operationBreakdown: Map<String, Int>
)

/**
 * Operation count for statistics.
 */
data class OperationCount(
    val operation: String,
    val count: Int
)

/**
 * Data retention summary.
 */
data class DataRetentionSummary(
    val totalRecords: Long,
    val recordsUnderOneYear: Long,
    val recordsOneToThreeYears: Long,
    val recordsThreeToSevenYears: Long,
    val recordsOverSevenYears: Long,
    val oldestRecord: java.time.Instant?,
    val newestRecord: java.time.Instant?
)

/**
 * Compliance report.
 */
data class ComplianceReport(
    val reportId: String,
    val period: DateRange,
    val generatedAt: java.time.Instant,
    val totalOperations: Int,
    val consentRecords: Int,
    val authorizationIds: List<String>,
    val operationsByType: Map<String, Int>,
    val successRate: Double,
    val findings: List<ComplianceFinding>,
    val recommendations: List<String>
)

/**
 * Compliance finding.
 */
data class ComplianceFinding(
    val category: ComplianceCategory,
    val severity: ComplianceSeverity,
    val description: String,
    val affectedRecords: Int,
    val recommendation: String
)

/**
 * Compliance categories.
 */
enum class ComplianceCategory {
    MISSING_CONSENT,
    OPERATION_WITHOUT_AUTH,
    DATA_RETENTION,
    FAILED_OPERATIONS,
    UNAUTHORIZED_ACCESS,
    OTHER
}

/**
 * Compliance severity levels.
 */
enum class ComplianceSeverity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
}

/**
 * Audit export formats.
 */
enum class AuditExportFormat {
    JSON,
    CSV,
    XML
}
