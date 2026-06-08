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
 * Composite repository for consent tracking and audit logging.
 *
 * Extends [ConsentReader] and [ConsentWriter] to provide the full set of
 * consent management capabilities while adhering to the Interface
 * Segregation Principle (ISP). Existing implementations remain compatible
 * since this interface inherits all methods from its parent interfaces.
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
 *
 * @see ConsentReader
 * @see ConsentWriter
 */
interface ConsentRepository : ConsentReader, ConsentWriter

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
