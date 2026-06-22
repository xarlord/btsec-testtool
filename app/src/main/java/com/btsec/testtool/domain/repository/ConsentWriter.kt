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

/**
 * Write/mutation interface for consent management and audit logging.
 *
 * Provides methods to request consent, revoke consent, save/delete
 * consent records, log audit events, generate compliance reports,
 * export audit logs, and manage data retention.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only mutation/action operations, allowing components that only
 * need to record or modify consent/audit state to depend on a narrow contract.
 *
 * All testing operations require explicit user consent that is:
 * 1. Specific to the action being performed
 * 2. Time-stamped
 * 3. Linked to the authorization ID
 * 4. Stored for 7 years (audit requirement)
 * 5. Tamper-evident
 */
interface ConsentWriter {
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
        deviceInfo: DeviceInfo,
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
        deviceInfo: DeviceInfo,
    ): ConsentRecord?

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
    suspend fun revokeConsent(
        authId: String,
        action: TestAction,
    ): Result<Unit>

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
        metadata: Map<String, String> = emptyMap(),
    ): Result<Unit>

    /**
     * Generate compliance report for audit purposes.
     *
     * @param startDate Start of reporting period
     * @param endDate End of reporting period
     * @return Compliance report
     */
    suspend fun generateComplianceReport(
        startDate: java.time.Instant,
        endDate: java.time.Instant,
    ): ComplianceReport

    /**
     * Export audit log for external review.
     *
     * @param outputPath Output file path
     * @param format Export format
     */
    suspend fun exportAuditLog(
        outputPath: String,
        format: AuditExportFormat,
    ): Result<java.io.File>
}
