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
 * Read-only interface for consent tracking and audit log queries.
 *
 * Provides methods to check consent status, retrieve consent records,
 * query audit logs, and observe statistics — all without mutating state.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only read/observation operations, allowing compliance dashboards
 * and audit review tools to depend on a narrow, query-only contract.
 *
 * All testing operations require explicit user consent that is:
 * 1. Specific to the action being performed
 * 2. Time-stamped
 * 3. Linked to the authorization ID
 * 4. Stored for 7 years (audit requirement)
 * 5. Tamper-evident
 */
interface ConsentReader {
    /**
     * Check if consent exists for a specific action.
     *
     * @param authId Authorization ID
     * @param action Action to check
     * @return true if consent has been granted
     */
    suspend fun hasConsent(
        authId: String,
        action: TestAction,
    ): Boolean

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
    suspend fun getLatestConsent(
        authId: String,
        action: TestAction,
    ): ConsentRecord?

    /**
     * Get all consent records for an authorization.
     */
    fun getConsentRecords(authId: String): Flow<List<ConsentRecord>>

    /**
     * Get consent records within a date range.
     */
    fun getConsentRecordsInRange(
        start: java.time.Instant,
        end: java.time.Instant,
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

    /**
     * Get audit log for an authorization.
     */
    fun getAuditLog(authId: String): Flow<List<AuditLogEntry>>

    /**
     * Get audit log within a date range.
     */
    fun getAuditLogInRange(
        start: java.time.Instant,
        end: java.time.Instant,
    ): Flow<List<AuditLogEntry>>

    /**
     * Get audit log by operation type.
     */
    fun getAuditLogByOperation(operation: String): Flow<List<AuditLogEntry>>

    /**
     * Get all audit log entries (admin only).
     */
    fun getAllAuditLogs(): Flow<List<AuditLogEntry>>

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
}
