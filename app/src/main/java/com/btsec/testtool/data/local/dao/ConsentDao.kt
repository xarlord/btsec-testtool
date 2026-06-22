/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.btsec.testtool.data.local.entity.AuditLogEntity
import com.btsec.testtool.data.local.entity.ConsentRecordEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for Consent records and Audit log CRUD.
 */
@Dao
interface ConsentDao {
    // ========== Consent CRUD ==========

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertConsentRecord(record: ConsentRecordEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertConsentRecords(records: List<ConsentRecordEntity>)

    @Delete
    suspend fun deleteConsentRecord(record: ConsentRecordEntity)

    @Query("DELETE FROM consent_records WHERE id = :id")
    suspend fun deleteConsentRecordById(id: String)

    @Query("DELETE FROM consent_records WHERE auth_id = :authId")
    suspend fun deleteConsentsByAuthId(authId: String)

    @Query("DELETE FROM consent_records WHERE timestamp < :beforeEpochMs")
    suspend fun deleteConsentsOlderThan(beforeEpochMs: Long): Int

    @Query("DELETE FROM consent_records")
    suspend fun deleteAllConsentRecords()

    @Query("SELECT * FROM consent_records WHERE id = :id")
    suspend fun getConsentRecordById(id: String): ConsentRecordEntity?

    @Query("SELECT * FROM consent_records WHERE auth_id = :authId ORDER BY timestamp DESC")
    fun getConsentRecordsByAuthId(authId: String): Flow<List<ConsentRecordEntity>>

    @Query("SELECT * FROM consent_records ORDER BY timestamp DESC")
    fun getAllConsentRecords(): Flow<List<ConsentRecordEntity>>

    @Query("SELECT * FROM consent_records WHERE authorized = 0 ORDER BY timestamp DESC")
    fun getDeniedConsents(): Flow<List<ConsentRecordEntity>>

    @Query("SELECT * FROM consent_records WHERE action = :action ORDER BY timestamp DESC")
    fun getConsentsByAction(action: String): Flow<List<ConsentRecordEntity>>

    @Query("SELECT * FROM consent_records WHERE auth_id = :authId AND action = :action ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLatestConsentForAction(
        authId: String,
        action: String,
    ): ConsentRecordEntity?

    @Query("SELECT * FROM consent_records WHERE timestamp >= :fromEpochMs AND timestamp <= :toEpochMs ORDER BY timestamp DESC")
    fun getConsentRecordsInRange(
        fromEpochMs: Long,
        toEpochMs: Long,
    ): Flow<List<ConsentRecordEntity>>

    @Query("SELECT EXISTS(SELECT 1 FROM consent_records WHERE auth_id = :authId AND action = :action AND authorized = 1)")
    suspend fun hasConsent(
        authId: String,
        action: String,
    ): Boolean

    @Query("SELECT COUNT(*) FROM consent_records")
    suspend fun getConsentCount(): Int

    // ========== Audit Log CRUD ==========

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAuditLog(entry: AuditLogEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAuditLogs(entries: List<AuditLogEntity>)

    @Query("DELETE FROM audit_log WHERE id = :id")
    suspend fun deleteAuditLogById(id: String)

    @Query("DELETE FROM audit_log")
    suspend fun deleteAllAuditLogs()

    @Query("SELECT * FROM audit_log WHERE id = :id")
    suspend fun getAuditLogById(id: String): AuditLogEntity?

    @Query("SELECT * FROM audit_log WHERE auth_id = :authId ORDER BY timestamp DESC")
    fun getAuditLogsByAuthId(authId: String): Flow<List<AuditLogEntity>>

    @Query("SELECT * FROM audit_log ORDER BY timestamp DESC")
    fun getAllAuditLogs(): Flow<List<AuditLogEntity>>

    @Query("SELECT * FROM audit_log WHERE operation = :operation ORDER BY timestamp DESC")
    fun getAuditLogsByOperation(operation: String): Flow<List<AuditLogEntity>>

    @Query("SELECT * FROM audit_log WHERE timestamp >= :fromEpochMs AND timestamp <= :toEpochMs ORDER BY timestamp DESC")
    fun getAuditLogsInRange(
        fromEpochMs: Long,
        toEpochMs: Long,
    ): Flow<List<AuditLogEntity>>

    @Query("SELECT * FROM audit_log WHERE success = 0 ORDER BY timestamp DESC")
    fun getFailedAuditLogs(): Flow<List<AuditLogEntity>>

    @Query("SELECT COUNT(*) FROM audit_log")
    suspend fun getAuditLogCount(): Int

    @Query("SELECT COUNT(*) FROM audit_log WHERE success = 1")
    suspend fun getSuccessfulOperationCount(): Int

    @Query("SELECT COUNT(*) FROM audit_log WHERE success = 0")
    suspend fun getFailedOperationCount(): Int
}
