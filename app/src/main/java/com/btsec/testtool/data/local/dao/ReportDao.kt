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
import androidx.room.Update
import com.btsec.testtool.data.local.entity.SecurityReportEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for SecurityReport CRUD.
 */
@Dao
interface ReportDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertReport(report: SecurityReportEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertReports(reports: List<SecurityReportEntity>)

    @Update
    suspend fun updateReport(report: SecurityReportEntity)

    @Delete
    suspend fun deleteReport(report: SecurityReportEntity)

    @Query("DELETE FROM security_reports WHERE id = :id")
    suspend fun deleteReportById(id: String)

    @Query("DELETE FROM security_reports")
    suspend fun deleteAllReports()

    @Query("SELECT * FROM security_reports WHERE id = :id")
    suspend fun getReportById(id: String): SecurityReportEntity?

    @Query("SELECT * FROM security_reports ORDER BY generated_at DESC")
    fun getAllReports(): Flow<List<SecurityReportEntity>>

    @Query("SELECT * FROM security_reports WHERE auth_id = :authId ORDER BY generated_at DESC")
    fun getReportsByAuthId(authId: String): Flow<List<SecurityReportEntity>>

    @Query("SELECT * FROM security_reports WHERE status = :status ORDER BY generated_at DESC")
    fun getReportsByStatus(status: String): Flow<List<SecurityReportEntity>>

    @Query("SELECT * FROM security_reports WHERE generated_at >= :fromEpochMs AND generated_at <= :toEpochMs ORDER BY generated_at DESC")
    fun getReportsInRange(fromEpochMs: Long, toEpochMs: Long): Flow<List<SecurityReportEntity>>

    @Query("UPDATE security_reports SET status = :status WHERE id = :id")
    suspend fun updateReportStatus(id: String, status: String)

    @Query("SELECT COUNT(*) FROM security_reports")
    suspend fun getReportCount(): Int

    @Query("SELECT COUNT(*) FROM security_reports WHERE status = :status")
    suspend fun getReportCountByStatus(status: String): Int
}
