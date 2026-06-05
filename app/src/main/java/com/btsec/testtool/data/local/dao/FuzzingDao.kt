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
import com.btsec.testtool.data.local.entity.FuzzResultEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for FuzzResult CRUD and pattern queries.
 */
@Dao
interface FuzzingDao {

    // ========== FuzzResult CRUD ==========

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFuzzResult(result: FuzzResultEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFuzzResults(results: List<FuzzResultEntity>)

    @Delete
    suspend fun deleteFuzzResult(result: FuzzResultEntity)

    @Query("DELETE FROM fuzz_results WHERE id = :id")
    suspend fun deleteFuzzResultById(id: String)

    @Query("DELETE FROM fuzz_results")
    suspend fun deleteAllFuzzResults()

    @Query("SELECT * FROM fuzz_results WHERE id = :id")
    suspend fun getFuzzResultById(id: String): FuzzResultEntity?

    @Query("SELECT * FROM fuzz_results ORDER BY start_time DESC")
    fun getAllFuzzResults(): Flow<List<FuzzResultEntity>>

    @Query("SELECT * FROM fuzz_results WHERE target_device_address = :deviceAddress ORDER BY start_time DESC")
    fun getFuzzResultsForDevice(deviceAddress: String): Flow<List<FuzzResultEntity>>

    @Query("SELECT * FROM fuzz_results WHERE status = :status ORDER BY start_time DESC")
    fun getFuzzResultsByStatus(status: String): Flow<List<FuzzResultEntity>>

    @Query("SELECT * FROM fuzz_results WHERE start_time >= :fromEpochMs AND start_time <= :toEpochMs ORDER BY start_time DESC")
    fun getFuzzResultsInRange(fromEpochMs: Long, toEpochMs: Long): Flow<List<FuzzResultEntity>>

    @Query("SELECT * FROM fuzz_results WHERE findings != '[]' ORDER BY start_time DESC")
    fun getFuzzResultsWithFindings(): Flow<List<FuzzResultEntity>>

    @Query("SELECT COUNT(*) FROM fuzz_results")
    suspend fun getFuzzResultCount(): Int

    @Query("SELECT COUNT(*) FROM fuzz_results WHERE target_device_address = :deviceAddress")
    suspend fun getFuzzResultCountForDevice(deviceAddress: String): Int

    @Query("SELECT SUM(packets_sent) FROM fuzz_results")
    suspend fun getTotalPacketsSent(): Long?

    @Query("SELECT SUM(packets_received) FROM fuzz_results")
    suspend fun getTotalPacketsReceived(): Long?
}
