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
import com.btsec.testtool.data.local.entity.KeyExtractionResultEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for KeyExtractionResult CRUD.
 */
@Dao
interface KeyExtractionDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertKeyExtractionResult(result: KeyExtractionResultEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertKeyExtractionResults(results: List<KeyExtractionResultEntity>)

    @Delete
    suspend fun deleteKeyExtractionResult(result: KeyExtractionResultEntity)

    @Query("DELETE FROM key_extraction_results WHERE id = :id")
    suspend fun deleteKeyExtractionResultById(id: String)

    @Query("DELETE FROM key_extraction_results")
    suspend fun deleteAllKeyExtractionResults()

    @Query("SELECT * FROM key_extraction_results WHERE id = :id")
    suspend fun getKeyExtractionResultById(id: String): KeyExtractionResultEntity?

    @Query("SELECT * FROM key_extraction_results ORDER BY timestamp DESC")
    fun getAllKeyExtractionResults(): Flow<List<KeyExtractionResultEntity>>

    @Query("SELECT * FROM key_extraction_results WHERE target_device_address = :deviceAddress ORDER BY timestamp DESC")
    fun getKeyExtractionResultsForDevice(deviceAddress: String): Flow<List<KeyExtractionResultEntity>>

    @Query("SELECT * FROM key_extraction_results WHERE key_type = :keyType ORDER BY timestamp DESC")
    fun getKeyExtractionResultsByKeyType(keyType: String): Flow<List<KeyExtractionResultEntity>>

    @Query("SELECT * FROM key_extraction_results WHERE extracted = 1 ORDER BY timestamp DESC")
    fun getSuccessfulExtractions(): Flow<List<KeyExtractionResultEntity>>

    @Query("SELECT * FROM key_extraction_results WHERE method = :method ORDER BY timestamp DESC")
    fun getKeyExtractionResultsByMethod(method: String): Flow<List<KeyExtractionResultEntity>>

    @Query("SELECT * FROM key_extraction_results WHERE confidence = :confidence ORDER BY timestamp DESC")
    fun getKeyExtractionResultsByConfidence(confidence: String): Flow<List<KeyExtractionResultEntity>>

    @Query("SELECT COUNT(*) FROM key_extraction_results")
    suspend fun getKeyExtractionCount(): Int

    @Query("SELECT COUNT(*) FROM key_extraction_results WHERE extracted = 1")
    suspend fun getSuccessfulExtractionCount(): Int

    @Query("SELECT COUNT(*) FROM key_extraction_results WHERE target_device_address = :deviceAddress")
    suspend fun getKeyExtractionCountForDevice(deviceAddress: String): Int
}
