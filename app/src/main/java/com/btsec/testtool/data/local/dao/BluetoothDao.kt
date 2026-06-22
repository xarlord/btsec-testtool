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
import com.btsec.testtool.data.local.entity.BluetoothDeviceEntity
import com.btsec.testtool.data.local.entity.BtOperationEntity
import kotlinx.coroutines.flow.Flow

/**
 * DAO for Bluetooth device and operation log CRUD.
 */
@Dao
interface BluetoothDao {
    // ========== Device CRUD ==========

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertDevice(device: BluetoothDeviceEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertDevices(devices: List<BluetoothDeviceEntity>)

    @Update
    suspend fun updateDevice(device: BluetoothDeviceEntity)

    @Delete
    suspend fun deleteDevice(device: BluetoothDeviceEntity)

    @Query("DELETE FROM bluetooth_devices WHERE address = :address")
    suspend fun deleteDeviceByAddress(address: String)

    @Query("DELETE FROM bluetooth_devices")
    suspend fun deleteAllDevices()

    @Query("SELECT * FROM bluetooth_devices WHERE address = :address")
    suspend fun getDeviceByAddress(address: String): BluetoothDeviceEntity?

    @Query("SELECT * FROM bluetooth_devices ORDER BY last_seen DESC")
    fun getAllDevices(): Flow<List<BluetoothDeviceEntity>>

    @Query("SELECT * FROM bluetooth_devices WHERE name LIKE '%' || :query || '%' OR address LIKE '%' || :query || '%'")
    fun searchDevices(query: String): Flow<List<BluetoothDeviceEntity>>

    @Query("SELECT * FROM bluetooth_devices WHERE type = :type")
    fun getDevicesByType(type: String): Flow<List<BluetoothDeviceEntity>>

    @Query("SELECT * FROM bluetooth_devices WHERE bond_state = :bondState")
    fun getDevicesByBondState(bondState: String): Flow<List<BluetoothDeviceEntity>>

    @Query("SELECT * FROM bluetooth_devices WHERE last_seen >= :sinceEpochMs ORDER BY last_seen DESC")
    fun getDevicesSeenSince(sinceEpochMs: Long): Flow<List<BluetoothDeviceEntity>>

    @Query("SELECT COUNT(*) FROM bluetooth_devices")
    suspend fun getDeviceCount(): Int

    // ========== Operation Log CRUD ==========

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOperation(operation: BtOperationEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOperations(operations: List<BtOperationEntity>)

    @Query("DELETE FROM bluetooth_operations WHERE id = :id")
    suspend fun deleteOperation(id: String)

    @Query("DELETE FROM bluetooth_operations")
    suspend fun deleteAllOperations()

    @Query("SELECT * FROM bluetooth_operations ORDER BY timestamp DESC")
    fun getAllOperations(): Flow<List<BtOperationEntity>>

    @Query("SELECT * FROM bluetooth_operations WHERE device_address = :deviceAddress ORDER BY timestamp DESC")
    fun getOperationsForDevice(deviceAddress: String): Flow<List<BtOperationEntity>>

    @Query("SELECT * FROM bluetooth_operations WHERE operation_type = :operationType ORDER BY timestamp DESC")
    fun getOperationsByType(operationType: String): Flow<List<BtOperationEntity>>

    @Query("SELECT * FROM bluetooth_operations WHERE timestamp >= :fromEpochMs AND timestamp <= :toEpochMs ORDER BY timestamp DESC")
    fun getOperationsInRange(
        fromEpochMs: Long,
        toEpochMs: Long,
    ): Flow<List<BtOperationEntity>>

    @Query("SELECT * FROM bluetooth_operations WHERE success = 0 ORDER BY timestamp DESC")
    fun getFailedOperations(): Flow<List<BtOperationEntity>>

    @Query("SELECT COUNT(*) FROM bluetooth_operations")
    suspend fun getOperationCount(): Int
}
