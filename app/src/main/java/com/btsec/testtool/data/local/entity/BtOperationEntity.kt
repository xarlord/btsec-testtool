/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Room entity for [BluetoothOperation].
 */
@Entity(tableName = "bluetooth_operations")
data class BtOperationEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    // epoch millis
    @ColumnInfo(name = "timestamp")
    val timestamp: Long,
    // OperationType enum name
    @ColumnInfo(name = "operation_type")
    val operationType: String,
    @ColumnInfo(name = "device_address")
    val deviceAddress: String?,
    @ColumnInfo(name = "success")
    val success: Boolean,
    @ColumnInfo(name = "error_message")
    val errorMessage: String?,
    @ColumnInfo(name = "duration_ms")
    val durationMs: Long?,
    // JSON map of String -> String
    @ColumnInfo(name = "metadata")
    val metadata: String,
)
