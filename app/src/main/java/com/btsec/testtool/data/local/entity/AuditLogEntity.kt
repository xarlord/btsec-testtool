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
 * Room entity for [AuditLogEntry].
 */
@Entity(tableName = "audit_log")
data class AuditLogEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    @ColumnInfo(name = "auth_id")
    val authId: String,
    // epoch millis
    @ColumnInfo(name = "timestamp")
    val timestamp: Long,
    @ColumnInfo(name = "operation")
    val operation: String,
    @ColumnInfo(name = "success")
    val success: Boolean,
    @ColumnInfo(name = "error_message")
    val errorMessage: String?,
    // JSON of DeviceInfo
    @ColumnInfo(name = "device_info")
    val deviceInfo: String,
    @ColumnInfo(name = "duration_ms")
    val durationMs: Long?,
    // JSON map of String -> String
    @ColumnInfo(name = "metadata")
    val metadata: String,
)
