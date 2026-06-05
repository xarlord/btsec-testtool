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

    @ColumnInfo(name = "timestamp")
    val timestamp: Long, // epoch millis

    @ColumnInfo(name = "operation")
    val operation: String,

    @ColumnInfo(name = "success")
    val success: Boolean,

    @ColumnInfo(name = "error_message")
    val errorMessage: String?,

    @ColumnInfo(name = "device_info")
    val deviceInfo: String, // JSON of DeviceInfo

    @ColumnInfo(name = "duration_ms")
    val durationMs: Long?,

    @ColumnInfo(name = "metadata")
    val metadata: String // JSON map of String -> String
)
