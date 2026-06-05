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
 * Room entity for [ConsentRecord].
 */
@Entity(tableName = "consent_records")
data class ConsentRecordEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,

    @ColumnInfo(name = "auth_id")
    val authId: String,

    @ColumnInfo(name = "action")
    val action: String,

    @ColumnInfo(name = "timestamp")
    val timestamp: Long, // epoch millis

    @ColumnInfo(name = "authorized")
    val authorized: Boolean,

    @ColumnInfo(name = "device_info")
    val deviceInfo: String, // JSON of DeviceInfo

    @ColumnInfo(name = "user_signature")
    val userSignature: String?
)
