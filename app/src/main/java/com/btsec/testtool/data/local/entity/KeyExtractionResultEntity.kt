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
 * Room entity for [KeyExtractionResult].
 */
@Entity(tableName = "key_extraction_results")
data class KeyExtractionResultEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,

    @ColumnInfo(name = "target_device_address")
    val targetDeviceAddress: String, // targetDevice.address

    @ColumnInfo(name = "target_device")
    val targetDevice: String, // JSON of BluetoothDevice

    @ColumnInfo(name = "key_type")
    val keyType: String, // KeyType enum name

    @ColumnInfo(name = "extracted")
    val extracted: Boolean,

    @ColumnInfo(name = "key_value")
    val keyValue: String?, // Base64 encoded ByteArray

    @ColumnInfo(name = "method")
    val method: String, // ExtractionMethod enum name

    @ColumnInfo(name = "confidence")
    val confidence: String, // ExtractionConfidence enum name

    @ColumnInfo(name = "timestamp")
    val timestamp: Long, // epoch millis

    @ColumnInfo(name = "notes")
    val notes: String?
)
