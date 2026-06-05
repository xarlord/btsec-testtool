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
 * Room entity for [FuzzResult].
 */
@Entity(tableName = "fuzz_results")
data class FuzzResultEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,

    @ColumnInfo(name = "target_device_address")
    val targetDeviceAddress: String, // config.targetDevice.address

    @ColumnInfo(name = "config")
    val config: String, // JSON of FuzzConfig

    @ColumnInfo(name = "start_time")
    val startTime: Long, // epoch millis

    @ColumnInfo(name = "end_time")
    val endTime: Long?, // epoch millis

    @ColumnInfo(name = "status")
    val status: String, // FuzzStatus enum name

    @ColumnInfo(name = "packets_sent")
    val packetsSent: Int,

    @ColumnInfo(name = "packets_received")
    val packetsReceived: Int,

    @ColumnInfo(name = "errors")
    val errors: String, // JSON array of FuzzError

    @ColumnInfo(name = "findings")
    val findings: String, // JSON array of FuzzFinding

    @ColumnInfo(name = "capture_file")
    val captureFile: String?,

    @ColumnInfo(name = "report_generated")
    val reportGenerated: Boolean
)
