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
 * Room entity for [BluetoothDevice].
 */
@Entity(tableName = "bluetooth_devices")
data class BluetoothDeviceEntity(
    @PrimaryKey
    @ColumnInfo(name = "address")
    val address: String,

    @ColumnInfo(name = "name")
    val name: String?,

    @ColumnInfo(name = "type")
    val type: String, // BluetoothType enum name

    @ColumnInfo(name = "device_class")
    val deviceClass: String?, // DeviceClass enum name

    @ColumnInfo(name = "bond_state")
    val bondState: String, // BondState enum name

    @ColumnInfo(name = "rssi")
    val rssi: Int?,

    @ColumnInfo(name = "tx_power")
    val txPower: Int?,

    @ColumnInfo(name = "first_seen")
    val firstSeen: Long, // epoch millis

    @ColumnInfo(name = "last_seen")
    val lastSeen: Long, // epoch millis

    @ColumnInfo(name = "scan_count")
    val scanCount: Int,

    @ColumnInfo(name = "services")
    val services: String, // JSON array of strings

    @ColumnInfo(name = "manufacturer_data")
    val manufacturerData: String // JSON map of Int -> Base64 String
)
