/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import kotlinx.serialization.Serializable
import java.time.Instant

/**
 * Represents a discovered Bluetooth device.
 */
@Serializable
data class BluetoothDevice(
    val address: String,              // MAC address
    val name: String? = null,         // Device name (nullable)
    val type: BluetoothType = BluetoothType.UNKNOWN,  // BLE, Classic, Dual Mode
    val deviceClass: DeviceClass? = null,     // Bluetooth device class
    val bondState: BondState = BondState.NONE,          // Pairing state
    val rssi: Int? = null,                    // Signal strength (dBm)
    val txPower: Int? = null,                 // TX Power (dBm)
    @Serializable(with = InstantAsEpochMillisSerializer::class) val firstSeen: Instant = Instant.now(),            // First discovery timestamp
    @Serializable(with = InstantAsEpochMillisSerializer::class) val lastSeen: Instant = Instant.now(),             // Last seen timestamp
    val scanCount: Int = 1,            // Number of times discovered
    val services: List<String> = emptyList(),  // UUIDs of discovered services
    val manufacturerData: Map<Int, ByteArray> = emptyMap()  // Company ID -> data
) {
    /**
     * Check if this is a BLE device.
     */
    fun isBle(): Boolean = type == BluetoothType.BLE || type == BluetoothType.DUAL_MODE

    /**
     * Check if this is a Classic Bluetooth device.
     */
    fun isClassic(): Boolean = type == BluetoothType.CLASSIC || type == BluetoothType.DUAL_MODE

    /**
     * Check if device is bonded/paired.
     */
    fun isBonded(): Boolean = bondState == BondState.BONDED
}

/**
 * Bluetooth device type enumeration.
 */
@Serializable
enum class BluetoothType {
    BLE,           // Bluetooth Low Energy only
    CLASSIC,       // Classic Bluetooth only
    DUAL_MODE,     // Both BLE and Classic
    UNKNOWN        // Could not determine type
}

/**
 * Bluetooth device class categories.
 */
@Serializable
enum class DeviceClass {
    COMPUTER,
    PHONE,
    AUDIO_VIDEO,
    PERIPHERAL,
    WEARABLE,
    TOY,
    HEALTH,
    VEHICLE,
    IOT_DEVICE,
    UNCATEGORIZED,
    UNKNOWN
}

/**
 * Bond (pairing) state enumeration.
 */
@Serializable
enum class BondState {
    NONE,      // Not paired
    BONDING,   // Pairing in progress
    BONDED     // Successfully paired
}

/**
 * Connection state sealed class.
 */
@Serializable
sealed class ConnectionState {
    @Serializable data object Disconnected : ConnectionState()
    @Serializable data object Connecting : ConnectionState()
    @Serializable data object Connected : ConnectionState()
    @Serializable data object Disconnecting : ConnectionState()
    @Serializable data class Error(val message: String) : ConnectionState()
}
