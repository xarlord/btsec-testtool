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
    val name: String?,                 // Device name (nullable)
    val type: BluetoothType,              // BLE, Classic, Dual Mode
    val deviceClass: DeviceClass?,     // Bluetooth device class
    val bondState: BondState,          // Pairing state
    val rssi: Int?,                    // Signal strength (dBm)
    val txPower: Int?,                 // TX Power (dBm)
    @Serializable(with = InstantSerializer::class)
    val firstSeen: Instant,            // First discovery timestamp
    @Serializable(with = InstantSerializer::class)
    val lastSeen: Instant,             // Last seen timestamp
    val scanCount: Int = 1,            // Number of times discovered
    val services: List<String> = emptyList(),  // UUIDs of discovered services
    val manufacturerData: Map<Int, @Serializable(with = ByteArraySerializer::class) ByteArray> = emptyMap()  // Company ID -> data
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
sealed class ConnectionState {
    data object Disconnected : ConnectionState()

    data object Connecting : ConnectionState()

    data object Connected : ConnectionState()

    data object Disconnecting : ConnectionState()

    data class Error(val message: String) : ConnectionState()
}
