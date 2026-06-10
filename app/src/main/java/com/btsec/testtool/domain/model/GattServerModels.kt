/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

/**
 * GATT Server Emulator domain models.
 *
 * Defines data structures for emulating BLE GATT server peripherals,
 * including service configurations, presets, events, and session tracking.
 *
 * All testing must be performed on AUTHORIZED devices with proper consent.
 */

enum class GattServerState {
    IDLE, ADVERTISING, CONNECTED, ERROR
}

data class GattServiceConfig(
    val uuid: String,
    val serviceType: Int, // BluetoothGattService.SERVICE_TYPE_PRIMARY or SECONDARY
    val characteristics: List<GattCharacteristicConfig>
)

data class GattCharacteristicConfig(
    val uuid: String,
    val properties: Int, // bitmask: READ, WRITE, NOTIFY, INDICATE
    val permissions: Int, // bitmask: READ, WRITE
    val initialValue: ByteArray = byteArrayOf(),
    val descriptors: List<GattDescriptorConfig> = emptyList()
) {
    override fun equals(other: Any?) = this === other || (other is GattCharacteristicConfig && uuid == other.uuid && initialValue.contentEquals(other.initialValue))
    override fun hashCode() = 31 * uuid.hashCode() + initialValue.contentHashCode()
}

data class GattDescriptorConfig(
    val uuid: String,
    val permissions: Int,
    val initialValue: ByteArray = byteArrayOf()
) {
    override fun equals(other: Any?) = this === other || (other is GattDescriptorConfig && uuid == other.uuid && initialValue.contentEquals(other.initialValue))
    override fun hashCode() = 31 * uuid.hashCode() + initialValue.contentHashCode()
}

data class GattServerEvent(
    val eventType: GattServerEventType,
    val timestamp: Long,
    val deviceAddress: String?,
    val characteristicUuid: String?,
    val value: ByteArray?,
    val offset: Int = 0,
    val response: GattServerResponse? = null
) {
    override fun equals(other: Any?) = this === other || (other is GattServerEvent && timestamp == other.timestamp && eventType == other.eventType)
    override fun hashCode() = 31 * eventType.hashCode() + timestamp.hashCode()
}

enum class GattServerEventType {
    CONNECTION_STATE_CHANGED,
    CHARACTERISTIC_READ_REQUEST,
    CHARACTERISTIC_WRITE_REQUEST,
    DESCRIPTOR_READ_REQUEST,
    DESCRIPTOR_WRITE_REQUEST,
    NOTIFICATION_SENT,
    MTU_CHANGED,
    SERVICE_ADDED
}

data class GattServerResponse(
    val status: Int, // BluetoothGatt.GATT_SUCCESS etc
    val value: ByteArray = byteArrayOf(),
    val delay: Long = 0 // Simulated processing delay in ms
) {
    override fun equals(other: Any?) = this === other || (other is GattServerResponse && status == other.status && value.contentEquals(other.value))
    override fun hashCode() = 31 * status + value.contentHashCode()
}

data class GattServerPreset(
    val name: String,
    val description: String,
    val services: List<GattServiceConfig>,
    val category: GattServerPresetCategory
)

enum class GattServerPresetCategory {
    HEART_RATE, THERMOMETER, BATTERY, CUSTOM, VULNERABLE
}

data class GattServerSession(
    val id: String,
    val startTime: Long,
    val endTime: Long?,
    val preset: GattServerPreset?,
    val connectedDevices: List<String>,
    val events: List<GattServerEvent>,
    val totalReadRequests: Int,
    val totalWriteRequests: Int,
    val totalConnections: Int
)
