/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.*

/**
 * Composite repository for Bluetooth operations.
 *
 * Extends [BluetoothStateReader] and [BluetoothOperationsWriter] to provide the
 * full set of Bluetooth capabilities while adhering to the Interface
 * Segregation Principle (ISP). Existing implementations remain compatible
 * since this interface inherits all methods from its parent interfaces.
 *
 * Handles device scanning, connection, and BLE operations.
 * All operations must be authorized before execution.
 *
 * @see BluetoothStateReader
 * @see BluetoothOperationsWriter
 */
interface BluetoothRepository : BluetoothStateReader, BluetoothOperationsWriter

/**
 * Bluetooth state enumeration.
 */
enum class BluetoothState {
    OFF,
    TURNING_ON,
    ON,
    TURNING_OFF,
    ERROR,
}

/**
 * Write types for BLE characteristics.
 */
enum class WriteType {
    DEFAULT, // Write with response
    WITHOUT_RESPONSE, // Write without response
    SIGNED, // Signed write
}

/**
 * Connection priority for BLE connections.
 */
enum class ConnectionPriority {
    BALANCED,
    HIGH,
    LOW_POWER,
}

/**
 * Captured packet information.
 */
data class CapturedPacket(
    val timestamp: java.time.Instant,
    val direction: PacketDirection,
    val packetType: PacketType,
    val data: ByteArray,
    val channel: Int?,
    val rssi: Int?,
    val size: Int = data.size,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CapturedPacket

        if (timestamp != other.timestamp) return false
        if (direction != other.direction) return false
        if (packetType != other.packetType) return false
        if (!data.contentEquals(other.data)) return false
        if (channel != other.channel) return false
        if (rssi != other.rssi) return false
        if (size != other.size) return false

        return true
    }

    override fun hashCode(): Int {
        var result = timestamp.hashCode()
        result = 31 * result + direction.hashCode()
        result = 31 * result + packetType.hashCode()
        result = 31 * result + data.contentHashCode()
        result = 31 * result + (channel ?: 0)
        result = 31 * result + (rssi ?: 0)
        result = 31 * result + size
        return result
    }
}

/**
 * Packet direction (relative to device under test).
 */
enum class PacketDirection {
    INBOUND, // From device to tester
    OUTBOUND, // From tester to device
    BROADCAST, // Broadcast packet
    UNKNOWN,
}

/**
 * Packet types.
 */
enum class PacketType {
    // BLE packets
    ADV_IND, // Connectable undirected advertising
    ADV_DIRECT_IND, // Connectable directed advertising
    ADV_SCAN_IND, // Scannable undirected advertising
    ADV_NONCONN_IND, // Non-connectable undirected advertising
    SCAN_REQ, // Scan request
    SCAN_RSP, // Scan response
    CONNECT_REQ, // Connect request
    DATA, // Data packet (LL_DATA)

    // Classic Bluetooth
    ACL, // Asynchronous Connection-Less
    SCO, // Synchronous Connection-Oriented

    // Other
    UNKNOWN,
}

/**
 * Packet capture statistics.
 */
data class PacketStatistics(
    val totalPackets: Int,
    val inboundPackets: Int,
    val outboundPackets: Int,
    val broadcastPackets: Int,
    val bytesCaptured: Long,
    val startTime: java.time.Instant?,
    val durationSeconds: Long,
)

/**
 * Bluetooth operation log entry.
 */
data class BluetoothOperation(
    val id: String,
    val timestamp: java.time.Instant,
    val operationType: OperationType,
    val deviceAddress: String?,
    val success: Boolean,
    val errorMessage: String?,
    val durationMs: Long?,
    val metadata: Map<String, String> = emptyMap(),
)

/**
 * Operation types for logging.
 */
enum class OperationType {
    SCAN_START,
    SCAN_STOP,
    CONNECT,
    DISCONNECT,
    BOND,
    UNBOND,
    READ_CHARACTERISTIC,
    WRITE_CHARACTERISTIC,
    SUBSCRIBE,
    UNSUBSCRIBE,
    DISCOVER_SERVICES,
    READ_DESCRIPTOR,
    WRITE_DESCRIPTOR,
    REQUEST_MTU,
    READ_RSSI,
    PACKET_MONITOR_START,
    PACKET_MONITOR_STOP,
}
