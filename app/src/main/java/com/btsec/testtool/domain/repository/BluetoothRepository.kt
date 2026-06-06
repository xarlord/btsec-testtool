/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.Flow

/**
 * Repository for Bluetooth operations.
 *
 * Handles device scanning, connection, and BLE operations.
 * All operations must be authorized before execution.
 */
interface BluetoothRepository {

    // ========== Bluetooth State ==========

    /**
     * Check if Bluetooth is enabled.
     */
    fun isBluetoothEnabled(): Flow<Boolean>

    /**
     * Get current Bluetooth state.
     */
    fun getBluetoothState(): Flow<BluetoothState>

    /**
     * Request Bluetooth to be enabled.
     */
    suspend fun requestEnableBluetooth(): Boolean

    // ========== Device Scanning ==========

    /**
     * Start scanning for Bluetooth devices.
     *
     * @param filter Optional device address filter
     * @return Flow of discovered devices
     */
    fun startScan(filter: String? = null): Flow<BluetoothDevice>

    /**
     * Stop scanning for devices.
     */
    suspend fun stopScan()

    /**
     * Check if currently scanning.
     */
    fun isScanning(): Flow<Boolean>

    /**
     * Get scan results from current or last scan.
     */
    fun getScanResults(): Flow<List<BluetoothDevice>>

    /**
     * Get a specific device by address.
     */
    suspend fun getDevice(address: String): BluetoothDevice?

    // ========== Device Connection ==========

    /**
     * Connect to a Bluetooth device.
     *
     * @param address Device MAC address
     * @param timeoutMs Connection timeout in milliseconds
     * @return Flow of connection state updates
     */
    fun connect(address: String, timeoutMs: Int = 30000): Flow<ConnectionState>

    /**
     * Disconnect from current device.
     */
    suspend fun disconnect()

    /**
     * Get current connection state.
     */
    fun getConnectionState(): Flow<ConnectionState>

    /**
     * Get currently connected device.
     */
    fun getConnectedDevice(): Flow<BluetoothDevice?>

    // ========== Bonding (Pairing) ==========

    /**
     * Create bond (pair) with a device.
     */
    suspend fun createBond(address: String): Boolean

    /**
     * Remove bond (unpair) with a device.
     */
    suspend fun removeBond(address: String): Boolean

    /**
     * Get bond state for a device.
     */
    fun getBondState(address: String): Flow<BondState>

    // ========== BLE Operations ==========

    /**
     * Discover services for connected BLE device.
     *
     * @return Flow of discovered services
     */
    fun discoverServices(): Flow<List<BleService>>

    /**
     * Get discovered services for connected device.
     */
    fun getServices(): Flow<List<BleService>>

    /**
     * Read a characteristic value.
     *
     * @param serviceUuid Service UUID
     * @param characteristicUuid Characteristic UUID
     * @return Read value as byte array
     */
    suspend fun readCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Result<ByteArray>

    /**
     * Write a characteristic value.
     *
     * @param serviceUuid Service UUID
     * @param characteristicUuid Characteristic UUID
     * @param value Value to write
     * @param writeType Type of write (default, with response, without response)
     */
    suspend fun writeCharacteristic(
        serviceUuid: String,
        characteristicUuid: String,
        value: ByteArray,
        writeType: WriteType = WriteType.DEFAULT
    ): Result<Unit>

    /**
     * Subscribe to characteristic notifications/indications.
     *
     * @param serviceUuid Service UUID
     * @param characteristicUuid Characteristic UUID
     * @return Flow of notification values
     */
    fun subscribeToCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Flow<ByteArray>

    /**
     * Unsubscribe from characteristic notifications.
     */
    suspend fun unsubscribeFromCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Result<Unit>

    /**
     * Read a descriptor value.
     */
    suspend fun readDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String
    ): Result<ByteArray>

    /**
     * Write a descriptor value.
     */
    suspend fun writeDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String,
        value: ByteArray
    ): Result<Unit>

    /**
     * Request MTU size for BLE connection.
     */
    suspend fun requestMtu(mtu: Int): Result<Int>

    /**
     * Get current MTU size.
     */
    fun getCurrentMtu(): Flow<Int>

    /**
     * Request connection priority.
     */
    suspend fun requestConnectionPriority(priority: ConnectionPriority): Result<Unit>

    /**
     * Read RSSI of connected device.
     */
    suspend fun readRssi(): Result<Int>

    // ========== Selected Device ==========

    /**
     * Get the currently selected device address.
     */
    fun getSelectedDeviceAddress(): Flow<String?>

    /**
     * Select a device for testing operations.
     */
    fun selectDevice(address: String?)

    // ========== Device Cache ==========

    /**
     * Refresh device cache (clear GATT cache).
     */
    suspend fun refreshCache(): Result<Unit>

    /**
     * Clear all cached devices.
     */
    suspend fun clearDeviceCache()

    /**
     * Get all cached devices (from previous scans).
     */
    fun getCachedDevices(): Flow<List<BluetoothDevice>>

    // ========== Packet Monitoring ==========

    /**
     * Start monitoring Bluetooth packets (sniffing).
     * Requires root and monitor mode support.
     *
     * @return Flow of captured packets
     */
    fun startPacketMonitoring(): Flow<CapturedPacket>

    /**
     * Stop packet monitoring.
     */
    suspend fun stopPacketMonitoring()

    /**
     * Check if packet monitoring is available.
     * Returns false if no monitor mode support.
     */
    suspend fun isPacketMonitoringAvailable(): Boolean

    /**
     * Get packet capture statistics.
     */
    fun getPacketStatistics(): Flow<PacketStatistics>

    // ========== Logging ==========

    /**
     * Log a Bluetooth operation for audit purposes.
     */
    suspend fun logOperation(operation: BluetoothOperation)

    /**
     * Get operation logs.
     */
    fun getOperationLogs(): Flow<List<BluetoothOperation>>

    /**
     * Clear operation logs.
     */
    suspend fun clearOperationLogs()
}

/**
 * Bluetooth state enumeration.
 */
enum class BluetoothState {
    OFF,
    TURNING_ON,
    ON,
    TURNING_OFF,
    ERROR
}

/**
 * Write types for BLE characteristics.
 */
enum class WriteType {
    DEFAULT,              // Write with response
    WITHOUT_RESPONSE,     // Write without response
    SIGNED                // Signed write
}

/**
 * Connection priority for BLE connections.
 */
enum class ConnectionPriority {
    BALANCED,
    HIGH,
    LOW_POWER
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
    val size: Int = data.size
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
    INBOUND,      // From device to tester
    OUTBOUND,     // From tester to device
    BROADCAST,    // Broadcast packet
    UNKNOWN
}

/**
 * Packet types.
 */
enum class PacketType {
    // BLE packets
    ADV_IND,              // Connectable undirected advertising
    ADV_DIRECT_IND,       // Connectable directed advertising
    ADV_SCAN_IND,         // Scannable undirected advertising
    ADV_NONCONN_IND,      // Non-connectable undirected advertising
    SCAN_REQ,             // Scan request
    SCAN_RSP,             // Scan response
    CONNECT_REQ,          // Connect request
    DATA,                 // Data packet (LL_DATA)
    // Classic Bluetooth
    ACL,                  // Asynchronous Connection-Less
    SCO,                  // Synchronous Connection-Oriented
    // Other
    UNKNOWN
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
    val durationSeconds: Long
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
    val metadata: Map<String, String> = emptyMap()
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
    PACKET_MONITOR_STOP
}
