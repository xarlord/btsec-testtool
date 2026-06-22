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
import kotlinx.coroutines.flow.Flow

/**
 * Write/mutation interface for Bluetooth operations.
 *
 * Provides methods for scanning, connecting, bonding, GATT read/write
 * operations, packet monitoring, device selection, cache management,
 * and operation logging.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only mutation/action operations, allowing components that only
 * need to trigger Bluetooth actions to depend on a narrow contract.
 */
interface BluetoothOperationsWriter {
    /**
     * Request Bluetooth to be enabled.
     */
    suspend fun requestEnableBluetooth(): Boolean

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
     * Clear all scan results.
     */
    suspend fun clearScanResults()

    /**
     * Connect to a Bluetooth device.
     *
     * @param address Device MAC address
     * @param timeoutMs Connection timeout in milliseconds
     * @return Flow of connection state updates
     */
    fun connect(
        address: String,
        timeoutMs: Int = 30000,
    ): Flow<ConnectionState>

    /**
     * Disconnect from current device.
     */
    suspend fun disconnect()

    /**
     * Create bond (pair) with a device.
     */
    suspend fun createBond(address: String): Boolean

    /**
     * Remove bond (unpair) with a device.
     */
    suspend fun removeBond(address: String): Boolean

    /**
     * Discover services for connected BLE device.
     *
     * @return Flow of discovered services
     */
    fun discoverServices(): Flow<List<BleService>>

    /**
     * Read a characteristic value.
     *
     * @param serviceUuid Service UUID
     * @param characteristicUuid Characteristic UUID
     * @return Read value as byte array
     */
    suspend fun readCharacteristic(
        serviceUuid: String,
        characteristicUuid: String,
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
        writeType: WriteType = WriteType.DEFAULT,
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
        characteristicUuid: String,
    ): Flow<ByteArray>

    /**
     * Unsubscribe from characteristic notifications.
     */
    suspend fun unsubscribeFromCharacteristic(
        serviceUuid: String,
        characteristicUuid: String,
    ): Result<Unit>

    /**
     * Read a descriptor value.
     */
    suspend fun readDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String,
    ): Result<ByteArray>

    /**
     * Write a descriptor value.
     */
    suspend fun writeDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String,
        value: ByteArray,
    ): Result<Unit>

    /**
     * Request MTU size for BLE connection.
     */
    suspend fun requestMtu(mtu: Int): Result<Int>

    /**
     * Request connection priority.
     */
    suspend fun requestConnectionPriority(priority: ConnectionPriority): Result<Unit>

    /**
     * Read RSSI of connected device.
     */
    suspend fun readRssi(): Result<Int>

    /**
     * Select a device for testing operations.
     */
    fun selectDevice(address: String?)

    /**
     * Refresh device cache (clear GATT cache).
     */
    suspend fun refreshCache(): Result<Unit>

    /**
     * Clear all cached devices.
     */
    suspend fun clearDeviceCache()

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
     * Log a Bluetooth operation for audit purposes.
     */
    suspend fun logOperation(operation: BluetoothOperation)

    /**
     * Clear operation logs.
     */
    suspend fun clearOperationLogs()
}
