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
 * Read-only interface for Bluetooth state observation and device queries.
 *
 * Provides methods to observe Bluetooth adapter state, retrieve scan results,
 * query connection state, bond state, GATT services, device cache, packet
 * statistics, and operation logs.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only read/observation operations, allowing UI layers and
 * analytics components to depend on a narrow, query-only contract.
 */
interface BluetoothStateReader {
    /**
     * Check if Bluetooth is enabled.
     */
    fun isBluetoothEnabled(): Flow<Boolean>

    /**
     * Get current Bluetooth state.
     */
    fun getBluetoothState(): Flow<BluetoothState>

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

    /**
     * Get current connection state.
     */
    fun getConnectionState(): Flow<ConnectionState>

    /**
     * Get currently connected device.
     */
    fun getConnectedDevice(): Flow<BluetoothDevice?>

    /**
     * Get bond state for a device.
     */
    fun getBondState(address: String): Flow<BondState>

    /**
     * Get discovered services for connected device.
     */
    fun getServices(): Flow<List<BleService>>

    /**
     * Get current MTU size.
     */
    fun getCurrentMtu(): Flow<Int>

    /**
     * Get the currently selected device address.
     */
    fun getSelectedDeviceAddress(): Flow<String?>

    /**
     * Get all cached devices (from previous scans).
     */
    fun getCachedDevices(): Flow<List<BluetoothDevice>>

    /**
     * Check if packet monitoring is available.
     * Returns false if no monitor mode support.
     */
    suspend fun isPacketMonitoringAvailable(): Boolean

    /**
     * Get packet capture statistics.
     */
    fun getPacketStatistics(): Flow<PacketStatistics>

    /**
     * Get operation logs.
     */
    fun getOperationLogs(): Flow<List<BluetoothOperation>>
}
