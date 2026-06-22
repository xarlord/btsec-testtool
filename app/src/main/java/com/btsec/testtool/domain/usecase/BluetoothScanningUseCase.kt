/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Use case for Bluetooth device scanning.
 */
class BluetoothScanningUseCase
    @Inject
    constructor(
        private val bluetoothRepository: BluetoothRepository,
    ) {
        private val scope =
            kotlinx.coroutines.CoroutineScope(
                kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.IO,
            )
        private var scanJob: Job? = null

        /**
         * Start scanning for Bluetooth devices (both BLE and Classic).
         * Collects the scan flow so that device callbacks actually fire.
         */
        suspend fun startScan(filter: String? = null): ScanResult {
            return try {
                // Cancel any previous scan
                scanJob?.cancel()
                // Clear previous results
                bluetoothRepository.clearScanResults()
                // Start collecting the cold flow — this triggers scanner.startScan()
                scanJob =
                    scope.launch {
                        bluetoothRepository.startScan(filter).collect { /* results stored via callback */ }
                    }
                ScanResult.Started
            } catch (e: Exception) {
                ScanResult.Error(e.message ?: "Scan start failed")
            }
        }

        /**
         * Stop scanning for devices.
         */
        suspend fun stopScan() {
            scanJob?.cancel()
            scanJob = null
            bluetoothRepository.stopScan()
        }

        /**
         * Get scan results as a flow.
         */
        fun getScanResults(): Flow<List<BluetoothDevice>> {
            return bluetoothRepository.getScanResults()
        }

        /**
         * Get devices discovered in current scan.
         */
        fun getDiscoveredDevices(): Flow<List<BluetoothDevice>> {
            return bluetoothRepository.getScanResults()
                .map { devices -> devices.filter { it.lastSeen.isAfter(java.time.Instant.now().minusSeconds(300)) } }
        }

        /**
         * Get scanning state.
         */
        fun isScanning(): Flow<Boolean> {
            return bluetoothRepository.isScanning()
        }

        /**
         * Get a specific device by address.
         */
        suspend fun getDevice(address: String): BluetoothDevice? {
            return bluetoothRepository.getDevice(address)
        }

        /**
         * Get the currently selected device address.
         */
        fun getSelectedDeviceAddress(): Flow<String?> {
            return bluetoothRepository.getSelectedDeviceAddress()
        }

        /**
         * Select a device for testing operations.
         */
        fun selectDevice(address: String?) {
            bluetoothRepository.selectDevice(address)
        }

        /**
         * Get the currently selected device.
         */
        suspend fun getSelectedDevice(): BluetoothDevice? {
            val address = bluetoothRepository.getSelectedDeviceAddress().first()
            if (address == null) return null
            return bluetoothRepository.getDevice(address)
        }

        /**
         * Get devices grouped by type.
         */
        fun getDevicesByType(): Flow<Map<BluetoothType, List<BluetoothDevice>>> {
            return bluetoothRepository.getScanResults()
                .map { devices -> devices.groupBy { it.type } }
        }

        /**
         * Get bonded (paired) devices.
         */
        fun getBondedDevices(): Flow<List<BluetoothDevice>> {
            return bluetoothRepository.getScanResults()
                .map { devices -> devices.filter { it.isBonded() } }
        }

        /**
         * Get BLE devices only.
         */
        fun getBleDevices(): Flow<List<BluetoothDevice>> {
            return bluetoothRepository.getScanResults()
                .map { devices -> devices.filter { it.isBle() } }
        }

        /**
         * Get Classic Bluetooth devices only.
         */
        fun getClassicDevices(): Flow<List<BluetoothDevice>> {
            return bluetoothRepository.getScanResults()
                .map { devices -> devices.filter { it.isClassic() } }
        }

        /**
         * Get devices with strong signal strength.
         */
        fun getNearbyDevices(thresholdRssi: Int = -70): Flow<List<BluetoothDevice>> {
            return bluetoothRepository.getScanResults()
                .map { devices ->
                    devices.filter { it.rssi != null && it.rssi!! >= thresholdRssi }
                        .sortedByDescending { it.rssi }
                }
        }

        /**
         * Get scan statistics.
         */
        suspend fun getScanStatistics(): ScanStatistics {
            val devices = bluetoothRepository.getScanResults().first()
            return ScanStatistics(
                totalDevices = devices.size,
                classicDevices = devices.count { it.isClassic() },
                bleDevices = devices.count { it.isBle() },
                bondedDevices = devices.count { it.isBonded() },
                deviceTypes = devices.groupBy { it.deviceClass }.mapValues { it.value.size },
            )
        }
    }

/**
 * Result of scan start request.
 */
sealed class ScanResult {
    data object Started : ScanResult()

    data object ConsentRequired : ScanResult()

    data object NotAuthorized : ScanResult()

    data object ActionNotAllowed : ScanResult()

    data object OutsideValidWindow : ScanResult()

    data class Error(val message: String) : ScanResult()
}

/**
 * Scan statistics summary.
 */
data class ScanStatistics(
    val totalDevices: Int,
    val classicDevices: Int,
    val bleDevices: Int,
    val bondedDevices: Int,
    val deviceTypes: Map<DeviceClass?, Int>,
)
