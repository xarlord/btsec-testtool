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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject

/**
 * Use case for Bluetooth device scanning.
 *
 * All scanning operations require valid authorization and consent.
 */
class BluetoothScanningUseCase @Inject constructor(
    private val bluetoothRepository: BluetoothRepository,
    private val authorizationUseCase: AuthorizationUseCase,
    private val consentRepository: ConsentRepository
) {

    /**
     * Start scanning for Bluetooth devices.
     *
     * @param filter Optional device address filter
     * @return Result of scan start
     */
    suspend fun startScan(filter: String? = null): ScanResult {
        // Check authorization
        val authResult = authorizationUseCase.requestActionAuthorization(
            TestAction.SCAN_DEVICES,
            getDeviceInfo()
        )

        when (authResult) {
            is ActionAuthorizationResult.Authorized -> {
                // Authorization granted, start scan
                bluetoothRepository.startScan(filter)
                return ScanResult.Started
            }
            is ActionAuthorizationResult.ConsentDenied -> {
                return ScanResult.ConsentRequired
            }
            is ActionAuthorizationResult.NoAuthorization -> {
                return ScanResult.NotAuthorized
            }
            is ActionAuthorizationResult.ActionNotAllowed -> {
                return ScanResult.ActionNotAllowed
            }
            is ActionAuthorizationResult.OutsideValidWindow -> {
                return ScanResult.OutsideValidWindow
            }
        }
    }

    /**
     * Stop scanning for devices.
     */
    suspend fun stopScan() {
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
     * Get devices grouped by type.
     */
    fun getDevicesByType(): Flow<Map<DeviceType, List<BluetoothDevice>>> {
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
            bleDevices = devices.count { it.isBle() },
            classicDevices = devices.count { it.isClassic() },
            bondedDevices = devices.count { it.isBonded() },
            deviceTypes = devices.groupBy { it.deviceClass }.mapValues { it.value.size }
        )
    }

    /**
     * Check if device is in authorized scope.
     */
    suspend fun isDeviceInScope(address: String): Boolean {
        return authorizationUseCase.isTargetInScope(address)
    }

    /**
     * Filter devices to only those in scope.
     */
    fun getInScopeDevices(): Flow<List<BluetoothDevice>> {
        return bluetoothRepository.getScanResults()
            .map { devices -> devices.filter { device ->
                authorizationUseCase.isTargetInScope(device.address)
            } }
    }

    private fun getDeviceInfo(): DeviceInfo {
        return DeviceInfo(
            platform = android.os.Build.MANUFACTURER,
            model = android.os.Build.MODEL,
            androidVersion = android.os.Build.VERSION.RELEASE,
            appVersion = "1.0.0",
            bluetoothAddress = "TESTING"  // Would get actual address in production
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
    val bleDevices: Int,
    val classicDevices: Int,
    val bondedDevices: Int,
    val deviceTypes: Map<DeviceClass?, Int>
)
