/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bluetooth

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice as AndroidBluetoothDevice
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.DeviceClass
import kotlinx.coroutines.flow.MutableStateFlow
import timber.log.Timber
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Helper class encapsulating BLE scan operations extracted from BluetoothRepositoryImpl.
 *
 * Responsible for starting/stopping scans, processing scan results, and
 * maintaining scan-related state (isScanning flag, scanResults list).
 */
@Singleton
class ScanOperationsHelper @Inject constructor() {

    val scanResults = MutableStateFlow<List<BluetoothDevice>>(emptyList())
    val isScanning = MutableStateFlow(false)

    /**
     * Build the [ScanSettings] used for BLE scans (low-latency mode).
     */
    fun buildScanSettings(): ScanSettings {
        return ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setReportDelay(0)
            .build()
    }

    /**
     * Process a single [ScanResult] into a domain [BluetoothDevice], applying the
     * optional [filter] address, and updating the internal scan results list.
     */
    @SuppressLint("MissingPermission")
    fun processScanResult(
        result: ScanResult,
        filter: String?,
        emit: (BluetoothDevice) -> Unit
    ) {
        result.device?.let { device ->
            val btDevice = mapScanResult(device, result)
            if (filter == null || device.address == filter) {
                emit(btDevice)
                updateScanResults(btDevice)
            }
        }
    }

    /**
     * Mark scanning as stopped.
     */
    fun markScanStopped() {
        isScanning.value = false
    }

    /**
     * Mark scanning as started.
     */
    fun markScanStarted() {
        isScanning.value = true
    }

    /**
     * Clear all cached scan results.
     */
    fun clearScanResults() {
        scanResults.value = emptyList()
    }

    // ========== Internal helpers ==========

    private fun updateScanResults(device: BluetoothDevice) {
        val current = scanResults.value.toMutableList()
        val existingIndex = current.indexOfFirst { it.address == device.address }
        if (existingIndex >= 0) {
            current[existingIndex] = device
        } else {
            current.add(device)
        }
        scanResults.value = current
    }

    @SuppressLint("MissingPermission")
    private fun mapScanResult(
        device: AndroidBluetoothDevice,
        result: ScanResult
    ): BluetoothDevice {
        return BluetoothDevice(
            address = device.address,
            name = device.name,
            type = if (device.type == AndroidBluetoothDevice.DEVICE_TYPE_LE) {
                BluetoothType.BLE
            } else if (device.type == AndroidBluetoothDevice.DEVICE_TYPE_CLASSIC) {
                BluetoothType.CLASSIC
            } else {
                BluetoothType.DUAL_MODE
            },
            deviceClass = mapDeviceClass(device.bluetoothClass?.deviceClass),
            bondState = when (device.bondState) {
                AndroidBluetoothDevice.BOND_BONDED -> BondState.BONDED
                AndroidBluetoothDevice.BOND_BONDING -> BondState.BONDING
                else -> BondState.NONE
            },
            rssi = result.rssi,
            txPower = result.txPower,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
            scanCount = 1,
            services = result.scanRecord?.serviceUuids?.map { it.toString() } ?: emptyList(),
            manufacturerData = emptyMap()
        )
    }

    private fun mapDeviceClass(deviceClass: Int?): DeviceClass? {
        if (deviceClass == null) return null
        return when ((deviceClass shr 8) and 0x1F) {
            1 -> DeviceClass.COMPUTER
            2 -> DeviceClass.PHONE
            4 -> DeviceClass.AUDIO_VIDEO
            5 -> DeviceClass.PERIPHERAL
            7 -> DeviceClass.WEARABLE
            8 -> DeviceClass.TOY
            9 -> DeviceClass.HEALTH
            else -> DeviceClass.UNCATEGORIZED
        }
    }
}
