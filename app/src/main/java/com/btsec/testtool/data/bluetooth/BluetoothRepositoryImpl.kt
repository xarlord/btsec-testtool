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
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.os.Build
import com.btsec.testtool.domain.model.BleService
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.ConnectionState
import com.btsec.testtool.data.local.dao.BluetoothDao
import com.btsec.testtool.data.local.*
import com.btsec.testtool.domain.repository.BluetoothRepository
import com.btsec.testtool.domain.repository.BluetoothState
import com.btsec.testtool.domain.repository.BluetoothOperation
import com.btsec.testtool.domain.repository.CapturedPacket
import com.btsec.testtool.domain.repository.ConnectionPriority
import com.btsec.testtool.domain.repository.PacketStatistics
import com.btsec.testtool.domain.repository.WriteType
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import timber.log.Timber
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of Bluetooth repository.
 *
 * Interfaces with Android's Bluetooth stack for device scanning,
 * connection, and BLE operations.
 *
 * Operations are delegated to:
 * - [ScanOperationsHelper] for BLE scanning
 * - [GattOperationsHelper] for GATT connect/read/write/subscribe/MTU/RSSI
 * - [ReflectionHelper] for safe hidden-API reflection calls
 */
@Singleton
class BluetoothRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context,
    private val bluetoothDao: BluetoothDao,
    private val scanHelper: ScanOperationsHelper,
    private val gattHelper: GattOperationsHelper
) : BluetoothRepository {

    private val bluetoothManager: BluetoothManager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager.adapter

    private val bluetoothState = MutableStateFlow(BluetoothState.OFF)
    private val selectedDeviceAddress = MutableStateFlow<String?>(null)
    private var suspendableGatt: SuspendableGatt? = null

    // ========== Bluetooth State ==========

    override fun isBluetoothEnabled(): Flow<Boolean> {
        return flow {
            emit(bluetoothAdapter?.isEnabled == true)
        }
    }

    override fun getBluetoothState(): Flow<BluetoothState> {
        return bluetoothState
    }

    override suspend fun requestEnableBluetooth(): Boolean {
        if (bluetoothAdapter?.isEnabled == true) return true
        return false
    }

    // ========== Device Scanning ==========

    @SuppressLint("MissingPermission")
    override fun startScan(filter: String?): Flow<BluetoothDevice> {
        return callbackFlow {
            val scanner = bluetoothAdapter?.bluetoothLeScanner
            if (scanner == null) {
                close()
                return@callbackFlow
            }

            scanHelper.markScanStarted()

            val scanCallback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    scanHelper.processScanResult(result, filter) { trySend(it) }
                }

                override fun onBatchScanResults(results: MutableList<ScanResult>) {
                    results.forEach { result ->
                        scanHelper.processScanResult(result, filter) { trySend(it) }
                    }
                }

                override fun onScanFailed(errorCode: Int) {
                    scanHelper.markScanStopped()
                }
            }

            scanner.startScan(scanCallback)

            awaitClose {
                scanner.stopScan(scanCallback)
                scanHelper.markScanStopped()
            }
        }
    }

    override suspend fun stopScan() {
        bluetoothAdapter?.bluetoothLeScanner?.stopScan(object : ScanCallback() {})
        scanHelper.markScanStopped()
    }

    override fun isScanning(): Flow<Boolean> = scanHelper.isScanning

    override fun getScanResults(): Flow<List<BluetoothDevice>> = scanHelper.scanResults

    override suspend fun getDevice(address: String): BluetoothDevice? {
        return scanHelper.scanResults.value.find { it.address == address }
    }

    // ========== Selected Device ==========

    override fun getSelectedDeviceAddress(): Flow<String?> = selectedDeviceAddress

    override fun selectDevice(address: String?) {
        selectedDeviceAddress.value = address
    }

    // ========== Device Connection ==========

    @SuppressLint("MissingPermission")
    override fun connect(address: String, timeoutMs: Int): Flow<ConnectionState> {
        return callbackFlow {
            val device = bluetoothAdapter?.getRemoteDevice(address)
            if (device == null) {
                trySend(ConnectionState.Error("Device not found"))
                close()
                return@callbackFlow
            }

            gattHelper.connectionState.value = ConnectionState.Connecting

            val gatt = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                device.connectGatt(context, false, gattCallback, AndroidBluetoothDevice.TRANSPORT_LE)
            } else {
                device.connectGatt(context, false, gattCallback)
            }

            gattHelper.setGatt(gatt)

            gattHelper.connectionState.collect { state ->
                trySend(state)
            }

            awaitClose {
                gattHelper.getGatt()?.close()
                gattHelper.setGatt(null)
                gattHelper.connectionState.value = ConnectionState.Disconnected
            }
        }
    }

    override suspend fun disconnect() {
        val gatt = gattHelper.getGatt()
        gatt?.disconnect()
        gatt?.close()
        gattHelper.setGatt(null)
        gattHelper.connectionState.value = ConnectionState.Disconnected
        gattHelper.connectedDevice.value = null
    }

    override fun getConnectionState(): Flow<ConnectionState> = gattHelper.connectionState

    override fun getConnectedDevice(): Flow<BluetoothDevice?> = gattHelper.connectedDevice

    // ========== GATT Callback ==========

    private val gattCallback = object : CustomBluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            gattHelper.onConnectionStateChanged(gatt, newState)
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            gattHelper.onServicesDiscovered(gatt, status)
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int
        ) {
            gattHelper.onCharacteristicRead(characteristic, value, status)
        }

        // Legacy callback for API < 33
        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            @Suppress("DEPRECATION")
            val value = characteristic.value ?: byteArrayOf()
            onCharacteristicRead(gatt, characteristic, value, status)
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            gattHelper.onCharacteristicChanged(characteristic, value)
        }

        // Legacy callback for API < 33
        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic
        ) {
            @Suppress("DEPRECATION")
            val value = characteristic.value ?: byteArrayOf()
            onCharacteristicChanged(gatt, characteristic, value)
        }

        override fun onDescriptorRead(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int,
            value: ByteArray
        ) {
            gattHelper.onDescriptorRead(descriptor, status, value)
        }

        // Legacy callback for API < 33
        @Deprecated("Deprecated in API 33")
        override fun onDescriptorRead(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            @Suppress("DEPRECATION")
            val value = descriptor.value ?: byteArrayOf()
            onDescriptorRead(gatt, descriptor, status, value)
        }
    }

    // ========== BLE Operations ==========

    override fun discoverServices(): Flow<List<BleService>> = gattHelper.discoveredServices

    override fun getServices(): Flow<List<BleService>> = gattHelper.discoveredServices

    override suspend fun readCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Result<ByteArray> = gattHelper.readCharacteristic(serviceUuid, characteristicUuid)

    override suspend fun writeCharacteristic(
        serviceUuid: String,
        characteristicUuid: String,
        value: ByteArray,
        writeType: WriteType
    ): Result<Unit> = gattHelper.writeCharacteristic(serviceUuid, characteristicUuid, value, writeType)

    @SuppressLint("MissingPermission")
    override fun subscribeToCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Flow<ByteArray> = callbackFlow {
        val gatt = gattHelper.getGatt()
        if (gatt == null) {
            Timber.w("subscribeToCharacteristic: not connected")
            close()
            return@callbackFlow
        }

        val service = gatt.getService(UUID.fromString(serviceUuid))
        if (service == null) {
            Timber.w("subscribeToCharacteristic: service not found: $serviceUuid")
            close()
            return@callbackFlow
        }

        val characteristic = service.getCharacteristic(UUID.fromString(characteristicUuid))
        if (characteristic == null) {
            Timber.w("subscribeToCharacteristic: characteristic not found: $characteristicUuid")
            close()
            return@callbackFlow
        }

        // Write to CCC descriptor to enable notifications
        val cccUuid = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        val cccDescriptor = characteristic.getDescriptor(cccUuid)

        // Set up notification listener for this characteristic
        val targetUuid = UUID.fromString(characteristicUuid)
        val previousListener = gattHelper.getNotificationListener()
        gattHelper.setNotificationListener { uuid, value ->
            if (uuid == targetUuid) {
                trySend(value)
            }
            previousListener?.invoke(uuid, value)
        }

        // Enable local notification
        if (!gatt.setCharacteristicNotification(characteristic, true)) {
            Timber.w("subscribeToCharacteristic: setCharacteristicNotification failed")
            gattHelper.setNotificationListener(previousListener)
            close()
            return@callbackFlow
        }

        // Write CCC descriptor to enable remote notifications
        if (cccDescriptor != null) {
            cccDescriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            gatt.writeDescriptor(cccDescriptor)
            Timber.d("subscribeToCharacteristic: wrote CCC descriptor for $characteristicUuid")
        } else {
            Timber.w("subscribeToCharacteristic: no CCC descriptor found for $characteristicUuid")
        }

        awaitClose {
            Timber.d("subscribeToCharacteristic: cleaning up $characteristicUuid")
            gattHelper.setNotificationListener(previousListener)
            try {
                gatt.setCharacteristicNotification(characteristic, false)
                if (cccDescriptor != null) {
                    cccDescriptor.value = BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
                    gatt.writeDescriptor(cccDescriptor)
                }
            } catch (e: Exception) {
                Timber.e(e, "Error cleaning up notification subscription")
            }
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun unsubscribeFromCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Result<Unit> {
        val gatt = gattHelper.getGatt() ?: return Result.failure(Exception("Not connected"))
        val service = gatt.getService(UUID.fromString(serviceUuid))
            ?: return Result.failure(Exception("Service not found: $serviceUuid"))
        val characteristic = service.getCharacteristic(UUID.fromString(characteristicUuid))
            ?: return Result.failure(Exception("Characteristic not found: $characteristicUuid"))

        return try {
            if (!gatt.setCharacteristicNotification(characteristic, false)) {
                Timber.w("unsubscribeFromCharacteristic: setCharacteristicNotification(false) failed")
            }
            val cccUuid = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
            val cccDescriptor = characteristic.getDescriptor(cccUuid)
            if (cccDescriptor != null) {
                cccDescriptor.value = BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
                gatt.writeDescriptor(cccDescriptor)
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "unsubscribeFromCharacteristic error")
            Result.failure(e)
        }
    }

    override suspend fun readDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String
    ): Result<ByteArray> = gattHelper.readDescriptor(serviceUuid, characteristicUuid, descriptorUuid)

    override suspend fun writeDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String,
        value: ByteArray
    ): Result<Unit> = gattHelper.writeDescriptor(serviceUuid, characteristicUuid, descriptorUuid, value)

    override suspend fun requestMtu(mtu: Int): Result<Int> = gattHelper.requestMtu(mtu)

    override fun getCurrentMtu(): Flow<Int> = gattHelper.currentMtu.asStateFlow()

    override suspend fun requestConnectionPriority(priority: ConnectionPriority): Result<Unit> =
        gattHelper.requestConnectionPriority(priority)

    override suspend fun readRssi(): Result<Int> = gattHelper.readRssi()

    // ========== Bonding ==========

    @SuppressLint("MissingPermission")
    override suspend fun createBond(address: String): Boolean {
        val device = bluetoothAdapter?.getRemoteDevice(address)
        return device?.createBond() ?: false
    }

    @SuppressLint("MissingPermission")
    override suspend fun removeBond(address: String): Boolean {
        val device = bluetoothAdapter?.getRemoteDevice(address) ?: return false
        return gattHelper.removeBond(device)
    }

    override fun getBondState(address: String): Flow<BondState> {
        val device = bluetoothAdapter?.getRemoteDevice(address)
        return flow {
            val state = when (device?.bondState) {
                AndroidBluetoothDevice.BOND_NONE -> BondState.NONE
                AndroidBluetoothDevice.BOND_BONDING -> BondState.BONDING
                AndroidBluetoothDevice.BOND_BONDED -> BondState.BONDED
                else -> BondState.NONE
            }
            emit(state)
        }
    }

    // ========== Device Cache ==========

    override suspend fun refreshCache(): Result<Unit> {
        return try {
            val gatt = gattHelper.getGatt() ?: return Result.failure(Exception("Not connected"))
            val refreshed = gattHelper.refreshGattCache(gatt)
            if (refreshed) {
                Timber.d("GATT cache refreshed successfully")
                Result.success(Unit)
            } else {
                Timber.w("GATT cache refresh returned false")
                Result.failure(Exception("GATT cache refresh failed"))
            }
        } catch (e: Exception) {
            Timber.e(e, "refreshCache error")
            Result.failure(e)
        }
    }

    override suspend fun clearDeviceCache() {
        scanHelper.clearScanResults()
    }

    override fun getCachedDevices(): Flow<List<BluetoothDevice>> = scanHelper.scanResults

    // ========== Packet Monitoring ==========

    override fun startPacketMonitoring(): Flow<CapturedPacket> {
        return flow { }
    }

    override suspend fun stopPacketMonitoring() {
        // TODO: Implement packet monitoring
    }

    override suspend fun isPacketMonitoringAvailable(): Boolean {
        return false
    }

    override fun getPacketStatistics(): Flow<PacketStatistics> {
        return flow {
            emit(PacketStatistics(0, 0, 0, 0, 0, null, 0))
        }
    }

    // ========== Logging ==========

    override suspend fun logOperation(operation: BluetoothOperation) {
        try {
            bluetoothDao.insertOperation(operation.toEntity())
        } catch (e: Exception) {
            Timber.e(e, "Failed to persist bluetooth operation log")
        }
    }

    override fun getOperationLogs(): Flow<List<BluetoothOperation>> {
        return bluetoothDao.getAllOperations().map { entities ->
            entities.toDomainOperations()
        }
    }

    override suspend fun clearOperationLogs() {
        try {
            bluetoothDao.deleteAllOperations()
        } catch (e: Exception) {
            Timber.e(e, "Failed to clear bluetooth operation logs")
        }
    }
}

/**
 * Custom GATT callback class to avoid conflicts.
 */
abstract class CustomBluetoothGattCallback : android.bluetooth.BluetoothGattCallback() {
    override fun onConnectionStateChange(gatt: android.bluetooth.BluetoothGatt, status: Int, newState: Int) {}
    override fun onServicesDiscovered(gatt: android.bluetooth.BluetoothGatt, status: Int) {}
}
