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
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import com.btsec.testtool.domain.model.BleCharacteristic
import com.btsec.testtool.domain.model.BleDescriptor
import com.btsec.testtool.domain.model.BleService
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.CharacteristicPermissions
import com.btsec.testtool.domain.model.CharacteristicProperties
import com.btsec.testtool.domain.model.ConnectionState
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.DeviceClass
import com.btsec.testtool.domain.model.FuzzConfig
import com.btsec.testtool.domain.model.FuzzDataPattern
import com.btsec.testtool.domain.model.FuzzError
import com.btsec.testtool.domain.model.FuzzMethod
import com.btsec.testtool.domain.repository.BluetoothRepository
import com.btsec.testtool.domain.repository.BluetoothState
import com.btsec.testtool.domain.repository.BluetoothOperation
import com.btsec.testtool.domain.repository.CapturedPacket
import com.btsec.testtool.domain.repository.ConnectionPriority
import com.btsec.testtool.domain.repository.PacketDirection
import com.btsec.testtool.domain.repository.PacketStatistics
import com.btsec.testtool.domain.repository.PacketType
import com.btsec.testtool.domain.repository.WriteType
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.time.Instant
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of Bluetooth repository.
 *
 * Interfaces with Android's Bluetooth stack for device scanning,
 * connection, and BLE operations.
 */
@Singleton
@android.annotation.SuppressLint("MissingPermission")
class BluetoothRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context
) : BluetoothRepository {

    private val bluetoothManager: BluetoothManager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager.adapter

    private val bluetoothState = MutableStateFlow(BluetoothState.OFF)
    private val scanResults = MutableStateFlow<List<BluetoothDevice>>(emptyList())
    private val isScanning = MutableStateFlow(false)
    private val connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    private val connectedDevice = MutableStateFlow<BluetoothDevice?>(null)
    private val discoveredServices = MutableStateFlow<List<BleService>>(emptyList())

    private var currentGatt: BluetoothGatt? = null

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
        // In production, would show dialog to user
        // For now, just check state
        return bluetoothAdapter?.isEnabled == true
    }

    // ========== Device Scanning ==========

    @SuppressLint("MissingPermission")  // Permissions checked before use
    override fun startScan(filter: String?): Flow<BluetoothDevice> {
        return callbackFlow {
            val scanner = bluetoothAdapter?.bluetoothLeScanner
            if (scanner == null) {
                close()
                return@callbackFlow
            }

            isScanning.value = true

            val scanCallback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    result.device?.let { device ->
                        val btDevice = mapScanResult(device, result)
                        if (filter == null || device.address == filter) {
                            trySend(btDevice)
                            updateScanResults(btDevice)
                        }
                    }
                }

                override fun onBatchScanResults(results: MutableList<ScanResult>) {
                    results.forEach { result ->
                        result.device?.let { device ->
                            val btDevice = mapScanResult(device, result)
                            if (filter == null || device.address == filter) {
                                trySend(btDevice)
                                updateScanResults(btDevice)
                            }
                        }
                    }
                }

                override fun onScanFailed(errorCode: Int) {
                    // Handle scan failure
                    isScanning.value = false
                }
            }

            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setReportDelay(0)
                .build()

            scanner.startScan(scanCallback)

            awaitClose {
                scanner.stopScan(scanCallback)
                isScanning.value = false
            }
        }
    }

    override suspend fun stopScan() {
        bluetoothAdapter?.bluetoothLeScanner?.stopScan(object : ScanCallback() {})
        isScanning.value = false
    }

    override fun isScanning(): Flow<Boolean> {
        return isScanning
    }

    override fun getScanResults(): Flow<List<BluetoothDevice>> {
        return scanResults
    }

    override suspend fun getDevice(address: String): BluetoothDevice? {
        return scanResults.value.find { it.address == address }
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

            connectionState.value = ConnectionState.Connecting

            currentGatt = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                device.connectGatt(context, false, gattCallback, AndroidBluetoothDevice.TRANSPORT_LE)
            } else {
                device.connectGatt(context, false, gattCallback)
            }

            // Emit connection state updates
            connectionState.collect { state ->
                trySend(state)
            }

            awaitClose {
                currentGatt?.close()
                currentGatt = null
                connectionState.value = ConnectionState.Disconnected
            }
        }
    }

    override suspend fun disconnect() {
        currentGatt?.disconnect()
        currentGatt?.close()
        currentGatt = null
        connectionState.value = ConnectionState.Disconnected
        connectedDevice.value = null
    }

    override fun getConnectionState(): Flow<ConnectionState> {
        return connectionState
    }

    override fun getConnectedDevice(): Flow<BluetoothDevice?> {
        return connectedDevice
    }

    // ========== GATT Callback ==========

    private val gattCallback = object : CustomBluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            when (newState) {
                BluetoothGatt.STATE_CONNECTED -> {
                    connectionState.value = ConnectionState.Connected
                    connectedDevice.value = mapBluetoothDevice(gatt.device)
                    gatt.discoverServices()
                }
                BluetoothGatt.STATE_DISCONNECTED -> {
                    connectionState.value = ConnectionState.Disconnected
                    connectedDevice.value = null
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                val services = gatt.services?.map { mapGattService(it) } ?: emptyList()
                discoveredServices.value = services
            }
        }
    }

    // ========== BLE Operations ==========

    override fun discoverServices(): Flow<List<BleService>> {
        return discoveredServices
    }

    override fun getServices(): Flow<List<BleService>> {
        return discoveredServices
    }

    @SuppressLint("MissingPermission")
    override suspend fun readCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Result<ByteArray> {
        val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
        val service = gatt.getService(UUID.fromString(serviceUuid))
            ?: return Result.failure(Exception("Service not found"))
        val characteristic = service.getCharacteristic(UUID.fromString(characteristicUuid))
            ?: return Result.failure(Exception("Characteristic not found"))

        return if (gatt.readCharacteristic(characteristic)) {
            // Would need to wait for callback in production
            Result.success(byteArrayOf())
        } else {
            Result.failure(Exception("Read failed"))
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun writeCharacteristic(
        serviceUuid: String,
        characteristicUuid: String,
        value: ByteArray,
        writeType: WriteType
    ): Result<Unit> {
        val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
        val service = gatt.getService(UUID.fromString(serviceUuid))
            ?: return Result.failure(Exception("Service not found"))
        val characteristic = service.getCharacteristic(UUID.fromString(characteristicUuid))
            ?: return Result.failure(Exception("Characteristic not found"))

        characteristic.value = value
        characteristic.writeType = when (writeType) {
            WriteType.DEFAULT -> BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            WriteType.WITHOUT_RESPONSE -> BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
            WriteType.SIGNED -> BluetoothGattCharacteristic.WRITE_TYPE_SIGNED
        }

        return if (gatt.writeCharacteristic(characteristic)) {
            Result.success(Unit)
        } else {
            Result.failure(Exception("Write failed"))
        }
    }

    override fun subscribeToCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Flow<ByteArray> {
        // Implementation would set up notifications and return data as Flow
        return flow { }
    }

    override suspend fun unsubscribeFromCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Result<Unit> {
        // Implementation would disable notifications
        return Result.success(Unit)
    }

    override suspend fun readDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String
    ): Result<ByteArray> {
        return Result.failure(Exception("Not implemented"))
    }

    override suspend fun writeDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String,
        value: ByteArray
    ): Result<Unit> {
        return Result.failure(Exception("Not implemented"))
    }

    override suspend fun requestMtu(mtu: Int): Result<Int> {
        val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
        return if (gatt.requestMtu(mtu)) {
            Result.success(mtu)
        } else {
            Result.failure(Exception("MTU request failed"))
        }
    }

    override fun getCurrentMtu(): Flow<Int> {
        return flow { emit(23) }  // Default BLE MTU
    }

    override suspend fun requestConnectionPriority(priority: ConnectionPriority): Result<Unit> {
        return Result.failure(Exception("Not implemented"))
    }

    @SuppressLint("MissingPermission")
    override suspend fun readRssi(): Result<Int> {
        val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
        return if (gatt.readRemoteRssi()) {
            Result.success(-60)  // Would return actual RSSI from callback
        } else {
            Result.failure(Exception("RSSI read failed"))
        }
    }

    // ========== Bonding ==========

    @SuppressLint("MissingPermission")
    override suspend fun createBond(address: String): Boolean {
        val device = bluetoothAdapter?.getRemoteDevice(address)
        return device?.createBond() ?: false
    }

    @SuppressLint("MissingPermission")
    override suspend fun removeBond(address: String): Boolean {
        val device = bluetoothAdapter?.getRemoteDevice(address) ?: return false
        return try {
            // removeBond() is a hidden API, need to use reflection
            val method = device.javaClass.getDeclaredMethod("removeBond")
            method.isAccessible = true
            method.invoke(device) as Boolean
        } catch (e: Exception) {
            false
        }
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
        return Result.failure(Exception("Not implemented"))
    }

    override suspend fun clearDeviceCache() {
        scanResults.value = emptyList()
    }

    override fun getCachedDevices(): Flow<List<BluetoothDevice>> {
        return scanResults
    }

    // ========== Packet Monitoring ==========

    override fun startPacketMonitoring(): Flow<CapturedPacket> {
        // Would require root and monitor mode
        return flow { }
    }

    override suspend fun stopPacketMonitoring() {
        // TODO: Implement packet monitoring
    }

    override suspend fun isPacketMonitoringAvailable(): Boolean {
        return false  // Requires root and specific hardware
    }

    override fun getPacketStatistics(): Flow<PacketStatistics> {
        return flow {
            emit(PacketStatistics(0, 0, 0, 0, 0, null, 0))
        }
    }

    // ========== Logging ==========

    override suspend fun logOperation(operation: BluetoothOperation) {
        // Would log to database for audit purposes
    }

    override fun getOperationLogs(): Flow<List<BluetoothOperation>> {
        return flow { emit(emptyList()) }
    }

    override suspend fun clearOperationLogs() {
        // Would clear logs from database
    }

    // ========== Helper Methods ==========

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
    private fun mapScanResult(device: android.bluetooth.BluetoothDevice, result: ScanResult): BluetoothDevice {
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

    @SuppressLint("MissingPermission")
    private fun mapBluetoothDevice(device: android.bluetooth.BluetoothDevice): BluetoothDevice {
        return BluetoothDevice(
            address = device.address,
            name = device.name,
            type = BluetoothType.BLE,
            deviceClass = null,
            bondState = when (device.bondState) {
                AndroidBluetoothDevice.BOND_BONDED -> BondState.BONDED
                AndroidBluetoothDevice.BOND_BONDING -> BondState.BONDING
                else -> BondState.NONE
            },
            rssi = null,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
            scanCount = 1,
            services = emptyList(),
            manufacturerData = emptyMap()
        )
    }

    private fun mapDeviceClass(deviceClass: Int?): DeviceClass? {
        // TODO: Implement device class mapping
        return com.btsec.testtool.domain.model.DeviceClass.UNCATEGORIZED
    }

    private fun mapGattService(service: android.bluetooth.BluetoothGattService): BleService {
        return BleService(
            uuid = service.uuid.toString(),
            primary = service.type == android.bluetooth.BluetoothGattService.SERVICE_TYPE_PRIMARY,
            characteristics = service.characteristics.map { mapGattCharacteristic(it) }
        )
    }

    private fun mapGattCharacteristic(
        characteristic: android.bluetooth.BluetoothGattCharacteristic
    ): BleCharacteristic {
        val props = characteristic.properties
        return BleCharacteristic(
            uuid = characteristic.uuid.toString(),
            properties = CharacteristicProperties(
                read = props and BluetoothGattCharacteristic.PROPERTY_READ != 0,
                write = props and BluetoothGattCharacteristic.PROPERTY_WRITE != 0,
                writeWithoutResponse = props and BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE != 0,
                notify = props and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0,
                indicate = props and BluetoothGattCharacteristic.PROPERTY_INDICATE != 0,
                signedWrite = props and BluetoothGattCharacteristic.PROPERTY_SIGNED_WRITE != 0,
                extendedProperties = props and BluetoothGattCharacteristic.PROPERTY_EXTENDED_PROPS != 0
            ),
            permissions = null,
            value = characteristic.value,
            descriptors = characteristic.descriptors.map {
                BleDescriptor(it.uuid.toString(), it.value)
            }
        )
    }
}

/**
 * Custom GATT callback class to avoid conflicts.
 */
abstract class CustomBluetoothGattCallback : android.bluetooth.BluetoothGattCallback() {
    override fun onConnectionStateChange(gatt: android.bluetooth.BluetoothGatt, status: Int, newState: Int) {}
    override fun onServicesDiscovered(gatt: android.bluetooth.BluetoothGatt, status: Int) {}
}
