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
import com.btsec.testtool.data.local.dao.BluetoothDao
import com.btsec.testtool.data.local.toDomain
import com.btsec.testtool.data.local.toDomainOperations
import com.btsec.testtool.data.local.toEntity
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import timber.log.Timber
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Implementation of Bluetooth repository.
 *
 * Interfaces with Android's Bluetooth stack for device scanning,
 * connection, and BLE operations.
 */
@Singleton
class BluetoothRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context,
    private val bluetoothDao: BluetoothDao
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
    private var suspendableGatt: SuspendableGatt? = null

    // Pending coroutine continuations for GATT callback resolution
    private val pendingReads = ConcurrentHashMap<String, (Result<ByteArray>) -> Unit>()
    private val pendingDescriptorReads = ConcurrentHashMap<String, (Result<ByteArray>) -> Unit>()
    private var notificationListener: ((UUID, ByteArray) -> Unit)? = null

    // Track actual negotiated MTU
    private val currentMtu = MutableStateFlow(23)

    // Currently selected device for testing operations
    private val selectedDeviceAddress = MutableStateFlow<String?>(null)

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
        // Cannot programmatically enable BT on modern Android — must use system intent.
        // Return current state; the UI layer should launch ACTION_REQUEST_ENABLE intent.
        return false
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

    // ========== Selected Device ==========

    override fun getSelectedDeviceAddress(): Flow<String?> {
        return selectedDeviceAddress
    }

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
                    // Cancel any pending reads on disconnect
                    pendingReads.values.forEach { callback ->
                        callback(Result.failure(Exception("GATT disconnected")))
                    }
                    pendingReads.clear()
                    pendingDescriptorReads.values.forEach { callback ->
                        callback(Result.failure(Exception("GATT disconnected")))
                    }
                    pendingDescriptorReads.clear()
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                val services = gatt.services?.map { mapGattService(it) } ?: emptyList()
                discoveredServices.value = services
            }
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int
        ) {
            val key = characteristic.uuid.toString()
            val callback = pendingReads.remove(key)
            if (callback != null) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    Timber.d("Characteristic read success: ${characteristic.uuid}, ${value.size} bytes")
                    callback(Result.success(value))
                } else {
                    Timber.w("Characteristic read failed: ${characteristic.uuid}, status=$status")
                    callback(Result.failure(Exception("Characteristic read failed with status: $status")))
                }
            }
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
            Timber.d("Notification received: ${characteristic.uuid}, ${value.size} bytes")
            notificationListener?.invoke(characteristic.uuid, value)
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
            val key = "${descriptor.characteristic.uuid}_${descriptor.uuid}"
            val callback = pendingDescriptorReads.remove(key)
            if (callback != null) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    Timber.d("Descriptor read success: ${descriptor.uuid}, ${value.size} bytes")
                    callback(Result.success(value))
                } else {
                    Timber.w("Descriptor read failed: ${descriptor.uuid}, status=$status")
                    callback(Result.failure(Exception("Descriptor read failed with status: $status")))
                }
            }
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
            ?: return Result.failure(Exception("Service not found: $serviceUuid"))
        val characteristic = service.getCharacteristic(UUID.fromString(characteristicUuid))
            ?: return Result.failure(Exception("Characteristic not found: $characteristicUuid"))

        return try {
            suspendCancellableCoroutine { cont ->
                val key = characteristicUuid
                pendingReads[key] = { result ->
                    if (cont.isActive) {
                        cont.resume(result)
                    }
                }
                cont.invokeOnCancellation {
                    pendingReads.remove(key)
                }

                if (!gatt.readCharacteristic(characteristic)) {
                    pendingReads.remove(key)
                    if (cont.isActive) {
                        cont.resume(Result.failure(Exception("Failed to initiate characteristic read")))
                    }
                }
            }
        } catch (e: CancellationException) {
            pendingReads.remove(characteristicUuid)
            Timber.w("readCharacteristic cancelled: $characteristicUuid")
            Result.failure(Exception("Operation cancelled"))
        } catch (e: Exception) {
            Timber.e(e, "readCharacteristic error: $characteristicUuid")
            Result.failure(e)
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

    @SuppressLint("MissingPermission")
    override fun subscribeToCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Flow<ByteArray> = callbackFlow {
        val gatt = currentGatt
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
        val previousListener = notificationListener
        notificationListener = { uuid, value ->
            if (uuid == targetUuid) {
                trySend(value)
            }
            previousListener?.invoke(uuid, value)
        }

        // Enable local notification
        if (!gatt.setCharacteristicNotification(characteristic, true)) {
            Timber.w("subscribeToCharacteristic: setCharacteristicNotification failed")
            notificationListener = previousListener
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
            notificationListener = previousListener
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
        val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
        val service = gatt.getService(UUID.fromString(serviceUuid))
            ?: return Result.failure(Exception("Service not found: $serviceUuid"))
        val characteristic = service.getCharacteristic(UUID.fromString(characteristicUuid))
            ?: return Result.failure(Exception("Characteristic not found: $characteristicUuid"))

        return try {
            // Disable local notification
            if (!gatt.setCharacteristicNotification(characteristic, false)) {
                Timber.w("unsubscribeFromCharacteristic: setCharacteristicNotification(false) failed")
            }
            // Write CCC descriptor to disable remote notifications
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

    @SuppressLint("MissingPermission")
    override suspend fun readDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String
    ): Result<ByteArray> {
        val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
        val service = gatt.getService(UUID.fromString(serviceUuid))
            ?: return Result.failure(Exception("Service not found: $serviceUuid"))
        val characteristic = service.getCharacteristic(UUID.fromString(characteristicUuid))
            ?: return Result.failure(Exception("Characteristic not found: $characteristicUuid"))
        val descriptor = characteristic.getDescriptor(UUID.fromString(descriptorUuid))
            ?: return Result.failure(Exception("Descriptor not found: $descriptorUuid"))

        return try {
            suspendCancellableCoroutine { cont ->
                val key = "${characteristicUuid}_${descriptorUuid}"
                pendingDescriptorReads[key] = { result ->
                    if (cont.isActive) {
                        cont.resume(result)
                    }
                }
                cont.invokeOnCancellation {
                    pendingDescriptorReads.remove(key)
                }

                if (!gatt.readDescriptor(descriptor)) {
                    pendingDescriptorReads.remove(key)
                    if (cont.isActive) {
                        cont.resume(Result.failure(Exception("Failed to initiate descriptor read")))
                    }
                }
            }
        } catch (e: CancellationException) {
            pendingDescriptorReads.remove("${characteristicUuid}_${descriptorUuid}")
            Timber.w("readDescriptor cancelled: $descriptorUuid")
            Result.failure(Exception("Operation cancelled"))
        } catch (e: Exception) {
            Timber.e(e, "readDescriptor error: $descriptorUuid")
            Result.failure(e)
        }
    }

    override suspend fun writeDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String,
        value: ByteArray
    ): Result<Unit> {
        return try {
            val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
            val service = gatt.getService(UUID.fromString(serviceUuid))
                ?: return Result.failure(Exception("Service not found: $serviceUuid"))
            val characteristic = service.getCharacteristic(UUID.fromString(characteristicUuid))
                ?: return Result.failure(Exception("Characteristic not found: $characteristicUuid"))
            val descriptor = characteristic.getDescriptor(UUID.fromString(descriptorUuid))
                ?: return Result.failure(Exception("Descriptor not found: $descriptorUuid"))

            val sgatt = suspendableGatt
            if (sgatt != null) {
                val success = sgatt.writeDescriptor(descriptor, value)
                if (success) Result.success(Unit) else Result.failure(Exception("Descriptor write failed"))
            } else {
                // Fallback: direct write without callback
                descriptor.value = value
                val written = gatt.writeDescriptor(descriptor)
                if (written) Result.success(Unit) else Result.failure(Exception("Descriptor write initiation failed"))
            }
        } catch (e: Exception) {
            Timber.e(e, "writeDescriptor error")
            Result.failure(e)
        }
    }

    override suspend fun requestMtu(mtu: Int): Result<Int> {
        return try {
            val sgatt = suspendableGatt
            if (sgatt != null) {
                val negotiated = sgatt.requestMtu(mtu)
                currentMtu.value = negotiated
                Result.success(negotiated)
            } else {
                val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
                if (gatt.requestMtu(mtu)) {
                    currentMtu.value = mtu
                    Result.success(mtu)
                } else {
                    Result.failure(Exception("MTU request failed"))
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "requestMtu error")
            Result.failure(e)
        }
    }

    override fun getCurrentMtu(): Flow<Int> = currentMtu.asStateFlow()

    override suspend fun requestConnectionPriority(priority: ConnectionPriority): Result<Unit> {
        return try {
            val sgatt = suspendableGatt
            val success = if (sgatt != null) {
                sgatt.requestConnectionPriority(priority.toAndroidInt())
            } else {
                currentGatt?.requestConnectionPriority(priority.toAndroidInt()) ?: false
            }
            if (success) Result.success(Unit) else Result.failure(Exception("Connection priority request failed"))
        } catch (e: Exception) {
            Timber.e(e, "requestConnectionPriority error")
            Result.failure(e)
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun readRssi(): Result<Int> {
        return try {
            val sgatt = suspendableGatt
            if (sgatt != null) {
                val rssi = sgatt.readRssi()
                Result.success(rssi)
            } else {
                val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
                if (gatt.readRemoteRssi()) {
                    // Without SuspendableGatt we can't get the callback result
                    // Return a placeholder indicating async operation initiated
                    Timber.w("readRssi called without SuspendableGatt — using fallback")
                    Result.success(-60)
                } else {
                    Result.failure(Exception("RSSI read failed"))
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "readRssi error")
            Result.failure(e)
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
            Timber.w(e, "removeBond failed for device %s", address)
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
        return try {
            val gatt = currentGatt ?: return Result.failure(Exception("Not connected"))
            val refreshed = gatt.refreshCache()
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
