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
import android.bluetooth.BluetoothDevice as AndroidBluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import com.btsec.testtool.domain.model.BleCharacteristic
import com.btsec.testtool.domain.model.BleDescriptor
import com.btsec.testtool.domain.model.BleService
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.CharacteristicProperties
import com.btsec.testtool.domain.model.ConnectionState
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.DeviceClass
import com.btsec.testtool.domain.repository.ConnectionPriority
import com.btsec.testtool.domain.repository.WriteType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import timber.log.Timber
import java.lang.ref.WeakReference
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume

/**
 * Helper class encapsulating GATT operations extracted from BluetoothRepositoryImpl.
 *
 * Responsible for reading/writing characteristics and descriptors, subscribing to
 * notifications, MTU negotiation, RSSI reads, connection priority, GATT callback
 * management, and service mapping.
 */
@Singleton
class GattOperationsHelper @Inject constructor(
    private val reflectionHelper: ReflectionHelper
) {

    val connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    val connectedDevice = MutableStateFlow<BluetoothDevice?>(null)
    val discoveredServices = MutableStateFlow<List<BleService>>(emptyList())
    val currentMtu = MutableStateFlow(23)

    // Weak reference to avoid leaking the GATT object
    private var gattRef: WeakReference<BluetoothGatt> = WeakReference(null)
    private var suspendableGatt: SuspendableGatt? = null

    // Pending coroutine continuations for GATT callback resolution
    private val pendingReads = ConcurrentHashMap<String, (Result<ByteArray>) -> Unit>()
    private val pendingDescriptorReads = ConcurrentHashMap<String, (Result<ByteArray>) -> Unit>()
    private var notificationListener: ((UUID, ByteArray) -> Unit)? = null

    /**
     * Set the current GATT connection reference.
     */
    fun setGatt(gatt: BluetoothGatt?) {
        gattRef = WeakReference(gatt)
    }

    /**
     * Set the SuspendableGatt wrapper.
     */
    fun setSuspendableGatt(sgatt: SuspendableGatt?) {
        suspendableGatt = sgatt
    }

    /**
     * Get the current BluetoothGatt instance.
     */
    fun getGatt(): BluetoothGatt? = gattRef.get()

    /**
     * Read a BLE characteristic value.
     */
    @SuppressLint("MissingPermission")
    suspend fun readCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Result<ByteArray> {
        val gatt = gattRef.get() ?: return Result.failure(Exception("Not connected"))
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

    /**
     * Write a value to a BLE characteristic.
     */
    @SuppressLint("MissingPermission")
    suspend fun writeCharacteristic(
        serviceUuid: String,
        characteristicUuid: String,
        value: ByteArray,
        writeType: WriteType
    ): Result<Unit> {
        val gatt = gattRef.get() ?: return Result.failure(Exception("Not connected"))
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

    /**
     * Get the notification listener so the GATT callback can dispatch.
     */
    fun getNotificationListener(): ((UUID, ByteArray) -> Unit)? = notificationListener

    /**
     * Set the notification listener.
     */
    fun setNotificationListener(listener: ((UUID, ByteArray) -> Unit)?) {
        notificationListener = listener
    }

    /**
     * Read a BLE descriptor value.
     */
    @SuppressLint("MissingPermission")
    suspend fun readDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String
    ): Result<ByteArray> {
        val gatt = gattRef.get() ?: return Result.failure(Exception("Not connected"))
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

    /**
     * Write a value to a BLE descriptor.
     */
    @SuppressLint("MissingPermission")
    suspend fun writeDescriptor(
        serviceUuid: String,
        characteristicUuid: String,
        descriptorUuid: String,
        value: ByteArray
    ): Result<Unit> {
        return try {
            val gatt = gattRef.get() ?: return Result.failure(Exception("Not connected"))
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

    /**
     * Request MTU negotiation.
     */
    suspend fun requestMtu(mtu: Int): Result<Int> {
        return try {
            val sgatt = suspendableGatt
            if (sgatt != null) {
                val negotiated = sgatt.requestMtu(mtu)
                currentMtu.value = negotiated
                Result.success(negotiated)
            } else {
                val gatt = gattRef.get() ?: return Result.failure(Exception("Not connected"))
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

    /**
     * Request connection priority change.
     */
    suspend fun requestConnectionPriority(priority: ConnectionPriority): Result<Unit> {
        return try {
            val sgatt = suspendableGatt
            val success = if (sgatt != null) {
                sgatt.requestConnectionPriority(priority.toAndroidInt())
            } else {
                gattRef.get()?.requestConnectionPriority(priority.toAndroidInt()) ?: false
            }
            if (success) Result.success(Unit) else Result.failure(Exception("Connection priority request failed"))
        } catch (e: Exception) {
            Timber.e(e, "requestConnectionPriority error")
            Result.failure(e)
        }
    }

    /**
     * Read RSSI of connected device.
     */
    @SuppressLint("MissingPermission")
    suspend fun readRssi(): Result<Int> {
        return try {
            val sgatt = suspendableGatt
            if (sgatt != null) {
                val rssi = sgatt.readRssi()
                Result.success(rssi)
            } else {
                val gatt = gattRef.get() ?: return Result.failure(Exception("Not connected"))
                if (gatt.readRemoteRssi()) {
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

    /**
     * Remove bond (unpair) using reflection via [ReflectionHelper].
     */
    @SuppressLint("MissingPermission")
    fun removeBond(device: AndroidBluetoothDevice): Boolean {
        val result = reflectionHelper.invokeHiddenMethod(
            target = device,
            clazz = AndroidBluetoothDevice::class.java,
            methodName = "removeBond"
        )
        return result.getOrNull() as? Boolean ?: false
    }

    /**
     * Refresh the GATT cache using reflection via [ReflectionHelper].
     */
    @SuppressLint("MissingPermission")
    fun refreshGattCache(gatt: BluetoothGatt): Boolean {
        val result = reflectionHelper.invokeHiddenMethod(
            target = gatt,
            clazz = BluetoothGatt::class.java,
            methodName = "refresh"
        )
        return result.getOrNull() as? Boolean ?: false
    }

    /**
     * Cancel all pending reads (e.g. on disconnect).
     */
    fun cancelPendingReads() {
        pendingReads.values.forEach { callback ->
            callback(Result.failure(Exception("GATT disconnected")))
        }
        pendingReads.clear()
        pendingDescriptorReads.values.forEach { callback ->
            callback(Result.failure(Exception("GATT disconnected")))
        }
        pendingDescriptorReads.clear()
    }

    // ========== GATT Callback dispatching ==========

    /**
     * Handle characteristic read callback from the GATT callback.
     */
    fun onCharacteristicRead(characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
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

    /**
     * Handle characteristic changed (notification) callback.
     */
    fun onCharacteristicChanged(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        Timber.d("Notification received: ${characteristic.uuid}, ${value.size} bytes")
        notificationListener?.invoke(characteristic.uuid, value)
    }

    /**
     * Handle descriptor read callback from the GATT callback.
     */
    fun onDescriptorRead(descriptor: BluetoothGattDescriptor, status: Int, value: ByteArray) {
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

    /**
     * Handle services discovered callback.
     */
    fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
        if (status == BluetoothGatt.GATT_SUCCESS) {
            val services = gatt.services?.map { mapGattService(it) } ?: emptyList()
            discoveredServices.value = services
        }
    }

    /**
     * Handle connection state changed callback.
     */
    @SuppressLint("MissingPermission")
    fun onConnectionStateChanged(gatt: BluetoothGatt, newState: Int) {
        when (newState) {
            BluetoothGatt.STATE_CONNECTED -> {
                connectionState.value = ConnectionState.Connected
                connectedDevice.value = mapBluetoothDevice(gatt.device)
                gatt.discoverServices()
            }
            BluetoothGatt.STATE_DISCONNECTED -> {
                connectionState.value = ConnectionState.Disconnected
                connectedDevice.value = null
                cancelPendingReads()
            }
        }
    }

    // ========== Mapping helpers ==========

    @SuppressLint("MissingPermission")
    private fun mapBluetoothDevice(device: AndroidBluetoothDevice): BluetoothDevice {
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
