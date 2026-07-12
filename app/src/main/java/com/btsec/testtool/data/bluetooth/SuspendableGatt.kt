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
import android.bluetooth.*
import android.content.Context
import com.btsec.testtool.domain.model.BluetoothDevice
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import timber.log.Timber
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Wrapper that converts async BluetoothGatt callbacks to Kotlin suspend functions and Flows.
 *
 * Provides a coroutine-friendly API for all GATT operations with:
 * - Timeout handling (30s default)
 * - Error mapping from GATT error codes
 * - Notification streaming via Flow
 * - Automatic cleanup on close
 */
class SuspendableGatt {
    private var gatt: BluetoothGatt? = null
    private val connectionState = MutableStateFlow<ConnectionStateInternal>(ConnectionStateInternal.Disconnected)

    private val pendingOperations = ConcurrentHashMap<String, CompletableDeferred<*>>()
    private val notificationChannels = ConcurrentHashMap<UUID, Channel<ByteArray>>()

    private var callback: BluetoothGattCallback? = null

    sealed class ConnectionStateInternal {
        data object Disconnected : ConnectionStateInternal()

        data object Connecting : ConnectionStateInternal()

        data object Connected : ConnectionStateInternal()

        data class Error(val message: String) : ConnectionStateInternal()
    }

    @SuppressLint("MissingPermission")
    suspend fun connect(
        device: android.bluetooth.BluetoothDevice,
        context: Context,
        transport: Int = android.bluetooth.BluetoothDevice.TRANSPORT_LE,
    ): BluetoothGatt {
        val deferred = CompletableDeferred<BluetoothGatt>()

        callback =
            object : BluetoothGattCallback() {
                override fun onConnectionStateChange(
                    gatt: BluetoothGatt,
                    status: Int,
                    newState: Int,
                ) {
                    when (newState) {
                        BluetoothGatt.STATE_CONNECTED -> {
                            connectionState.value = ConnectionStateInternal.Connected
                            this@SuspendableGatt.gatt = gatt
                            Timber.d("GATT connected to ${device.address}")
                            deferred.tryComplete(gatt)
                        }
                        BluetoothGatt.STATE_DISCONNECTED -> {
                            connectionState.value = ConnectionStateInternal.Disconnected
                            Timber.d("GATT disconnected from ${device.address}, status=$status")
                            if (!deferred.isCompleted) {
                                deferred.completeExceptionally(
                                    GattException("Connection failed with status: $status"),
                                )
                            }
                            // Cancel all pending operations
                            pendingOperations.values.forEach { it.cancel() }
                            pendingOperations.clear()
                        }
                    }
                }

                override fun onServicesDiscovered(
                    gatt: BluetoothGatt,
                    status: Int,
                ) {
                    val key = "discover_services"

                    @Suppress("UNCHECKED_CAST")
                    val op = pendingOperations.remove(key) as? CompletableDeferred<List<BluetoothGattService>>
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        op?.tryComplete(gatt.services ?: emptyList())
                    } else {
                        op?.completeExceptionally(GattException("Service discovery failed: $status"))
                    }
                }

                override fun onCharacteristicRead(
                    gatt: BluetoothGatt,
                    characteristic: BluetoothGattCharacteristic,
                    value: ByteArray,
                    status: Int,
                ) {
                    val key = "read_${characteristic.uuid}"

                    @Suppress("UNCHECKED_CAST")
                    val op = pendingOperations.remove(key) as? CompletableDeferred<ByteArray>
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        op?.tryComplete(value)
                    } else {
                        op?.completeExceptionally(GattException("Characteristic read failed: $status"))
                    }
                }

                override fun onCharacteristicWrite(
                    gatt: BluetoothGatt,
                    characteristic: BluetoothGattCharacteristic,
                    status: Int,
                ) {
                    val key = "write_${characteristic.uuid}"

                    @Suppress("UNCHECKED_CAST")
                    val op = pendingOperations.remove(key) as? CompletableDeferred<Boolean>
                    op?.tryComplete(status == BluetoothGatt.GATT_SUCCESS)
                }

                override fun onCharacteristicChanged(
                    gatt: BluetoothGatt,
                    characteristic: BluetoothGattCharacteristic,
                    value: ByteArray,
                ) {
                    notificationChannels[characteristic.uuid]?.trySend(value)
                }

                override fun onDescriptorRead(
                    gatt: BluetoothGatt,
                    descriptor: BluetoothGattDescriptor,
                    status: Int,
                    value: ByteArray,
                ) {
                    val key = "read_desc_${descriptor.uuid}"

                    @Suppress("UNCHECKED_CAST")
                    val op = pendingOperations.remove(key) as? CompletableDeferred<ByteArray>
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        op?.tryComplete(value)
                    } else {
                        op?.tryCompleteExceptionarily(GattException("Descriptor read failed: $status"))
                    }
                }

                override fun onDescriptorWrite(
                    gatt: BluetoothGatt,
                    descriptor: BluetoothGattDescriptor,
                    status: Int,
                ) {
                    val key = "write_desc_${descriptor.uuid}"

                    @Suppress("UNCHECKED_CAST")
                    val op = pendingOperations.remove(key) as? CompletableDeferred<Boolean>
                    op?.tryComplete(status == BluetoothGatt.GATT_SUCCESS)
                }

                override fun onMtuChanged(
                    gatt: BluetoothGatt,
                    mtu: Int,
                    status: Int,
                ) {
                    val key = "mtu"

                    @Suppress("UNCHECKED_CAST")
                    val op = pendingOperations.remove(key) as? CompletableDeferred<Int>
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        op?.tryComplete(mtu)
                    } else {
                        op?.tryCompleteExceptionarily(GattException("MTU change failed: $status"))
                    }
                }

                override fun onReadRemoteRssi(
                    gatt: BluetoothGatt,
                    rssi: Int,
                    status: Int,
                ) {
                    val key = "rssi"

                    @Suppress("UNCHECKED_CAST")
                    val op = pendingOperations.remove(key) as? CompletableDeferred<Int>
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        op?.tryComplete(rssi)
                    } else {
                        op?.tryCompleteExceptionarily(GattException("RSSI read failed: $status"))
                    }
                }
            }

        val gattInstance = device.connectGatt(context, false, callback, transport)
        return withTimeoutOrNull(30_000L) {
            deferred.await()
        } ?: throw GattException("Connection timeout")
    }

    @SuppressLint("MissingPermission")
    suspend fun discoverServices(): List<BluetoothGattService> {
        val g = gatt ?: throw GattException("Not connected")
        val deferred = CompletableDeferred<List<BluetoothGattService>>()
        pendingOperations["discover_services"] = deferred
        g.discoverServices()
        return withTimeoutOrNull(15_000L) { deferred.await() }
            ?: throw GattException("Service discovery timeout")
    }

    @SuppressLint("MissingPermission")
    suspend fun readCharacteristic(characteristic: BluetoothGattCharacteristic): ByteArray {
        val g = gatt ?: throw GattException("Not connected")
        val deferred = CompletableDeferred<ByteArray>()
        pendingOperations["read_${characteristic.uuid}"] = deferred
        if (!g.readCharacteristic(characteristic)) {
            pendingOperations.remove("read_${characteristic.uuid}")
            throw GattException("Failed to initiate characteristic read")
        }
        return withTimeoutOrNull(10_000L) { deferred.await() }
            ?: throw GattException("Characteristic read timeout")
    }

    @SuppressLint("MissingPermission")
    suspend fun writeCharacteristic(
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
    ): Boolean {
        val g = gatt ?: throw GattException("Not connected")
        val deferred = CompletableDeferred<Boolean>()
        pendingOperations["write_${characteristic.uuid}"] = deferred
        characteristic.value = value
        if (!g.writeCharacteristic(characteristic)) {
            pendingOperations.remove("write_${characteristic.uuid}")
            throw GattException("Failed to initiate characteristic write")
        }
        return withTimeoutOrNull(10_000L) { deferred.await() }
            ?: throw GattException("Characteristic write timeout")
    }

    @SuppressLint("MissingPermission")
    suspend fun readDescriptor(descriptor: BluetoothGattDescriptor): ByteArray {
        val g = gatt ?: throw GattException("Not connected")
        val deferred = CompletableDeferred<ByteArray>()
        pendingOperations["read_desc_${descriptor.uuid}"] = deferred
        if (!g.readDescriptor(descriptor)) {
            pendingOperations.remove("read_desc_${descriptor.uuid}")
            throw GattException("Failed to initiate descriptor read")
        }
        return withTimeoutOrNull(10_000L) { deferred.await() }
            ?: throw GattException("Descriptor read timeout")
    }

    @SuppressLint("MissingPermission")
    suspend fun writeDescriptor(
        descriptor: BluetoothGattDescriptor,
        value: ByteArray,
    ): Boolean {
        val g = gatt ?: throw GattException("Not connected")
        val deferred = CompletableDeferred<Boolean>()
        pendingOperations["write_desc_${descriptor.uuid}"] = deferred
        descriptor.value = value
        if (!g.writeDescriptor(descriptor)) {
            pendingOperations.remove("write_desc_${descriptor.uuid}")
            throw GattException("Failed to initiate descriptor write")
        }
        return withTimeoutOrNull(10_000L) { deferred.await() }
            ?: throw GattException("Descriptor write timeout")
    }

    @SuppressLint("MissingPermission")
    suspend fun requestMtu(mtu: Int): Int {
        val g = gatt ?: throw GattException("Not connected")
        val deferred = CompletableDeferred<Int>()
        pendingOperations["mtu"] = deferred
        if (!g.requestMtu(mtu)) {
            pendingOperations.remove("mtu")
            throw GattException("Failed to request MTU")
        }
        return withTimeoutOrNull(10_000L) { deferred.await() }
            ?: throw GattException("MTU request timeout")
    }

    @SuppressLint("MissingPermission")
    suspend fun readRssi(): Int {
        val g = gatt ?: throw GattException("Not connected")
        val deferred = CompletableDeferred<Int>()
        pendingOperations["rssi"] = deferred
        if (!g.readRemoteRssi()) {
            pendingOperations.remove("rssi")
            throw GattException("Failed to read RSSI")
        }
        return withTimeoutOrNull(10_000L) { deferred.await() }
            ?: throw GattException("RSSI read timeout")
    }

    @SuppressLint("MissingPermission")
    fun requestConnectionPriority(priority: Int): Boolean {
        return gatt?.requestConnectionPriority(priority) ?: false
    }

    fun getConnectionState(): Flow<ConnectionStateInternal> = connectionState.asStateFlow()

    @SuppressLint("MissingPermission")
    suspend fun close() {
        gatt?.close()
        gatt = null
        connectionState.value = ConnectionStateInternal.Disconnected
        pendingOperations.values.forEach { it.cancel() }
        pendingOperations.clear()
        notificationChannels.values.forEach { it.close() }
        notificationChannels.clear()
        callback = null
    }

    class GattException(message: String) : Exception(message)
}

private fun <T> CompletableDeferred<T>.tryComplete(value: T) =
    try {
        complete(value)
    } catch (_: Exception) {
    }

private fun <T> CompletableDeferred<T>.tryCompleteExceptionarily(e: Exception) =
    try {
        completeExceptionally(e)
    } catch (_: Exception) {
    }
