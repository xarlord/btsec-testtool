/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bluetooth

import android.annotation.SuppressLint
import android.bluetooth.*
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.ConnectionPriority
import com.btsec.testtool.domain.repository.WriteType
import timber.log.Timber
import java.time.Instant

/**
 * Extension functions for mapping Android Bluetooth types to domain models.
 */

@SuppressLint("MissingPermission")
fun android.bluetooth.BluetoothDevice.toDomainModel(): com.btsec.testtool.domain.model.BluetoothDevice {
    return com.btsec.testtool.domain.model.BluetoothDevice(
        address = address,
        name = name,
        type = when (type) {
            android.bluetooth.BluetoothDevice.DEVICE_TYPE_LE -> BluetoothType.BLE
            android.bluetooth.BluetoothDevice.DEVICE_TYPE_CLASSIC -> BluetoothType.CLASSIC
            android.bluetooth.BluetoothDevice.DEVICE_TYPE_DUAL -> BluetoothType.DUAL_MODE
            else -> BluetoothType.UNKNOWN
        },
        deviceClass = bluetoothClass?.deviceClass?.let { mapDeviceClass(it) },
        bondState = when (bondState) {
            android.bluetooth.BluetoothDevice.BOND_BONDED -> BondState.BONDED
            android.bluetooth.BluetoothDevice.BOND_BONDING -> BondState.BONDING
            else -> BondState.NONE
        },
        rssi = null,
        txPower = null,
        firstSeen = Instant.now(),
        lastSeen = Instant.now(),
        services = emptyList(),
        manufacturerData = emptyMap()
    )
}

internal fun mapDeviceClass(deviceClass: Int): DeviceClass {
    // Major class mapping from Bluetooth spec
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

fun BluetoothGattService.toDomainModel(): BleService {
    return BleService(
        uuid = uuid.toString(),
        primary = type == BluetoothGattService.SERVICE_TYPE_PRIMARY,
        characteristics = characteristics.map { it.toDomainModel() }
    )
}

fun BluetoothGattCharacteristic.toDomainModel(): BleCharacteristic {
    val props = properties
    return BleCharacteristic(
        uuid = uuid.toString(),
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
        value = value,
        descriptors = descriptors.map { it.toDomainModel() }
    )
}

fun BluetoothGattDescriptor.toDomainModel(): BleDescriptor {
    return BleDescriptor(
        uuid = uuid.toString(),
        value = value
    )
}

fun ConnectionPriority.toAndroidInt(): Int {
    return when (this) {
        ConnectionPriority.BALANCED -> BluetoothGatt.CONNECTION_PRIORITY_BALANCED
        ConnectionPriority.HIGH -> BluetoothGatt.CONNECTION_PRIORITY_HIGH
        ConnectionPriority.LOW_POWER -> BluetoothGatt.CONNECTION_PRIORITY_LOW_POWER
    }
}

fun WriteType.toAndroidInt(): Int {
    return when (this) {
        WriteType.DEFAULT -> BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        WriteType.WITHOUT_RESPONSE -> BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        WriteType.SIGNED -> BluetoothGattCharacteristic.WRITE_TYPE_SIGNED
    }
}

/**
 * Refresh the GATT cache using reflection.
 * The refresh() method is hidden in the Android API.
 */
@SuppressLint("MissingPermission")
fun BluetoothGatt.refreshCache(): Boolean {
    return try {
        val method = BluetoothGatt::class.java.getDeclaredMethod("refresh")
        method.isAccessible = true
        method.invoke(this) as? Boolean ?: false
    } catch (e: NoSuchMethodException) {
        Timber.d(e, "GATT refresh method not available on this device")
        false
    } catch (e: SecurityException) {
        Timber.d(e, "GATT refresh method not accessible")
        false
    } catch (e: Exception) {
        Timber.d(e, "GATT cache refresh failed")
        false
    }
}
