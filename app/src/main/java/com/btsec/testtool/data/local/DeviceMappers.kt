/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import android.util.Base64
import com.btsec.testtool.data.local.entity.BluetoothDeviceEntity
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.DeviceClass
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import java.time.Instant

// ---------- BluetoothDeviceEntity <-> BluetoothDevice ----------

fun BluetoothDeviceEntity.toDomain(): BluetoothDevice {
    val servicesList: List<String> = try {
        mapperJson.decodeFromString<List<String>>(services)
    } catch (_: Exception) {
        emptyList()
    }

    val manufacturerDataMap: Map<Int, ByteArray> = try {
        val raw: Map<String, String> = mapperJson.decodeFromString<Map<String, String>>(manufacturerData)
        raw.mapKeys { it.key.toIntOrNull() ?: 0 }
            .mapValues { Base64.decode(it.value, Base64.DEFAULT) }
    } catch (_: Exception) {
        emptyMap()
    }

    return BluetoothDevice(
        address = address,
        name = name,
        type = try { BluetoothType.valueOf(type) } catch (_: Exception) { BluetoothType.UNKNOWN },
        deviceClass = deviceClass?.let { try { DeviceClass.valueOf(it) } catch (_: Exception) { null } },
        bondState = try { BondState.valueOf(bondState) } catch (_: Exception) { BondState.NONE },
        rssi = rssi,
        txPower = txPower,
        firstSeen = Instant.ofEpochMilli(firstSeen),
        lastSeen = Instant.ofEpochMilli(lastSeen),
        scanCount = scanCount,
        services = servicesList,
        manufacturerData = manufacturerDataMap
    )
}

fun BluetoothDevice.toEntity(): BluetoothDeviceEntity {
    val servicesJson = mapperJson.encodeToString(services)
    val manufacturerDataJson = mapperJson.encodeToString(
        manufacturerData.mapKeys { it.key.toString() }
            .mapValues { Base64.encodeToString(it.value, Base64.DEFAULT) }
    )
    return BluetoothDeviceEntity(
        address = address,
        name = name,
        type = type.name,
        deviceClass = deviceClass?.name,
        bondState = bondState.name,
        rssi = rssi,
        txPower = txPower,
        firstSeen = firstSeen.toEpochMilli(),
        lastSeen = lastSeen.toEpochMilli(),
        scanCount = scanCount,
        services = servicesJson,
        manufacturerData = manufacturerDataJson
    )
}

// ---------- Collection mappers ----------

fun List<BluetoothDeviceEntity>.toDomainDevices(): List<BluetoothDevice> =
    map { it.toDomain() }

fun List<BluetoothDevice>.toEntities(): List<BluetoothDeviceEntity> =
    map { it.toEntity() }
