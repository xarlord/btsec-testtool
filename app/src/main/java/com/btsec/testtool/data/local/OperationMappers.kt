/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import com.btsec.testtool.data.local.entity.BtOperationEntity
import com.btsec.testtool.domain.repository.BluetoothOperation
import com.btsec.testtool.domain.repository.OperationType
import kotlinx.serialization.encodeToString
import java.time.Instant

// ---------- BtOperationEntity <-> BluetoothOperation ----------

fun BtOperationEntity.toDomain(): BluetoothOperation {
    val metadataMap: Map<String, String> =
        try {
            mapperJson.decodeFromString<Map<String, String>>(metadata)
        } catch (_: Exception) {
            emptyMap()
        }
    return BluetoothOperation(
        id = id,
        timestamp = Instant.ofEpochMilli(timestamp),
        operationType =
            try {
                OperationType.valueOf(operationType)
            } catch (_: Exception) {
                OperationType.SCAN_START
            },
        deviceAddress = deviceAddress,
        success = success,
        errorMessage = errorMessage,
        durationMs = durationMs,
        metadata = metadataMap,
    )
}

fun BluetoothOperation.toEntity(): BtOperationEntity {
    return BtOperationEntity(
        id = id,
        timestamp = timestamp.toEpochMilli(),
        operationType = operationType.name,
        deviceAddress = deviceAddress,
        success = success,
        errorMessage = errorMessage,
        durationMs = durationMs,
        metadata = mapperJson.encodeToString(metadata),
    )
}

/** Map a list of BtOperationEntity entities to domain BluetoothOperation objects. */
fun List<BtOperationEntity>.toDomainOperations(): List<BluetoothOperation> = map { it.toDomain() }
