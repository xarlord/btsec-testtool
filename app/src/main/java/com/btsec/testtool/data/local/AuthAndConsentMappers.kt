/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import com.btsec.testtool.data.local.entity.AuditLogEntity
import com.btsec.testtool.data.local.entity.AuthorizationEntity
import com.btsec.testtool.data.local.entity.BtOperationEntity
import com.btsec.testtool.data.local.entity.ConsentRecordEntity
import com.btsec.testtool.domain.model.Authorization
import com.btsec.testtool.domain.model.ConsentRecord
import com.btsec.testtool.domain.model.DeviceInfo
import com.btsec.testtool.domain.model.TestAction
import com.btsec.testtool.domain.model.TestScope
import com.btsec.testtool.domain.repository.AuditLogEntry
import com.btsec.testtool.domain.repository.BluetoothOperation
import com.btsec.testtool.domain.repository.OperationType
import kotlinx.serialization.encodeToString
import timber.log.Timber
import java.time.Instant

// ---------- AuthorizationEntity <-> Authorization ----------

fun AuthorizationEntity.toDomain(): Authorization {
    val actions =
        authorizedActions.split(",")
            .filter { it.isNotBlank() }
            .mapNotNull {
                try {
                    TestAction.valueOf(it.trim())
                } catch (_: Exception) {
                    null
                }
            }
            .toSet()

    val scope: TestScope =
        try {
            mapperJson.decodeFromString<TestScope>(scope)
        } catch (e: Exception) {
            Timber.w(e, "Failed to parse TestScope for auth $authId, using fallback")
            // Fallback: create minimal scope
            TestScope(
                authId = authId,
                authorizedTargets = emptyList(),
                allowedActions = actions,
                validFrom = Instant.ofEpochMilli(issuedAt),
                validUntil = Instant.ofEpochMilli(expiresAt),
                disclosureDeadline = Instant.ofEpochMilli(expiresAt),
            )
        }

    val termsList: List<String> =
        try {
            mapperJson.decodeFromString<List<String>>(terms)
        } catch (_: Exception) {
            emptyList()
        }

    return Authorization(
        authId = authId,
        issuedTo = issuedTo,
        issuedBy = issuedBy,
        issuedAt = Instant.ofEpochMilli(issuedAt),
        expiresAt = Instant.ofEpochMilli(expiresAt),
        authorizedActions = actions,
        scope = scope,
        signature = signature,
        terms = termsList,
    )
}

fun Authorization.toEntity(): AuthorizationEntity {
    val actionsStr = authorizedActions.joinToString(",") { it.name }
    val scopeJson = mapperJson.encodeToString(scope)
    val termsJson = mapperJson.encodeToString(terms)
    return AuthorizationEntity(
        authId = authId,
        issuedTo = issuedTo,
        issuedBy = issuedBy,
        issuedAt = issuedAt.toEpochMilli(),
        expiresAt = expiresAt.toEpochMilli(),
        authorizedActions = actionsStr,
        scope = scopeJson,
        signature = signature,
        terms = termsJson,
    )
}

// ---------- ConsentRecordEntity <-> ConsentRecord ----------

fun ConsentRecordEntity.toDomain(): ConsentRecord {
    val deviceInfo: DeviceInfo =
        try {
            mapperJson.decodeFromString<DeviceInfo>(deviceInfo)
        } catch (_: Exception) {
            DeviceInfo("", "", "", "", "")
        }
    return ConsentRecord(
        id = id,
        authId = authId,
        action = action,
        timestamp = Instant.ofEpochMilli(timestamp),
        authorized = authorized,
        deviceInfo = deviceInfo,
        userSignature = userSignature,
    )
}

fun ConsentRecord.toEntity(): ConsentRecordEntity {
    return ConsentRecordEntity(
        id = id,
        authId = authId,
        action = action,
        timestamp = timestamp.toEpochMilli(),
        authorized = authorized,
        deviceInfo = mapperJson.encodeToString(deviceInfo),
        userSignature = userSignature,
    )
}

// ---------- AuditLogEntity <-> AuditLogEntry ----------

fun AuditLogEntity.toDomain(): AuditLogEntry {
    val deviceInfo: DeviceInfo =
        try {
            mapperJson.decodeFromString<DeviceInfo>(deviceInfo)
        } catch (_: Exception) {
            DeviceInfo("", "", "", "", "")
        }
    val metadataMap: Map<String, String> =
        try {
            mapperJson.decodeFromString<Map<String, String>>(metadata)
        } catch (_: Exception) {
            emptyMap()
        }
    return AuditLogEntry(
        id = id,
        authId = authId,
        timestamp = Instant.ofEpochMilli(timestamp),
        operation = operation,
        success = success,
        errorMessage = errorMessage,
        deviceInfo = deviceInfo,
        durationMs = durationMs,
        metadata = metadataMap,
    )
}

fun AuditLogEntry.toEntity(): AuditLogEntity {
    return AuditLogEntity(
        id = id,
        authId = authId,
        timestamp = timestamp.toEpochMilli(),
        operation = operation,
        success = success,
        errorMessage = errorMessage,
        deviceInfo = mapperJson.encodeToString(deviceInfo),
        durationMs = durationMs,
        metadata = mapperJson.encodeToString(metadata),
    )
}

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

// ---------- Collection mappers ----------

fun List<AuthorizationEntity>.toDomainAuthorizations(): List<Authorization> = map { it.toDomain() }

fun List<ConsentRecordEntity>.toDomainConsentRecords(): List<ConsentRecord> = map { it.toDomain() }

fun List<AuditLogEntity>.toDomainAuditLogEntries(): List<AuditLogEntry> = map { it.toDomain() }

fun List<BtOperationEntity>.toDomainOperations(): List<BluetoothOperation> = map { it.toDomain() }
