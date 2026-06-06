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
import androidx.room.TypeConverter
import com.btsec.testtool.data.local.entity.AuditLogEntity
import com.btsec.testtool.data.local.entity.AuthorizationEntity
import com.btsec.testtool.data.local.entity.BluetoothDeviceEntity
import com.btsec.testtool.data.local.entity.BtOperationEntity
import com.btsec.testtool.data.local.entity.ConsentRecordEntity
import com.btsec.testtool.data.local.entity.FuzzResultEntity
import com.btsec.testtool.data.local.entity.KeyExtractionResultEntity
import com.btsec.testtool.data.local.entity.SecurityReportEntity
import com.btsec.testtool.data.local.entity.VulnDefinitionEntity
import com.btsec.testtool.data.local.entity.VulnerabilityEntity
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.DeviceClass
import com.btsec.testtool.domain.model.VulnerabilityCategory
import com.btsec.testtool.domain.model.VulnerabilitySeverity
import com.btsec.testtool.domain.model.FuzzStatus
import com.btsec.testtool.domain.model.KeyType
import com.btsec.testtool.domain.model.ExtractionMethod
import com.btsec.testtool.domain.model.ExtractionConfidence
import com.btsec.testtool.domain.model.ReportStatus
import com.btsec.testtool.domain.model.TestAction
import com.btsec.testtool.domain.model.TestScope
import com.btsec.testtool.domain.model.TargetDevice
import com.btsec.testtool.domain.model.DeviceType
import com.btsec.testtool.domain.model.DeviceInfo
import com.btsec.testtool.domain.model.ConsentRecord
import com.btsec.testtool.domain.model.Authorization
import com.btsec.testtool.domain.model.Vulnerability
import com.btsec.testtool.domain.model.VulnerabilityDefinition
import com.btsec.testtool.domain.model.FuzzConfig
import com.btsec.testtool.domain.model.FuzzResult
import com.btsec.testtool.domain.model.FuzzError
import com.btsec.testtool.domain.model.FuzzFinding
import com.btsec.testtool.domain.model.ErrorSeverity
import com.btsec.testtool.domain.model.FindingCategory
import com.btsec.testtool.domain.model.FuzzMethod
import com.btsec.testtool.domain.model.PatternType
import com.btsec.testtool.domain.model.FuzzDataPattern
import com.btsec.testtool.domain.model.BleService
import com.btsec.testtool.domain.model.BleCharacteristic
import com.btsec.testtool.domain.model.CharacteristicProperties
import com.btsec.testtool.domain.model.KeyExtractionResult
import com.btsec.testtool.domain.model.SecurityReport
import com.btsec.testtool.domain.model.ReportPeriod
import com.btsec.testtool.domain.model.ReportFinding
import com.btsec.testtool.domain.model.Recommendation
import com.btsec.testtool.domain.model.RecommendationPriority
import com.btsec.testtool.domain.model.ReportAppendix
import com.btsec.testtool.domain.repository.AuditLogEntry
import com.btsec.testtool.domain.repository.BluetoothOperation
import com.btsec.testtool.domain.repository.OperationType
import com.btsec.testtool.domain.repository.AuthorizationStatus
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import timber.log.Timber
import java.time.Instant

/**
 * Room TypeConverters for complex types.
 *
 * Uses kotlinx.serialization for JSON conversion of complex nested objects,
 * comma-separated strings for enum sets, epoch millis for Instants,
 * and Base64 for ByteArrays.
 */
class BtSecTypeConverters {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    // ========== Instant ==========

    @TypeConverter
    fun fromInstant(instant: Instant?): Long? = instant?.toEpochMilli()

    @TypeConverter
    fun toInstant(epochMillis: Long?): Instant? =
        epochMillis?.let { Instant.ofEpochMilli(it) }
}

// ============================================================================
// Extension functions: Entity -> Domain
// ============================================================================

/**
 * JSON instance used by mapper extension functions.
 */
private val mapperJson = Json { ignoreUnknownKeys = true; encodeDefaults = true }

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

// ---------- AuthorizationEntity <-> Authorization ----------

fun AuthorizationEntity.toDomain(): Authorization {
    val actions = authorizedActions.split(",")
        .filter { it.isNotBlank() }
        .mapNotNull { try { TestAction.valueOf(it.trim()) } catch (_: Exception) { null } }
        .toSet()

    val scope: TestScope = try {
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
            disclosureDeadline = Instant.ofEpochMilli(expiresAt)
        )
    }

    val termsList: List<String> = try {
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
        terms = termsList
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
        terms = termsJson
    )
}

// ---------- ConsentRecordEntity <-> ConsentRecord ----------

fun ConsentRecordEntity.toDomain(): ConsentRecord {
    val deviceInfo: DeviceInfo = try {
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
        userSignature = userSignature
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
        userSignature = userSignature
    )
}

// ---------- AuditLogEntity <-> AuditLogEntry ----------

fun AuditLogEntity.toDomain(): AuditLogEntry {
    val deviceInfo: DeviceInfo = try {
        mapperJson.decodeFromString<DeviceInfo>(deviceInfo)
    } catch (_: Exception) {
        DeviceInfo("", "", "", "", "")
    }
    val metadataMap: Map<String, String> = try {
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
        metadata = metadataMap
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
        metadata = mapperJson.encodeToString(metadata)
    )
}

// ---------- BtOperationEntity <-> BluetoothOperation ----------

fun BtOperationEntity.toDomain(): BluetoothOperation {
    val metadataMap: Map<String, String> = try {
        mapperJson.decodeFromString<Map<String, String>>(metadata)
    } catch (_: Exception) {
        emptyMap()
    }
    return BluetoothOperation(
        id = id,
        timestamp = Instant.ofEpochMilli(timestamp),
        operationType = try { OperationType.valueOf(operationType) } catch (_: Exception) { OperationType.SCAN_START },
        deviceAddress = deviceAddress,
        success = success,
        errorMessage = errorMessage,
        durationMs = durationMs,
        metadata = metadataMap
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
        metadata = mapperJson.encodeToString(metadata)
    )
}

// ---------- VulnerabilityEntity <-> Vulnerability ----------

fun VulnerabilityEntity.toDomain(): Vulnerability {
    val affectedDevice: BluetoothDevice = try {
        mapperJson.decodeFromString<BluetoothDevice>(affectedDevice)
    } catch (e: Exception) {
        Timber.w(e, "Failed to parse affected device for vuln $cveId, using fallback")
        BluetoothDevice(
            address = affectedDeviceAddress,
            name = null,
            type = BluetoothType.UNKNOWN,
            deviceClass = null,
            bondState = BondState.NONE,
            rssi = null,
            txPower = null,
            firstSeen = Instant.ofEpochMilli(discoveredAt),
            lastSeen = Instant.ofEpochMilli(discoveredAt)
        )
    }

    val versions: List<String> = try {
        mapperJson.decodeFromString<List<String>>(affectedBluetoothVersions)
    } catch (_: Exception) {
        emptyList()
    }

    val refs: List<String> = try {
        mapperJson.decodeFromString<List<String>>(references)
    } catch (_: Exception) {
        emptyList()
    }

    return Vulnerability(
        id = id,
        cveId = cveId,
        name = name,
        description = description,
        severity = try { VulnerabilitySeverity.valueOf(severity) } catch (e: Exception) {
            Timber.w(e, "Unknown severity '$severity' for vuln $cveId, defaulting to INFORMATIONAL")
            VulnerabilitySeverity.INFORMATIONAL },
        cvssScore = cvssScore,
        affectedDevice = affectedDevice,
        discoveredAt = Instant.ofEpochMilli(discoveredAt),
        category = try { VulnerabilityCategory.valueOf(category) } catch (_: Exception) { VulnerabilityCategory.OTHER },
        affectedBluetoothVersions = versions,
        references = refs,
        mitigation = mitigation,
        verified = verified,
        notes = notes
    )
}

fun Vulnerability.toEntity(): VulnerabilityEntity {
    return VulnerabilityEntity(
        id = id,
        cveId = cveId,
        name = name,
        description = description,
        severity = severity.name,
        cvssScore = cvssScore,
        affectedDeviceAddress = affectedDevice.address,
        affectedDevice = mapperJson.encodeToString(affectedDevice),
        discoveredAt = discoveredAt.toEpochMilli(),
        category = category.name,
        affectedBluetoothVersions = mapperJson.encodeToString(affectedBluetoothVersions),
        references = mapperJson.encodeToString(references),
        mitigation = mitigation,
        verified = verified,
        notes = notes
    )
}

// ---------- VulnDefinitionEntity <-> VulnerabilityDefinition ----------

fun VulnDefinitionEntity.toDomain(): VulnerabilityDefinition {
    val profiles: List<String> = try {
        mapperJson.decodeFromString<List<String>>(affectedProfiles)
    } catch (_: Exception) {
        emptyList()
    }

    val refs: List<String> = try {
        mapperJson.decodeFromString<List<String>>(references)
    } catch (_: Exception) {
        emptyList()
    }

    return VulnerabilityDefinition(
        cveId = cveId,
        name = name,
        description = description,
        severity = try { VulnerabilitySeverity.valueOf(severity) } catch (_: Exception) { VulnerabilitySeverity.INFORMATIONAL },
        cvssScore = cvssScore,
        category = try { VulnerabilityCategory.valueOf(category) } catch (_: Exception) { VulnerabilityCategory.OTHER },
        affectedVersions = affectedVersions,
        affectedProfiles = profiles,
        yearDiscovered = yearDiscovered,
        references = refs,
        mitigation = mitigation,
        testMethodology = testMethodology
    )
}

fun VulnerabilityDefinition.toEntity(): VulnDefinitionEntity {
    return VulnDefinitionEntity(
        cveId = cveId,
        name = name,
        description = description,
        severity = severity.name,
        cvssScore = cvssScore,
        category = category.name,
        affectedVersions = affectedVersions,
        affectedProfiles = mapperJson.encodeToString(affectedProfiles),
        yearDiscovered = yearDiscovered,
        references = mapperJson.encodeToString(references),
        mitigation = mitigation,
        testMethodology = testMethodology
    )
}

// ---------- FuzzResultEntity <-> FuzzResult ----------

fun FuzzResultEntity.toDomain(): FuzzResult {
    val config: FuzzConfig = try {
        mapperJson.decodeFromString<FuzzConfig>(config)
    } catch (e: Exception) {
        Timber.e(e, "Cannot deserialize FuzzConfig for result $id")
        throw IllegalStateException("Cannot deserialize FuzzConfig for result $id", e)
    }

    val errorsList: List<FuzzError> = try {
        mapperJson.decodeFromString<List<FuzzError>>(errors)
    } catch (_: Exception) {
        emptyList()
    }

    val findingsList: List<FuzzFinding> = try {
        mapperJson.decodeFromString<List<FuzzFinding>>(findings)
    } catch (_: Exception) {
        emptyList()
    }

    return FuzzResult(
        id = id,
        config = config,
        startTime = Instant.ofEpochMilli(startTime),
        endTime = endTime?.let { Instant.ofEpochMilli(it) },
        status = try { FuzzStatus.valueOf(status) } catch (_: Exception) { FuzzStatus.ERROR },
        packetsSent = packetsSent,
        packetsReceived = packetsReceived,
        errors = errorsList,
        findings = findingsList,
        captureFile = captureFile,
        reportGenerated = reportGenerated
    )
}

fun FuzzResult.toEntity(): FuzzResultEntity {
    return FuzzResultEntity(
        id = id,
        targetDeviceAddress = config.targetDevice.address,
        config = mapperJson.encodeToString(config),
        startTime = startTime.toEpochMilli(),
        endTime = endTime?.toEpochMilli(),
        status = status.name,
        packetsSent = packetsSent,
        packetsReceived = packetsReceived,
        errors = mapperJson.encodeToString(errors),
        findings = mapperJson.encodeToString(findings),
        captureFile = captureFile,
        reportGenerated = reportGenerated
    )
}

// ---------- KeyExtractionResultEntity <-> KeyExtractionResult ----------

fun KeyExtractionResultEntity.toDomain(): KeyExtractionResult {
    val device: BluetoothDevice = try {
        mapperJson.decodeFromString<BluetoothDevice>(targetDevice)
    } catch (_: Exception) {
        BluetoothDevice(
            address = targetDeviceAddress,
            name = null,
            type = BluetoothType.UNKNOWN,
            deviceClass = null,
            bondState = BondState.NONE,
            rssi = null,
            txPower = null,
            firstSeen = Instant.ofEpochMilli(timestamp),
            lastSeen = Instant.ofEpochMilli(timestamp)
        )
    }

    return KeyExtractionResult(
        id = id,
        targetDevice = device,
        keyType = try { KeyType.valueOf(keyType) } catch (_: Exception) { KeyType.LTK },
        extracted = extracted,
        keyValue = keyValue?.let { Base64.decode(it, Base64.DEFAULT) },
        method = try { ExtractionMethod.valueOf(method) } catch (_: Exception) { ExtractionMethod.OTHER },
        confidence = try { ExtractionConfidence.valueOf(confidence) } catch (_: Exception) { ExtractionConfidence.UNKNOWN },
        timestamp = Instant.ofEpochMilli(timestamp),
        notes = notes
    )
}

fun KeyExtractionResult.toEntity(): KeyExtractionResultEntity {
    return KeyExtractionResultEntity(
        id = id,
        targetDeviceAddress = targetDevice.address,
        targetDevice = mapperJson.encodeToString(targetDevice),
        keyType = keyType.name,
        extracted = extracted,
        keyValue = keyValue?.let { Base64.encodeToString(it, Base64.DEFAULT) },
        method = method.name,
        confidence = confidence.name,
        timestamp = timestamp.toEpochMilli(),
        notes = notes
    )
}

// ---------- SecurityReportEntity <-> SecurityReport ----------

fun SecurityReportEntity.toDomain(): SecurityReport {
    val targetDevicesList: List<BluetoothDevice> = try {
        mapperJson.decodeFromString<List<BluetoothDevice>>(targetDevices)
    } catch (_: Exception) {
        emptyList()
    }

    val vulnerabilitiesList: List<Vulnerability> = try {
        mapperJson.decodeFromString<List<Vulnerability>>(vulnerabilities)
    } catch (_: Exception) {
        emptyList()
    }

    val fuzzingResultsList: List<FuzzResult> = try {
        mapperJson.decodeFromString<List<FuzzResult>>(fuzzingResults)
    } catch (_: Exception) {
        emptyList()
    }

    val keyResultsList: List<KeyExtractionResult> = try {
        mapperJson.decodeFromString<List<KeyExtractionResult>>(keyExtractionResults)
    } catch (_: Exception) {
        emptyList()
    }

    val findingsList: List<ReportFinding> = try {
        mapperJson.decodeFromString<List<ReportFinding>>(findings)
    } catch (_: Exception) {
        emptyList()
    }

    val recommendationsList: List<Recommendation> = try {
        mapperJson.decodeFromString<List<Recommendation>>(recommendations)
    } catch (_: Exception) {
        emptyList()
    }

    val appendixData: ReportAppendix = try {
        mapperJson.decodeFromString<ReportAppendix>(appendix)
    } catch (_: Exception) {
        ReportAppendix(
            toolsUsed = emptyList(),
            testMethodology = "",
            limitations = emptyList(),
            glossary = emptyMap(),
            references = emptyList()
        )
    }

    return SecurityReport(
        id = id,
        authId = authId,
        title = title,
        generatedAt = Instant.ofEpochMilli(generatedAt),
        testPeriod = ReportPeriod(
            start = Instant.ofEpochMilli(testPeriodStart),
            end = Instant.ofEpochMilli(testPeriodEnd)
        ),
        targetDevices = targetDevicesList,
        vulnerabilities = vulnerabilitiesList,
        fuzzingResults = fuzzingResultsList,
        keyExtractionResults = keyResultsList,
        executiveSummary = executiveSummary,
        findings = findingsList,
        recommendations = recommendationsList,
        appendix = appendixData,
        status = try { ReportStatus.valueOf(status) } catch (_: Exception) { ReportStatus.DRAFT }
    )
}

fun SecurityReport.toEntity(): SecurityReportEntity {
    return SecurityReportEntity(
        id = id,
        authId = authId,
        title = title,
        generatedAt = generatedAt.toEpochMilli(),
        testPeriodStart = testPeriod.start.toEpochMilli(),
        testPeriodEnd = testPeriod.end.toEpochMilli(),
        targetDevices = mapperJson.encodeToString(targetDevices),
        vulnerabilities = mapperJson.encodeToString(vulnerabilities),
        fuzzingResults = mapperJson.encodeToString(fuzzingResults),
        keyExtractionResults = mapperJson.encodeToString(keyExtractionResults),
        executiveSummary = executiveSummary,
        findings = mapperJson.encodeToString(findings),
        recommendations = mapperJson.encodeToString(recommendations),
        appendix = mapperJson.encodeToString(appendix),
        status = status.name
    )
}

// ---------- Collection mappers ----------

fun List<BluetoothDeviceEntity>.toDomainDevices(): List<BluetoothDevice> =
    map { it.toDomain() }

fun List<BluetoothDevice>.toEntities(): List<BluetoothDeviceEntity> =
    map { it.toEntity() }

fun List<AuthorizationEntity>.toDomainAuthorizations(): List<Authorization> =
    map { it.toDomain() }

fun List<ConsentRecordEntity>.toDomainConsentRecords(): List<ConsentRecord> =
    map { it.toDomain() }

fun List<AuditLogEntity>.toDomainAuditLogEntries(): List<AuditLogEntry> =
    map { it.toDomain() }

fun List<BtOperationEntity>.toDomainOperations(): List<BluetoothOperation> =
    map { it.toDomain() }

fun List<VulnerabilityEntity>.toDomainVulnerabilities(): List<Vulnerability> =
    map { it.toDomain() }

fun List<VulnDefinitionEntity>.toDomainDefinitions(): List<VulnerabilityDefinition> =
    map { it.toDomain() }

fun List<FuzzResultEntity>.toDomainFuzzResults(): List<FuzzResult> =
    map { it.toDomain() }

fun List<KeyExtractionResultEntity>.toDomainKeyResults(): List<KeyExtractionResult> =
    map { it.toDomain() }

fun List<SecurityReportEntity>.toDomainReports(): List<SecurityReport> =
    map { it.toDomain() }
