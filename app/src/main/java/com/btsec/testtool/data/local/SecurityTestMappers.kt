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
import com.btsec.testtool.data.local.entity.FuzzResultEntity
import com.btsec.testtool.data.local.entity.KeyExtractionResultEntity
import com.btsec.testtool.data.local.entity.SecurityReportEntity
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.Vulnerability
import com.btsec.testtool.domain.model.FuzzConfig
import com.btsec.testtool.domain.model.FuzzResult
import com.btsec.testtool.domain.model.FuzzStatus
import com.btsec.testtool.domain.model.FuzzError
import com.btsec.testtool.domain.model.FuzzFinding
import com.btsec.testtool.domain.model.KeyExtractionResult
import com.btsec.testtool.domain.model.KeyType
import com.btsec.testtool.domain.model.ExtractionMethod
import com.btsec.testtool.domain.model.ExtractionConfidence
import com.btsec.testtool.domain.model.SecurityReport
import com.btsec.testtool.domain.model.ReportStatus
import com.btsec.testtool.domain.model.ReportPeriod
import com.btsec.testtool.domain.model.ReportFinding
import com.btsec.testtool.domain.model.Recommendation
import com.btsec.testtool.domain.model.ReportAppendix
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import timber.log.Timber
import java.time.Instant

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
        ReportAppendix()
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

fun List<FuzzResultEntity>.toDomainFuzzResults(): List<FuzzResult> =
    map { it.toDomain() }

fun List<KeyExtractionResultEntity>.toDomainKeyResults(): List<KeyExtractionResult> =
    map { it.toDomain() }

fun List<SecurityReportEntity>.toDomainReports(): List<SecurityReport> =
    map { it.toDomain() }
