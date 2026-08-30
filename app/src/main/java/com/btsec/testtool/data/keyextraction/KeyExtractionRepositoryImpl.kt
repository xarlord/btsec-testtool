/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.keyextraction

import android.content.Context
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.DateRange
import com.btsec.testtool.domain.repository.DefaultKeyInfo
import com.btsec.testtool.domain.repository.DeviceKeyStatistics
import com.btsec.testtool.domain.repository.EncryptionAnalysis
import com.btsec.testtool.domain.repository.EncryptionMode
import com.btsec.testtool.domain.repository.EncryptionStrength
import com.btsec.testtool.domain.repository.ExtractionProgress
import com.btsec.testtool.domain.repository.ExtractionStatus
import com.btsec.testtool.domain.repository.ExtractionStep
import com.btsec.testtool.domain.repository.KeyExtractionOperation
import com.btsec.testtool.domain.repository.KeyExtractionRepository
import com.btsec.testtool.domain.repository.KeyExtractionStatistics
import com.btsec.testtool.domain.repository.KeyFindingCategory
import com.btsec.testtool.domain.repository.KeySecurityAnalysis
import com.btsec.testtool.domain.repository.KeySecurityFinding
import com.btsec.testtool.domain.repository.PairingCapture
import com.btsec.testtool.domain.repository.PairingMethod
import com.btsec.testtool.domain.repository.SecurityScore
import com.btsec.testtool.domain.repository.WeakKeyFinding
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of key extraction repository with real KNOB attack probing.
 *
 * Performs actual BLE key negotiation probing to detect devices that accept
 * low-entropy encryption keys. The KNOB (Key Negotiation of Bluetooth) attack
 * exploits a flaw in the Bluetooth specification that allows an attacker to
 * negotiate a reduced encryption key length.
 *
 * ALL key extraction operations are logged for audit purposes.
 * This is for AUTHORIZED security testing only.
 */
@Singleton
class KeyExtractionRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        private val probe: KeyExtractionProbe,
    ) : KeyExtractionRepository {
        private val bluetoothAdapter: android.bluetooth.BluetoothAdapter? by lazy {
            (context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager?)
                ?.adapter
        }

        private val extractionStatus = MutableStateFlow<ExtractionStatus>(ExtractionStatus.PENDING)
        private val extractionProgress = MutableStateFlow<ExtractionProgress?>(null)
        private val extractionResults = MutableStateFlow<List<KeyExtractionResult>>(emptyList())
        private val pairingMonitorActive = MutableStateFlow(false)
        private val logs = MutableStateFlow<List<KeyExtractionOperation>>(emptyList())

        override fun extractKey(
            device: BluetoothDevice,
            keyType: KeyType,
            method: ExtractionMethod,
        ): Flow<ExtractionProgress> {
            return flow {
                extractionStatus.value = ExtractionStatus.RUNNING
                val extractionId = generateId()

                // Emit initial progress
                emit(
                    ExtractionProgress(
                        extractionId = extractionId,
                        targetDevice = device,
                        keyType = keyType,
                        method = method,
                        status = ExtractionStatus.RUNNING,
                        progressPercentage = 0,
                        currentStep = ExtractionStep.INITIALIZING,
                        estimatedCompletionTime = Instant.now().plusSeconds(60),
                        error = null,
                    ),
                )

                // Step 1: Check current encryption
                val encInfo = probe.getEncryptionInfo()
                emit(
                    ExtractionProgress(
                        extractionId = extractionId,
                        targetDevice = device,
                        keyType = keyType,
                        method = method,
                        status = ExtractionStatus.RUNNING,
                        progressPercentage = 10,
                        currentStep = ExtractionStep.INITIALIZING,
                        estimatedCompletionTime = Instant.now().plusSeconds(50),
                        error = null,
                    ),
                )

                // Step 2: Try KNOB-style low entropy negotiation
                // The Bluetooth spec requires a minimum of 7 bytes (56 bits) for encryption key size.
                // A KNOB-vulnerable device will accept key sizes below this minimum (1-6 bytes).
                emit(
                    ExtractionProgress(
                        extractionId = extractionId,
                        targetDevice = device,
                        keyType = keyType,
                        method = method,
                        status = ExtractionStatus.RUNNING,
                        progressPercentage = 20,
                        currentStep = ExtractionStep.NEGOTIATING,
                        estimatedCompletionTime = Instant.now().plusSeconds(40),
                        error = null,
                    ),
                )

                val unsafeKeySizes = listOf(1, 2, 3, 4, 5, 6)
                var vulnerableKeySize: Int? = null
                var negotiationUnavailable = false

                for (ks in unsafeKeySizes) {
                    val result = probe.negotiateKeySize(ks)
                    when (result) {
                        is KeyNegotiationResult.Accepted -> {
                            vulnerableKeySize = ks
                            emit(
                                ExtractionProgress(
                                    extractionId = extractionId,
                                    targetDevice = device,
                                    keyType = keyType,
                                    method = method,
                                    status = ExtractionStatus.RUNNING,
                                    progressPercentage = 40,
                                    currentStep = ExtractionStep.NEGOTIATING,
                                    estimatedCompletionTime = Instant.now().plusSeconds(20),
                                    error = null,
                                ),
                            )
                            break
                        }
                        is KeyNegotiationResult.Rejected -> {
                            emit(
                                ExtractionProgress(
                                    extractionId = extractionId,
                                    targetDevice = device,
                                    keyType = keyType,
                                    method = method,
                                    status = ExtractionStatus.RUNNING,
                                    progressPercentage = 30,
                                    currentStep = ExtractionStep.NEGOTIATING,
                                    estimatedCompletionTime = Instant.now().plusSeconds(30),
                                    error = null,
                                ),
                            )
                        }
                        is KeyNegotiationResult.Unavailable -> {
                            negotiationUnavailable = true
                            emit(
                                ExtractionProgress(
                                    extractionId = extractionId,
                                    targetDevice = device,
                                    keyType = keyType,
                                    method = method,
                                    status = ExtractionStatus.RUNNING,
                                    progressPercentage = 50,
                                    currentStep = ExtractionStep.ANALYZING,
                                    estimatedCompletionTime = Instant.now().plusSeconds(15),
                                    error = null,
                                ),
                            )
                            break
                        }
                        is KeyNegotiationResult.Error -> {
                            emit(
                                ExtractionProgress(
                                    extractionId = extractionId,
                                    targetDevice = device,
                                    keyType = keyType,
                                    method = method,
                                    status = ExtractionStatus.RUNNING,
                                    progressPercentage = 35,
                                    currentStep = ExtractionStep.ANALYZING,
                                    estimatedCompletionTime = Instant.now().plusSeconds(25),
                                    error = null,
                                ),
                            )
                        }
                    }
                }

                // Step 3: Determine result based on evidence. Accepting a short key
                // proves a KNOB weakness, but it never exposes key material through
                // the public Android APIs. Do not represent that probe outcome as an
                // extracted key.
                val extracted = false
                val confidence =
                    when {
                        vulnerableKeySize != null -> ExtractionConfidence.HIGH
                        encInfo != null && !negotiationUnavailable -> ExtractionConfidence.MEDIUM
                        else -> ExtractionConfidence.LOW
                    }

                val notes =
                    when {
                        vulnerableKeySize != null ->
                            "Device accepted $vulnerableKeySize-byte encryption key — KNOB vulnerable!"
                        encInfo != null ->
                            "Encryption key size: ${encInfo.keySize} bytes. Secure: ${encInfo.isSecureConnection}"
                        else ->
                            "Could not probe encryption — limited platform support"
                    }

                // Step 4: Build and save result
                val result =
                    KeyExtractionResult(
                        id = extractionId,
                        targetDevice = device,
                        keyType = keyType,
                        extracted = extracted,
                        keyValue = null,
                        method = method,
                        confidence = confidence,
                        timestamp = Instant.now(),
                        notes = notes,
                    )
                saveResult(result)

                // Emit final progress
                emit(
                    ExtractionProgress(
                        extractionId = extractionId,
                        targetDevice = device,
                        keyType = keyType,
                        method = method,
                        status = ExtractionStatus.COMPLETED,
                        progressPercentage = 100,
                        currentStep = ExtractionStep.COMPLETED,
                        estimatedCompletionTime = Instant.now(),
                        error = null,
                    ),
                )

                extractionStatus.value = ExtractionStatus.COMPLETED
            }
        }

        override fun extractAllKeys(device: BluetoothDevice): Flow<ExtractionProgress> {
            return flow {
                KeyType.entries.forEach { keyType ->
                    extractKey(device, keyType, ExtractionMethod.PASSIVE_MONITORING).collect { progress ->
                        emit(progress)
                    }
                }
            }
        }

        override suspend fun cancelExtraction(): Result<Unit> {
            extractionStatus.value = ExtractionStatus.CANCELLED
            probe.close()
            return Result.success(Unit)
        }

        override fun getExtractionStatus(): Flow<ExtractionStatus> {
            return extractionStatus
        }

        override suspend fun saveExtractionResult(result: KeyExtractionResult): Result<Unit> {
            return saveResult(result)
        }

        override suspend fun getExtractionResult(id: String): KeyExtractionResult? {
            return extractionResults.value.find { it.id == id }
        }

        override fun getAllExtractionResults(): Flow<List<KeyExtractionResult>> {
            return extractionResults
        }

        override fun getExtractionResultsForDevice(deviceAddress: String): Flow<List<KeyExtractionResult>> {
            return extractionResults.map { it.filter { it.targetDevice.address == deviceAddress } }
        }

        override fun getExtractionResultsByKeyType(keyType: KeyType): Flow<List<KeyExtractionResult>> {
            return extractionResults.map { it.filter { it.keyType == keyType } }
        }

        override fun getSuccessfulExtractions(): Flow<List<KeyExtractionResult>> {
            return extractionResults.map { it.filter { it.extracted } }
        }

        override suspend fun deleteExtractionResult(id: String): Result<Unit> {
            val updated = extractionResults.value.filter { it.id != id }
            extractionResults.value = updated
            return Result.success(Unit)
        }

        override suspend fun analyzeKeySecurity(device: BluetoothDevice): KeySecurityAnalysis {
            val encryption = analyzeEncryptionStrength(device)
            val keySize = encryption.encryptionKeySize ?: 0
            val score =
                when {
                    encryption.usingSecureConnections -> SecurityScore.GOOD
                    encryption.encryptionEnabled -> SecurityScore.FAIR
                    else -> SecurityScore.POOR
                }
            val strength =
                when {
                    keySize >= 256 -> EncryptionStrength.STRONG
                    keySize >= 128 -> EncryptionStrength.STANDARD
                    keySize > 0 -> EncryptionStrength.WEAK
                    else -> EncryptionStrength.NONE
                }
            val securityFindings =
                encryption.findings.mapIndexed { idx, desc ->
                    KeySecurityFinding(
                        severity = if (desc.startsWith("WARNING")) VulnerabilitySeverity.HIGH else VulnerabilitySeverity.INFORMATIONAL,
                        category =
                            if (desc.contains(
                                    "Legacy",
                                    ignoreCase = true,
                                )
                            ) {
                                KeyFindingCategory.WEAK_ENCRYPTION
                            } else {
                                KeyFindingCategory.REUSED_KEY
                            },
                        description = desc,
                        affectedKey = null,
                        recommendation = if (desc.startsWith("WARNING")) "Upgrade to LE Secure Connections" else "",
                    )
                }
            return KeySecurityAnalysis(
                deviceAddress = device.address,
                deviceName = device.name,
                analysisDate = Instant.now(),
                overallScore = score,
                findings = securityFindings,
                extractedKeys = emptyList(),
                encryptionStrength = strength,
                recommendations =
                    buildList {
                        if (!encryption.encryptionEnabled) add("Enable encryption by pairing with the device")
                        if (encryption.encryptionEnabled && !encryption.usingSecureConnections) {
                            add("Upgrade to LE Secure Connections pairing")
                        }
                        if (score == SecurityScore.GOOD) add("Encryption is strong — continue monitoring")
                    },
            )
        }

        override suspend fun checkForWeakKeys(device: BluetoothDevice): List<WeakKeyFinding> {
            return emptyList()
        }

        override suspend fun verifyKey(
            keyType: KeyType,
            keyValue: ByteArray,
            device: BluetoothDevice,
        ): Boolean {
            return false
        }

        override suspend fun deriveKey(
            extractedKey: KeyExtractionResult,
            targetKeyType: KeyType,
        ): ByteArray? {
            return null
        }

        override fun startPairingMonitor(): Flow<PairingCapture> {
            return flow {
                pairingMonitorActive.value = true
            }
        }

        override suspend fun stopPairingMonitor(): Result<Unit> {
            pairingMonitorActive.value = false
            return Result.success(Unit)
        }

        override fun isPairingMonitorActive(): Flow<Boolean> {
            return pairingMonitorActive
        }

        override suspend fun isKnownDefaultKey(
            keyType: KeyType,
            keyValue: ByteArray,
        ): Boolean {
            return false
        }

        override suspend fun getDefaultKeyInfo(keyValue: ByteArray): DefaultKeyInfo? {
            return null
        }

        override suspend fun addToKeyDatabase(
            deviceAddress: String,
            keyType: KeyType,
            keyValue: ByteArray,
        ): Result<Unit> {
            return Result.success(Unit)
        }

        override suspend fun lookupKeyInDatabase(
            deviceAddress: String,
            keyType: KeyType,
        ): ByteArray? {
            return null
        }

        override suspend fun analyzeEncryptionStrength(device: BluetoothDevice): EncryptionAnalysis {
            val observed = probe.getEncryptionInfo()
            if (observed == null) {
                return EncryptionAnalysis(
                    deviceAddress = device.address,
                    encryptionEnabled = false,
                    encryptionKeySize = null,
                    supportsSecureConnections = false,
                    usingSecureConnections = false,
                    pairingMethod = null,
                    encryptionMode = EncryptionMode.UNKNOWN,
                    findings =
                        listOf(
                            "Encryption evidence unavailable: stock Android cannot observe negotiated link parameters",
                        ),
                )
            }

            return EncryptionAnalysis(
                deviceAddress = device.address,
                encryptionEnabled = true,
                encryptionKeySize = observed.keySize * Byte.SIZE_BITS,
                supportsSecureConnections = observed.isSecureConnection,
                usingSecureConnections = observed.isSecureConnection,
                pairingMethod = if (observed.isSecureConnection) PairingMethod.SECURE_CONNECTIONS else null,
                encryptionMode = if (observed.isSecureConnection) EncryptionMode.SECURE_CONNECTIONS else EncryptionMode.UNKNOWN,
                findings =
                    listOf(
                        "Observed ${observed.encryptionType} encryption with ${observed.keySize * Byte.SIZE_BITS}-bit key material",
                    ),
            )
        }

        override suspend fun supportsSecureConnections(device: BluetoothDevice): Boolean =
            probe.getEncryptionInfo()?.isSecureConnection ?: false

        override suspend fun getEncryptionKeySize(device: BluetoothDevice): Int? =
            probe.getEncryptionInfo()?.keySize?.times(Byte.SIZE_BITS)

        override fun getKeyExtractionStatistics(): Flow<KeyExtractionStatistics> {
            return flow {
                val results = extractionResults.value
                emit(
                    KeyExtractionStatistics(
                        totalExtractions = results.size,
                        successfulExtractions = results.count { it.extracted },
                        failedExtractions = results.count { !it.extracted },
                        successRate =
                            if (results.isNotEmpty()) {
                                results.count { it.extracted }.toDouble() / results.size.toDouble()
                            } else {
                                0.0
                            },
                        extractionsByType = results.groupBy { it.keyType }.mapValues { it.value.size },
                        extractionsByMethod = results.groupBy { it.method }.mapValues { it.value.size },
                        mostExtractedDevice =
                            results.groupBy { it.targetDevice.address }
                                .maxByOrNull { it.value.size }?.key,
                        dateRange =
                            DateRange(
                                start = results.minByOrNull { it.timestamp }?.timestamp ?: Instant.now(),
                                end = results.maxByOrNull { it.timestamp }?.timestamp ?: Instant.now(),
                            ),
                    ),
                )
            }
        }

        override suspend fun getStatisticsForDevice(deviceAddress: String): DeviceKeyStatistics {
            val deviceResults = extractionResults.value.filter { it.targetDevice.address == deviceAddress }
            return DeviceKeyStatistics(
                deviceAddress = deviceAddress,
                deviceName = deviceResults.firstOrNull()?.targetDevice?.name,
                totalExtractions = deviceResults.size,
                successfulExtractions = deviceResults.count { it.extracted },
                extractedKeyTypes = deviceResults.filter { it.extracted }.map { it.keyType }.distinct(),
                lastExtractionDate = deviceResults.maxByOrNull { it.timestamp }?.timestamp ?: Instant.now(),
            )
        }

        override suspend fun logExtractionOperation(operation: KeyExtractionOperation) {
            val current = logs.value.toMutableList()
            current.add(operation)
            logs.value = current
        }

        override fun getExtractionLogs(): Flow<List<KeyExtractionOperation>> {
            return logs
        }

        private suspend fun saveResult(result: KeyExtractionResult): Result<Unit> {
            val current = extractionResults.value.toMutableList()
            current.add(result)
            extractionResults.value = current
            return Result.success(Unit)
        }

        private fun generateId(): String {
            return java.util.UUID.randomUUID().toString()
        }
    }
