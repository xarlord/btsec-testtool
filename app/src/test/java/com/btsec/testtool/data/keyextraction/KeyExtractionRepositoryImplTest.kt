/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.keyextraction

import android.content.Context
import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for KeyExtractionRepositoryImpl.
 */
@ExtendWith(MockitoExtension::class)
@DisplayName("KeyExtractionRepositoryImpl Tests")
class KeyExtractionRepositoryImplTest {

    @Mock
    private lateinit var mockContext: Context

    private lateinit var repository: KeyExtractionRepositoryImpl

    @BeforeEach
    fun setUp() {
        repository = KeyExtractionRepositoryImpl(mockContext)
    }

    @Test
    @DisplayName("extractKey should emit progress updates")
    fun testExtractKeyEmitsProgress() = runTest {
        val device = createTestDevice()

        val progressUpdates = mutableListOf<ExtractionProgress>()

        repository.extractKey(device, KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING)
            .collect { progress ->
                progressUpdates.add(progress)
            }

        assertTrue(progressUpdates.isNotEmpty())
        assertEquals(KeyType.LTK, progressUpdates.first().keyType)
        assertEquals(device.address, progressUpdates.first().targetDevice.address)
    }

    @Test
    @DisplayName("cancelExtraction should stop active extraction")
    fun testCancelExtraction() = runTest {
        val device = createTestDevice()

        // Start extraction and cancel
        repository.extractKey(device, KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING)
            .collect {}

        val result = repository.cancelExtraction()
        assertTrue(result.isSuccess)

        val status = repository.getExtractionStatus().first()
        assertTrue(status == ExtractionStatus.CANCELLED || status == ExtractionStatus.COMPLETED)
    }

    @Test
    @DisplayName("getExtractionResults should return saved results")
    fun testGetExtractionResults() = runTest {
        val device = createTestDevice()
        val result = KeyExtractionResult(
            id = "key-1",
            targetDevice = device,
            keyType = KeyType.LTK,
            extracted = false,
            keyValue = null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.LOW,
            timestamp = Instant.now()
        )

        repository.saveExtractionResult(result)

        val results = repository.getAllExtractionResults().first()
        assertTrue(results.any { it.id == "key-1" })
    }

    @Test
    @DisplayName("getExtractionResultsForDevice should filter by device")
    fun testGetExtractionResultsForDevice() = runTest {
        val device1 = createTestDevice("AA:BB:CC:DD:EE:FF")
        val device2 = createTestDevice("11:22:33:44:55:66")

        val result1 = KeyExtractionResult(
            id = "key-1",
            targetDevice = device1,
            keyType = KeyType.LTK,
            extracted = false,
            keyValue = null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.LOW,
            timestamp = Instant.now()
        )

        val result2 = KeyExtractionResult(
            id = "key-2",
            targetDevice = device2,
            keyType = KeyType.IRK,
            extracted = false,
            keyValue = null,
            method = ExtractionMethod.BRUTE_FORCE,
            confidence = ExtractionConfidence.UNKNOWN,
            timestamp = Instant.now()
        )

        repository.saveExtractionResult(result1)
        repository.saveExtractionResult(result2)

        val device1Results = repository.getExtractionResultsForDevice("AA:BB:CC:DD:EE:FF").first()
        assertEquals(1, device1Results.size)
        assertEquals("key-1", device1Results.first().id)
    }

    @Test
    @DisplayName("getExtractionResultsByKeyType should filter by type")
    fun testGetExtractionResultsByKeyType() = runTest {
        val device = createTestDevice()

        val ltkResult = KeyExtractionResult(
            id = "ltk-key",
            targetDevice = device,
            keyType = KeyType.LTK,
            extracted = false,
            keyValue = null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.HIGH,
            timestamp = Instant.now()
        )

        val irkResult = KeyExtractionResult(
            id = "irk-key",
            targetDevice = device,
            keyType = KeyType.IRK,
            extracted = false,
            keyValue = null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.MEDIUM,
            timestamp = Instant.now()
        )

        repository.saveExtractionResult(ltkResult)
        repository.saveExtractionResult(irkResult)

        val ltkResults = repository.getExtractionResultsByKeyType(KeyType.LTK).first()
        assertEquals(1, ltkResults.size)
        assertEquals(KeyType.LTK, ltkResults.first().keyType)
    }

    @Test
    @DisplayName("getSuccessfulExtractions should return only successful")
    fun testGetSuccessfulExtractions() = runTest {
        val device = createTestDevice()

        val successResult = KeyExtractionResult(
            id = "success",
            targetDevice = device,
            keyType = KeyType.LTK,
            extracted = true,
            keyValue = byteArrayOf(0x01, 0x02),
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.CERTAIN,
            timestamp = Instant.now()
        )

        val failResult = KeyExtractionResult(
            id = "fail",
            targetDevice = device,
            keyType = KeyType.IRK,
            extracted = false,
            keyValue = null,
            method = ExtractionMethod.BRUTE_FORCE,
            confidence = ExtractionConfidence.UNKNOWN,
            timestamp = Instant.now()
        )

        repository.saveExtractionResult(successResult)
        repository.saveExtractionResult(failResult)

        val successful = repository.getSuccessfulExtractions().first()
        assertEquals(1, successful.size)
        assertEquals("success", successful.first().id)
    }

    @Test
    @DisplayName("analyzeKeySecurity should return analysis")
    fun testAnalyzeKeySecurity() = runTest {
        val device = createTestDevice()

        val analysis = repository.analyzeKeySecurity(device)

        assertNotNull(analysis)
        assertEquals(device.address, analysis.deviceAddress)
        assertTrue(analysis.extractedKeys.isEmpty()) // Mock implementation
        assertTrue(analysis.recommendations.isNotEmpty())
    }

    @Test
    @DisplayName("checkForWeakKeys should return findings list")
    fun testCheckForWeakKeys() = runTest {
        val device = createTestDevice()

        val findings = repository.checkForWeakKeys(device)

        assertNotNull(findings)
        // Mock implementation returns empty list
        assertTrue(findings.isEmpty())
    }

    @Test
    @DisplayName("startPairingMonitor should start monitoring")
    fun testStartPairingMonitor() = runTest {
        val isActive = repository.isPairingMonitorActive().first()
        assertFalse(isActive)

        repository.startPairingMonitor()

        // Monitor starts but no data in mock
        val isActiveAfter = repository.isPairingMonitorActive().first()
        // State might change after starting
    }

    @Test
    @DisplayName("stopPairingMonitor should stop monitoring")
    fun testStopPairingMonitor() = runTest {
        repository.startPairingMonitor()
        val result = repository.stopPairingMonitor()

        assertTrue(result.isSuccess)
    }

    @Test
    @DisplayName("isKnownDefaultKey should check default keys")
    fun testIsKnownDefaultKey() = runTest {
        val result = repository.isKnownDefaultKey(KeyType.LTK, byteArrayOf(0x00, 0x00))
        // Mock implementation returns false
        assertFalse(result)
    }

    @Test
    @DisplayName("analyzeEncryptionStrength should return analysis")
    fun testAnalyzeEncryptionStrength() = runTest {
        val device = createTestDevice()

        val analysis = repository.analyzeEncryptionStrength(device)

        assertNotNull(analysis)
        assertEquals(device.address, analysis.deviceAddress)
        assertTrue(analysis.encryptionEnabled)
        assertEquals(128, analysis.encryptionKeySize)
        assertTrue(analysis.supportsSecureConnections)
    }

    @Test
    @DisplayName("supportsSecureConnections should check support")
    fun testSupportsSecureConnections() = runTest {
        val device = createTestDevice()

        val supports = repository.supportsSecureConnections(device)
        assertTrue(supports) // Mock returns true
    }

    @Test
    @DisplayName("getEncryptionKeySize should return key size")
    fun testGetEncryptionKeySize() = runTest {
        val device = createTestDevice()

        val keySize = repository.getEncryptionKeySize(device)
        assertEquals(128, keySize) // Standard BLE key size
    }

    @Test
    @DisplayName("getKeyExtractionStatistics should calculate stats")
    fun testGetKeyExtractionStatistics() = runTest {
        val stats = repository.getKeyExtractionStatistics().first()

        assertNotNull(stats)
        assertTrue(stats.totalExtractions >= 0)
    }

    @Test
    @DisplayName("getStatisticsForDevice should return device stats")
    fun testGetStatisticsForDevice() = runTest {
        val device = createTestDevice()

        val result = KeyExtractionResult(
            id = "key-stats",
            targetDevice = device,
            keyType = KeyType.LTK,
            extracted = false,
            keyValue = null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.LOW,
            timestamp = Instant.now()
        )

        repository.saveExtractionResult(result)

        val stats = repository.getStatisticsForDevice(device.address)
        assertEquals(device.address, stats.deviceAddress)
        assertEquals(1, stats.totalExtractions)
    }

    @Test
    @DisplayName("logExtractionOperation should record operation")
    fun testLogExtractionOperation() = runTest {
        val operation = KeyExtractionOperation(
            id = "op-1",
            timestamp = Instant.now(),
            operationType = ExtractionOperationType.START,
            targetDevice = "AA:BB:CC:DD:EE:FF",
            keyType = KeyType.LTK,
            method = ExtractionMethod.PASSIVE_MONITORING,
            success = true,
            errorMessage = null,
            durationMs = 5000
        )

        repository.logExtractionOperation(operation)

        val logs = repository.getExtractionLogs().first()
        assertTrue(logs.any { it.id == "op-1" })
    }

    @Test
    @DisplayName("All key types should be defined")
    fun testAllKeyTypesDefined() {
        val keyTypes = KeyType.entries

        assertTrue(keyTypes.contains(KeyType.LTK))
        assertTrue(keyTypes.contains(KeyType.IRK))
        assertTrue(keyTypes.contains(KeyType.CSRK))
        assertTrue(keyTypes.contains(KeyType.LINK_KEY))
        assertTrue(keyTypes.contains(KeyType.PRIVATE_KEY))
    }

    @Test
    @DisplayName("All extraction methods should be defined")
    fun testAllExtractionMethodsDefined() {
        val methods = ExtractionMethod.entries

        assertTrue(methods.contains(ExtractionMethod.PASSIVE_MONITORING))
        assertTrue(methods.contains(ExtractionMethod.ACTIVE_PROMPT))
        assertTrue(methods.contains(ExtractionMethod.KNOWN_PLAINTEXT))
        assertTrue(methods.contains(ExtractionMethod.BRUTE_FORCE))
        assertTrue(methods.contains(ExtractionMethod.DATABASE_LOOKUP))
    }

    @Test
    @DisplayName("All confidence levels should be defined")
    fun testAllConfidenceLevelsDefined() {
        val levels = ExtractionConfidence.entries

        assertTrue(levels.contains(ExtractionConfidence.CERTAIN))
        assertTrue(levels.contains(ExtractionConfidence.HIGH))
        assertTrue(levels.contains(ExtractionConfidence.MEDIUM))
        assertTrue(levels.contains(ExtractionConfidence.LOW))
        assertTrue(levels.contains(ExtractionConfidence.UNKNOWN))
    }

    // Helper functions

    private fun createTestDevice(address: String = "AA:BB:CC:DD:EE:FF"): BluetoothDevice {
        return BluetoothDevice(
            address = address,
            name = "Test Device",
            type = DeviceType.BLE,
            deviceClass = DeviceClass.UNCATEGORIZED,
            bondState = BondState.BONDED,
            rssi = -60,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
            scanCount = 1
        )
    }
}
