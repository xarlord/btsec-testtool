/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.fuzzing

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
import kotlin.test.assertTrue

/**
 * Unit tests for FuzzingRepositoryImpl.
 */
@ExtendWith(MockitoExtension::class)
@DisplayName("FuzzingRepositoryImpl Tests")
class FuzzingRepositoryImplTest {

    @Mock
    private lateinit var mockContext: Context

    private lateinit var repository: FuzzingRepositoryImpl

    @BeforeEach
    fun setUp() {
        repository = FuzzingRepositoryImpl(mockContext)
    }

    @Test
    @DisplayName("startFuzzing should emit progress updates")
    fun testStartFuzzingEmitsProgress() = runTest {
        val device = createTestDevice()
        val config = FuzzConfig(
            targetDevice = device,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 10,
            packetsPerSecond = 5,
            dataPatterns = emptyList(),
            durationSeconds = 1
        )

        val progressUpdates = mutableListOf<FuzzProgress>()

        repository.startFuzzing(config).collect { progress ->
            progressUpdates.add(progress)
        }

        assertTrue(progressUpdates.isNotEmpty())
        assertEquals(10, progressUpdates.lastOrNull()?.currentPacketNumber)
        assertEquals(FuzzStatus.COMPLETED, progressUpdates.lastOrNull()?.status)
    }

    @Test
    @DisplayName("stopFuzzing should stop active fuzzing")
    fun testStopFuzzing() = runTest {
        val device = createTestDevice()
        val config = createTestConfig(device)

        // Start fuzzing in background and then stop
        repository.startFuzzing(config)

        val result = repository.stopFuzzing()
        assertTrue(result.isSuccess)

        val status = repository.getFuzzingStatus().first()
        assertTrue(status == FuzzStatus.STOPPED || status == FuzzStatus.COMPLETED)
    }

    @Test
    @DisplayName("getFuzzingResults should return saved results")
    fun testGetFuzzingResults() = runTest {
        val device = createTestDevice()
        val config = createTestConfig(device)

        repository.startFuzzing(config).collect {} // Wait for completion

        val results = repository.getAllFuzzingResults().first()
        assertTrue(results.isNotEmpty())

        val result = results.first()
        assertEquals(device.address, result.config.targetDevice.address)
        assertTrue(result.packetsSent > 0)
    }

    @Test
    @DisplayName("getFuzzingResultsForDevice should filter by device")
    fun testGetFuzzingResultsForDevice() = runTest {
        val device1 = createTestDevice("AA:BB:CC:DD:EE:FF")
        val device2 = createTestDevice("11:22:33:44:55:66")

        val config1 = createTestConfig(device1, packetCount = 5)
        val config2 = createTestConfig(device2, packetCount = 3)

        repository.startFuzzing(config1).collect {}
        repository.startFuzzing(config2).collect {}

        val device1Results = repository.getFuzzingResultsForDevice("AA:BB:CC:DD:EE:FF").first()
        assertTrue(device1Results.all { it.config.targetDevice.address == "AA:BB:CC:DD:EE:FF" })
    }

    @Test
    @DisplayName("getAvailablePatterns should return default patterns")
    fun testGetAvailablePatterns() = runTest {
        val patterns = repository.getAvailablePatterns().first()

        assertNotNull(patterns)
        assertTrue(patterns.size >= 3)
    }

    @Test
    @DisplayName("addPattern should add custom pattern")
    fun testAddPattern() = runTest {
        val pattern = FuzzDataPattern(
            name = "Custom Pattern",
            description = "Custom fuzzing pattern",
            patternType = PatternType.CUSTOM,
            data = byteArrayOf(0xFF, 0xFE, 0xFD)
        )

        val result = repository.addPattern(pattern)
        assertTrue(result.isSuccess)

        val patterns = repository.getAvailablePatterns().first()
        assertTrue(patterns.any { it.name == "Custom Pattern" })
    }

    @Test
    @DisplayName("removePattern should remove pattern")
    fun testRemovePattern() = runTest {
        val pattern = FuzzDataPattern(
            name = "To Remove",
            description = "Pattern to remove",
            patternType = PatternType.RANDOM,
            data = byteArrayOf(0x01)
        )

        repository.addPattern(pattern)
        val result = repository.removePattern("To Remove")
        assertTrue(result.isSuccess)

        val patterns = repository.getAvailablePatterns().first()
        assertFalse(patterns.any { it.name == "To Remove" })
    }

    @Test
    @DisplayName("getKnownExploitPatterns should return CVE patterns")
    fun testGetKnownExploitPatterns() = runTest {
        val patterns = repository.getKnownExploitPatterns()

        assertTrue(patterns.isNotEmpty())
        assertTrue(patterns.any { it.name.contains("KNOB") })
        assertTrue(patterns.any { it.patternType == PatternType.KNOWN_EXPLOIT })
    }

    @Test
    @DisplayName("getBoundaryPatterns should return edge case patterns")
    fun testGetBoundaryPatterns() = runTest {
        val patterns = repository.getBoundaryPatterns()

        assertTrue(patterns.isNotEmpty())
        assertTrue(patterns.any { it.patternType == PatternType.EDGE_CASE })
    }

    @Test
    @DisplayName("getFormatStringPatterns should return format patterns")
    fun testGetFormatStringPatterns() = runTest {
        val patterns = repository.getFormatStringPatterns()

        assertTrue(patterns.isNotEmpty())
        assertTrue(patterns.any { it.patternType == PatternType.FORMAT_STRING })
    }

    @Test
    @DisplayName("getBufferOverflowPatterns should return overflow patterns")
    fun testGetBufferOverflowPatterns() = runTest {
        val patterns = repository.getBufferOverflowPatterns()

        assertTrue(patterns.isNotEmpty())
        assertTrue(patterns.any { it.patternType == PatternType.OVERLONG })
    }

    @Test
    @DisplayName("getFuzzingStatistics should calculate correctly")
    fun testGetFuzzingStatistics() = runTest {
        val device = createTestDevice()
        val config = createTestConfig(device, packetCount = 100)

        repository.startFuzzing(config).collect {}

        val stats = repository.getFuzzingStatistics().first()
        assertTrue(stats.totalTests > 0)
        assertTrue(stats.totalPacketsSent > 0)
        assertEquals(0.0, stats.averageSuccessRate) // No responses in mock
    }

    @Test
    @DisplayName("isRateAllowed should check rate limits")
    fun testIsRateAllowed() = runTest {
        assertTrue(repository.isRateAllowed(50))
        assertTrue(repository.isRateAllowed(100))
        assertFalse(repository.isRateAllowed(200))
    }

    @Test
    @DisplayName("getMaxAllowedRate should return limit")
    fun testGetMaxAllowedRate() = runTest {
        val maxRate = repository.getMaxAllowedRate()
        assertEquals(100, maxRate)
    }

    @Test
    @DisplayName("saveFuzzingResult should persist result")
    fun testSaveFuzzingResult() = runTest {
        val device = createTestDevice()
        val config = createTestConfig(device)
        val result = FuzzResult(
            id = "fuzz-1",
            config = config,
            startTime = Instant.now(),
            endTime = Instant.now().plusSeconds(60),
            status = FuzzStatus.COMPLETED,
            packetsSent = 100,
            packetsReceived = 80,
            errors = emptyList(),
            findings = emptyList(),
            captureFile = null
        )

        val saveResult = repository.saveFuzzingResult(result)
        assertTrue(saveResult.isSuccess)

        val retrieved = repository.getFuzzingResult("fuzz-1")
        assertNotNull(retrieved)
        assertEquals("fuzz-1", retrieved?.id)
    }

    @Test
    @DisplayName("deleteFuzzingResult should remove result")
    fun testDeleteFuzzingResult() = runTest {
        val device = createTestDevice()
        val config = createTestConfig(device)

        repository.startFuzzing(config).collect {}

        val results = repository.getAllFuzzingResults().first()
        val firstResult = results.first()

        val deleteResult = repository.deleteFuzzingResult(firstResult.id)
        assertTrue(deleteResult.isSuccess)

        val remaining = repository.getAllFuzzingResults().first()
        assertFalse(remaining.any { it.id == firstResult.id })
    }

    @Test
    @DisplayName("pauseFuzzing should pause active fuzzing")
    fun testPauseFuzzing() = runTest {
        val result = repository.pauseFuzzing()
        assertTrue(result.isSuccess)
    }

    @Test
    @DisplayName("resumeFuzzing should resume paused fuzzing")
    fun testResumeFuzzing() = runTest {
        val result = repository.resumeFuzzing()
        assertTrue(result.isSuccess)
    }

    @Test
    @DisplayName("logFuzzingOperation should record operation")
    fun testLogFuzzingOperation() = runTest {
        val operation = FuzzingOperation(
            id = "op-1",
            timestamp = Instant.now(),
            operationType = FuzzingOperationType.START,
            targetDevice = "AA:BB:CC:DD:EE:FF",
            resultId = "fuzz-1",
            success = true,
            errorMessage = null,
            durationMs = 1000
        )

        repository.logFuzzingOperation(operation)

        val logs = repository.getFuzzingLogs().first()
        assertTrue(logs.any { it.id == "op-1" })
    }

    @Test
    @DisplayName("getStatisticsForDevice should return device stats")
    fun testGetStatisticsForDevice() = runTest {
        val device = createTestDevice("AA:BB:CC:DD:EE:FF")
        val config = createTestConfig(device, packetCount = 50)

        repository.startFuzzing(config).collect {}

        val stats = repository.getStatisticsForDevice("AA:BB:CC:DD:EE:FF")
        assertEquals("AA:BB:CC:DD:EE:FF", stats.deviceAddress)
        assertTrue(stats.testsPerformed > 0)
    }

    // Helper functions

    private fun createTestDevice(address: String = "AA:BB:CC:DD:EE:FF"): BluetoothDevice {
        return BluetoothDevice(
            address = address,
            name = "Test Device",
            type = DeviceType.BLE,
            deviceClass = DeviceClass.UNCATEGORIZED,
            bondState = BondState.NONE,
            rssi = -60,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
            scanCount = 1
        )
    }

    private fun createTestConfig(device: BluetoothDevice, packetCount: Int = 100): FuzzConfig {
        return FuzzConfig(
            targetDevice = device,
            targetService = null,
            targetCharacteristic = null,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = packetCount,
            packetsPerSecond = 10,
            randomSeed = null,
            dataPatterns = emptyList(),
            durationSeconds = 60,
            stopOnError = true,
            stopOnDisconnect = true,
            capturePackets = true,
            captureNotifications = true
        )
    }
}
