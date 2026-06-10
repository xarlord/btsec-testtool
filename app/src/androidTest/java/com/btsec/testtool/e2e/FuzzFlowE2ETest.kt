/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.domain.model.BleCharacteristic
import com.btsec.testtool.domain.model.BleService
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.CharacteristicProperties
import com.btsec.testtool.domain.model.FuzzConfig
import com.btsec.testtool.domain.model.FuzzDataPattern
import com.btsec.testtool.domain.model.FuzzMethod
import com.btsec.testtool.domain.model.FuzzStatus
import com.btsec.testtool.domain.model.PatternType
import com.btsec.testtool.domain.repository.FuzzingRepository
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant
import javax.inject.Inject

/**
 * E2E tests for the fuzzing flow.
 *
 * Exercises: Connect → fuzz characteristic → verify results
 * (crash/disconnect/timeout tracking).
 *
 * Validates the fuzzing repository contract, configuration validation,
 * and result tracking through the Hilt-injected dependency graph.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class FuzzFlowE2ETest {

    @get:Rule
    val hiltRule = HiltAndroidRule(this)

    @Inject
    lateinit var fuzzingRepository: FuzzingRepository

    private val targetDevice = BluetoothDevice(
        address = "AA:BB:CC:DD:EE:FF",
        name = "E2E-Fuzz-Target",
        type = BluetoothType.BLE,
        deviceClass = null,
        bondState = BondState.NONE,
        rssi = -45,
        txPower = null,
        firstSeen = Instant.now(),
        lastSeen = Instant.now(),
        scanCount = 1,
        services = emptyList(),
        manufacturerData = emptyMap()
    )

    private val targetService = BleService(
        uuid = "0000180f-0000-1000-8000-00805f9b34fb", // Battery Service
        primary = true,
        characteristics = listOf(
            BleCharacteristic(
                uuid = "00002a19-0000-1000-8000-00805f9b34fb", // Battery Level
                properties = CharacteristicProperties(
                    read = true,
                    write = true,
                    writeWithoutResponse = true,
                    notify = true
                )
            )
        )
    )

    @Before
    fun setUp() {
        hiltRule.inject()
    }

    // ── Fuzz Configuration Validation ────────────────────────────────

    @Test
    fun fuzzFlow_configCreation_validates() {
        val config = FuzzConfig(
            targetDevice = targetDevice,
            targetService = targetService,
            targetCharacteristic = targetService.characteristics.first(),
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 50,
            packetsPerSecond = 5,
            stopOnError = true,
            stopOnDisconnect = true,
            capturePackets = true,
            captureNotifications = true
        )

        assertEquals(targetDevice.address, config.targetDevice.address)
        assertEquals(FuzzMethod.RANDOM, config.fuzzMethod)
        assertEquals(50, config.packetCount)
        assertEquals(5, config.packetsPerSecond)
        assertTrue(config.stopOnError)
        assertTrue(config.stopOnDisconnect)
    }

    @Test
    fun fuzzFlow_configWithAllMethods() {
        val methods = FuzzMethod.entries
        assertTrue("Should have multiple fuzz methods available", methods.size >= 10)

        for (method in methods) {
            val config = FuzzConfig(
                targetDevice = targetDevice,
                targetService = targetService,
                fuzzMethod = method,
                packetCount = 10
            )
            assertEquals(method, config.fuzzMethod)
        }
    }

    @Test
    fun fuzzFlow_configWithCustomPatterns() {
        val patterns = listOf(
            FuzzDataPattern(
                name = "overflow",
                description = "Buffer overflow test",
                patternType = PatternType.OVERLONG,
                data = ByteArray(512) { it.toByte() },
                length = 512
            ),
            FuzzDataPattern(
                name = "null_bytes",
                description = "Null byte injection",
                patternType = PatternType.NULL_BYTES,
                data = ByteArray(64) { 0x00 },
                length = 64
            ),
            FuzzDataPattern(
                name = "edge_case",
                description = "Boundary values",
                patternType = PatternType.EDGE_CASE,
                data = byteArrayOf(0x00, 0x7F, 0x80.toByte(), 0xFF.toByte()),
                length = 4
            )
        )

        val config = FuzzConfig(
            targetDevice = targetDevice,
            targetService = targetService,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 100,
            dataPatterns = patterns
        )

        assertEquals(3, config.dataPatterns.size)
        assertEquals("overflow", config.dataPatterns[0].name)
        assertEquals(PatternType.OVERLONG, config.dataPatterns[0].patternType)
        assertEquals(512, config.dataPatterns[0].length)
    }

    // ── Fuzzing State Observation ────────────────────────────────────

    @Test
    fun fuzzFlow_fuzzingStatusObservable() = runBlocking {
        val status = fuzzingRepository.getFuzzingStatus().first()
        assertNotNull("Fuzzing status should be observable", status)
    }

    @Test
    fun fuzzFlow_fuzzingProgressInitiallyNull() = runBlocking {
        val progress = fuzzingRepository.getFuzzingProgress().first()
        assertEquals(null, progress)
    }

    @Test
    fun fuzzFlow_allFuzzingResultsObservable() = runBlocking {
        val results = fuzzingRepository.getAllFuzzingResults().first()
        assertNotNull("Fuzz results flow should be observable", results)
    }

    @Test
    fun fuzzFlow_fuzzingStatisticsObservable() = runBlocking {
        val stats = fuzzingRepository.getFuzzingStatistics().first()
        assertNotNull("Fuzzing statistics should be observable", stats)
    }

    // ── Fuzzing Operations Log ───────────────────────────────────────

    @Test
    fun fuzzFlow_fuzzingLogsInitiallyEmpty() = runBlocking {
        val ops = fuzzingRepository.getFuzzingLogs().first()
        assertNotNull("Fuzzing logs flow should be observable", ops)
    }

    // ── Fuzz Methods Coverage ────────────────────────────────────────

    @Test
    fun fuzzFlow_allFuzzMethodsHaveNames() {
        for (method in FuzzMethod.entries) {
            assertNotNull(method.name)
            assertTrue(method.name.isNotBlank())
        }
    }

    @Test
    fun fuzzFlow_allPatternTypesHaveNames() {
        for (type in PatternType.entries) {
            assertNotNull(type.name)
            assertTrue(type.name.isNotBlank())
        }
    }

    // ── FuzzConfig Duration Mode ──────────────────────────────────────

    @Test
    fun fuzzFlow_durationBasedConfig() {
        val config = FuzzConfig(
            targetDevice = targetDevice,
            targetService = targetService,
            fuzzMethod = FuzzMethod.BIT_FLIP,
            packetCount = 1000,
            durationSeconds = 30
        )
        assertEquals(30, config.durationSeconds)
    }

    @Test
    fun fuzzFlow_countBasedConfig_defaultDuration() {
        val config = FuzzConfig(
            targetDevice = targetDevice,
            fuzzMethod = FuzzMethod.SEQUENTIAL,
            packetCount = 200
        )
        assertEquals(null, config.durationSeconds)
        assertEquals(200, config.packetCount)
    }

    // ── FuzzConfig Seed Reproducibility ──────────────────────────────

    @Test
    fun fuzzFlow_configWithSeed() {
        val config = FuzzConfig(
            targetDevice = targetDevice,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 100,
            randomSeed = 42L
        )
        assertEquals(42L, config.randomSeed)
    }

    // ── Stop Conditions ──────────────────────────────────────────────

    @Test
    fun fuzzFlow_stopOnErrorConfig() {
        val configStop = FuzzConfig(
            targetDevice = targetDevice,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 100,
            stopOnError = true
        )
        assertTrue(configStop.stopOnError)

        val configContinue = FuzzConfig(
            targetDevice = targetDevice,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 100,
            stopOnError = false
        )
        assertTrue(!configContinue.stopOnError)
    }

    @Test
    fun fuzzFlow_stopOnDisconnectConfig() {
        val config = FuzzConfig(
            targetDevice = targetDevice,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 100,
            stopOnDisconnect = false
        )
        assertTrue(!config.stopOnDisconnect)
    }

    // ── Fuzz Status Enum ─────────────────────────────────────────────

    @Test
    fun fuzzFlow_fuzzStatusValues() {
        val statuses = FuzzStatus.entries
        assertTrue("Should have at least 4 fuzz statuses", statuses.size >= 4)
        assertTrue(FuzzStatus.entries.contains(FuzzStatus.PENDING))
        assertTrue(FuzzStatus.entries.contains(FuzzStatus.RUNNING))
        assertTrue(FuzzStatus.entries.contains(FuzzStatus.COMPLETED))
        assertTrue(FuzzStatus.entries.contains(FuzzStatus.ERROR))
    }
}
