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
import com.btsec.testtool.domain.repository.*
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for FuzzingRepositoryImpl — verifies CRUD operations on results,
 * pattern management, rate limiting, statistics, logging, and fuzzing lifecycle.
 *
 * Android Context and BleFuzzEngine are mocked via MockK since the tests run
 * outside of an Android device/emulator.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("FuzzingRepositoryImpl")
class FuzzingRepositoryImplTest {
    private lateinit var context: Context
    private lateinit var bleFuzzEngine: BleFuzzEngine
    private lateinit var payloadGenerator: FuzzPayloadGenerator
    private lateinit var repository: FuzzingRepositoryImpl

    private val testDevice =
        BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF",
            name = "Test Device",
            type = BluetoothType.BLE,
            deviceClass = DeviceClass.PHONE,
            bondState = BondState.BONDED,
            rssi = -50,
            txPower = 4,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
        )

    private val testDevice2 =
        BluetoothDevice(
            address = "11:22:33:44:55:66",
            name = "Device 2",
            type = BluetoothType.CLASSIC,
            deviceClass = DeviceClass.COMPUTER,
            bondState = BondState.NONE,
            rssi = -70,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
        )

    private fun createConfig(
        device: BluetoothDevice = testDevice,
        packetCount: Int = 10,
        durationSeconds: Int? = 300,
    ) = FuzzConfig(
        targetDevice = device,
        targetService = null,
        targetCharacteristic = null,
        fuzzMethod = FuzzMethod.RANDOM,
        packetCount = packetCount,
        packetsPerSecond = 10,
        randomSeed = 42L,
        dataPatterns = emptyList(),
        durationSeconds = durationSeconds,
    )

    private fun createResult(
        id: String = "result-${System.nanoTime()}",
        device: BluetoothDevice = testDevice,
        status: FuzzStatus = FuzzStatus.COMPLETED,
        packetsSent: Int = 100,
        packetsReceived: Int = 95,
        findings: List<FuzzFinding> = emptyList(),
        errors: List<FuzzError> = emptyList(),
        startTime: Instant = Instant.now().minusSeconds(60),
    ) = FuzzResult(
        id = id,
        config = createConfig(device),
        startTime = startTime,
        endTime = Instant.now(),
        status = status,
        packetsSent = packetsSent,
        packetsReceived = packetsReceived,
        errors = errors,
        findings = findings,
        captureFile = null,
        reportGenerated = false,
    )

    private fun createEngineResult(
        packetsSent: Int = 100,
        packetsReceived: Int = 95,
        findings: List<FuzzFinding> = emptyList(),
        errors: List<FuzzError> = emptyList(),
    ) = FuzzResult(
        id = "engine-result",
        config = createConfig(),
        startTime = Instant.now(),
        endTime = Instant.now(),
        status = FuzzStatus.COMPLETED,
        packetsSent = packetsSent,
        packetsReceived = packetsReceived,
        errors = errors,
        findings = findings,
        captureFile = null,
        reportGenerated = false,
    )

    @BeforeEach
    fun setUp() {
        context = mockk(relaxed = true)
        bleFuzzEngine = mockk(relaxed = true)
        payloadGenerator = mockk(relaxed = true)
        repository = FuzzingRepositoryImpl(context, bleFuzzEngine, payloadGenerator)
    }

    // ========== Save, Get, Delete Results ==========

    @Nested
    @DisplayName("Result CRUD operations")
    inner class ResultCrudTests {
        @Test
        @DisplayName("saveFuzzingResult should store result and getAllFuzzingResults should return it")
        fun saveAndGetResult() =
            runTest {
                val result = createResult(id = "r1")

                val saveOutcome = repository.saveFuzzingResult(result)
                assertTrue(saveOutcome.isSuccess)

                val all = repository.getAllFuzzingResults().first()
                assertEquals(1, all.size)
                assertEquals("r1", all[0].id)
            }

        @Test
        @DisplayName("getFuzzingResult should return the result by ID")
        fun getResultById() =
            runTest {
                val r1 = createResult(id = "r1")
                val r2 = createResult(id = "r2")
                repository.saveFuzzingResult(r1)
                repository.saveFuzzingResult(r2)

                val found = repository.getFuzzingResult("r1")
                assertNotNull(found)
                assertEquals("r1", found.id)

                val notFound = repository.getFuzzingResult("nonexistent")
                assertNull(notFound)
            }

        @Test
        @DisplayName("deleteFuzzingResult should remove result by ID")
        fun deleteResult() =
            runTest {
                val r1 = createResult(id = "r1")
                val r2 = createResult(id = "r2")
                repository.saveFuzzingResult(r1)
                repository.saveFuzzingResult(r2)

                val deleteOutcome = repository.deleteFuzzingResult("r1")
                assertTrue(deleteOutcome.isSuccess)

                val remaining = repository.getAllFuzzingResults().first()
                assertEquals(1, remaining.size)
                assertEquals("r2", remaining[0].id)
            }

        @Test
        @DisplayName("getFuzzingResultsForDevice should filter by device address")
        fun getResultsForDevice() =
            runTest {
                val r1 = createResult(id = "r1", device = testDevice)
                val r2 = createResult(id = "r2", device = testDevice2)
                repository.saveFuzzingResult(r1)
                repository.saveFuzzingResult(r2)

                val deviceResults = repository.getFuzzingResultsForDevice("AA:BB:CC:DD:EE:FF").first()
                assertEquals(1, deviceResults.size)
                assertEquals("r1", deviceResults[0].id)
            }

        @Test
        @DisplayName("getFuzzingResultsInRange should filter by start/end time")
        fun getResultsInRange() =
            runTest {
                val now = Instant.now()
                val oldTime = now.minusSeconds(7200) // 2 hours ago
                val recentTime = now.minusSeconds(1800) // 30 min ago

                val oldResult = createResult(id = "old", startTime = oldTime)
                val recentResult = createResult(id = "recent", startTime = recentTime)
                repository.saveFuzzingResult(oldResult)
                repository.saveFuzzingResult(recentResult)

                // Query range: last hour only
                val rangeStart = now.minusSeconds(3600)
                val rangeEnd = now.plusSeconds(60)
                val inRange = repository.getFuzzingResultsInRange(rangeStart, rangeEnd).first()
                assertEquals(1, inRange.size)
                assertEquals("recent", inRange[0].id)
            }
    }

    // ========== Fuzzing Lifecycle ==========

    @Nested
    @DisplayName("Fuzzing lifecycle controls")
    inner class LifecycleTests {
        @Test
        @DisplayName("stopFuzzing should update status to STOPPED")
        fun stopFuzzing() =
            runTest {
                val outcome = repository.stopFuzzing()
                assertTrue(outcome.isSuccess)
                assertEquals(FuzzStatus.STOPPED, repository.getFuzzingStatus().first())
            }

        @Test
        @DisplayName("pauseFuzzing and resumeFuzzing should return success")
        fun pauseAndResume() =
            runTest {
                val pauseResult = repository.pauseFuzzing()
                assertTrue(pauseResult.isSuccess)

                val resumeResult = repository.resumeFuzzing()
                assertTrue(resumeResult.isSuccess)
            }

        @Test
        @DisplayName("startFuzzing should emit progress and save result via BleFuzzEngine")
        fun startFuzzingEmitsProgress() =
            runTest {
                val engineResult =
                    createEngineResult(
                        packetsSent = 50,
                        packetsReceived = 48,
                        findings =
                            listOf(
                                FuzzFinding(
                                    timestamp = Instant.now(),
                                    packetNumber = 10,
                                    description = "Crash on packet 10",
                                    severity = VulnerabilitySeverity.HIGH,
                                    packetData = null,
                                    response = null,
                                    category = FindingCategory.CRASH,
                                ),
                            ),
                        errors =
                            listOf(
                                FuzzError(
                                    timestamp = Instant.now(),
                                    packetNumber = 5,
                                    errorCode = 1,
                                    errorMessage = "Write failed",
                                    severity = ErrorSeverity.MEDIUM,
                                ),
                            ),
                    )
                coEvery {
                    bleFuzzEngine.executeFuzzing(any(), any(), any())
                } returns engineResult

                val config = createConfig(packetCount = 50)
                val progressList = mutableListOf<FuzzProgress>()

                // Collect flow
                repository.startFuzzing(config).collect { progress ->
                    progressList.add(progress)
                }

                // Should emit initial + final progress
                assertTrue(progressList.size >= 2)
                assertEquals(FuzzStatus.RUNNING, progressList.first().status)
                assertEquals(FuzzStatus.COMPLETED, progressList.last().status)

                // Engine result should be saved
                val saved = repository.getAllFuzzingResults().first()
                assertEquals(1, saved.size)

                coVerify { bleFuzzEngine.executeFuzzing(any(), any(), any()) }
            }
    }

    // ========== Pattern Management ==========

    @Nested
    @DisplayName("Pattern management")
    inner class PatternTests {
        @Test
        @DisplayName("addPattern and getAvailablePatterns should store and retrieve patterns")
        fun addAndGetPatterns() =
            runTest {
                val pattern =
                    FuzzDataPattern(
                        name = "Custom Pattern",
                        description = "A custom test pattern",
                        patternType = PatternType.RANDOM,
                        data = byteArrayOf(0xDE.toByte(), 0xAD.toByte()),
                    )

                val outcome = repository.addPattern(pattern)
                assertTrue(outcome.isSuccess)

                val patterns = repository.getAvailablePatterns().first()
                assertEquals(1, patterns.size)
                assertEquals("Custom Pattern", patterns[0].name)
            }

        @Test
        @DisplayName("removePattern should remove pattern by name")
        fun removePattern() =
            runTest {
                val p1 = FuzzDataPattern("p1", "desc1", PatternType.RANDOM, byteArrayOf(0x01))
                val p2 = FuzzDataPattern("p2", "desc2", PatternType.EDGE_CASE, byteArrayOf(0x02))
                repository.addPattern(p1)
                repository.addPattern(p2)

                val outcome = repository.removePattern("p1")
                assertTrue(outcome.isSuccess)

                val remaining = repository.getAvailablePatterns().first()
                assertEquals(1, remaining.size)
                assertEquals("p2", remaining[0].name)
            }

        @Test
        @DisplayName("getPatternsForType should filter by pattern type")
        fun getPatternsForType() =
            runTest {
                val random = FuzzDataPattern("r1", "random", PatternType.RANDOM, byteArrayOf(0x01))
                val edge = FuzzDataPattern("e1", "edge", PatternType.EDGE_CASE, byteArrayOf(0xFF.toByte()))
                repository.addPattern(random)
                repository.addPattern(edge)

                val randomPatterns = repository.getPatternsForType(PatternType.RANDOM)
                assertEquals(1, randomPatterns.size)
                assertEquals("r1", randomPatterns[0].name)
            }

        @Test
        @DisplayName("Predefined pattern methods should return non-empty lists")
        fun predefinedPatterns() =
            runTest {
                val exploits = repository.getKnownExploitPatterns()
                assertTrue(exploits.isNotEmpty())
                assertEquals(PatternType.KNOWN_EXPLOIT, exploits[0].patternType)

                val boundaries = repository.getBoundaryPatterns()
                assertTrue(boundaries.isNotEmpty())

                val formatStrings = repository.getFormatStringPatterns()
                assertTrue(formatStrings.isNotEmpty())

                val overflow = repository.getBufferOverflowPatterns()
                assertTrue(overflow.isNotEmpty())
            }
    }

    // ========== Statistics ==========

    @Nested
    @DisplayName("Fuzzing statistics")
    inner class StatisticsTests {
        @Test
        @DisplayName("getFuzzingStatistics should aggregate stored results")
        fun fuzzingStatistics() =
            runTest {
                val r1 =
                    createResult(
                        id = "r1",
                        packetsSent = 100,
                        packetsReceived = 90,
                        findings =
                            listOf(
                                FuzzFinding(
                                    timestamp = Instant.now(),
                                    packetNumber = 1,
                                    description = "crash",
                                    severity = VulnerabilitySeverity.HIGH,
                                    packetData = null,
                                    response = null,
                                    category = FindingCategory.CRASH,
                                ),
                            ),
                    )
                val r2 =
                    createResult(
                        id = "r2",
                        packetsSent = 200,
                        packetsReceived = 180,
                        errors =
                            listOf(
                                FuzzError(
                                    timestamp = Instant.now(),
                                    packetNumber = 2,
                                    errorCode = null,
                                    errorMessage = "err",
                                    severity = ErrorSeverity.LOW,
                                ),
                            ),
                    )
                repository.saveFuzzingResult(r1)
                repository.saveFuzzingResult(r2)

                val stats = repository.getFuzzingStatistics().first()
                assertEquals(2, stats.totalTests)
                assertEquals(300L, stats.totalPacketsSent)
                assertEquals(270L, stats.totalPacketsReceived)
                assertEquals(1L, stats.totalFindings)
                assertEquals(1L, stats.totalErrors)
            }

        @Test
        @DisplayName("getStatisticsForDevice should return per-device stats")
        fun deviceStatistics() =
            runTest {
                val r1 = createResult(id = "r1", device = testDevice, packetsSent = 100, packetsReceived = 90)
                val r2 = createResult(id = "r2", device = testDevice2, packetsSent = 50, packetsReceived = 40)
                repository.saveFuzzingResult(r1)
                repository.saveFuzzingResult(r2)

                val stats = repository.getStatisticsForDevice("AA:BB:CC:DD:EE:FF")
                assertEquals("AA:BB:CC:DD:EE:FF", stats.deviceAddress)
                assertEquals(1, stats.testsPerformed)
                assertEquals(100L, stats.packetsSent)
                assertEquals(90L, stats.packetsReceived)
            }
    }

    // ========== Rate Limiting ==========

    @Nested
    @DisplayName("Rate limiting")
    inner class RateLimitingTests {
        @Test
        @DisplayName("isRateAllowed should return true for rate <= 100, false otherwise")
        fun rateAllowed() =
            runTest {
                assertTrue(repository.isRateAllowed(100))
                assertTrue(repository.isRateAllowed(50))
                assertTrue(repository.isRateAllowed(1))
                assertTrue(!repository.isRateAllowed(101))
                assertTrue(!repository.isRateAllowed(500))
            }

        @Test
        @DisplayName("getMaxAllowedRate should return 100")
        fun maxAllowedRate() =
            runTest {
                assertEquals(100, repository.getMaxAllowedRate())
            }
    }

    // ========== Logging ==========

    @Nested
    @DisplayName("Fuzzing operation logging")
    inner class LoggingTests {
        @Test
        @DisplayName("logFuzzingOperation should store operation and getFuzzingLogs should retrieve it")
        fun logAndRetrieve() =
            runTest {
                val operation =
                    FuzzingOperation(
                        id = "op-1",
                        timestamp = Instant.now(),
                        operationType = FuzzingOperationType.START,
                        targetDevice = "AA:BB:CC:DD:EE:FF",
                        resultId = null,
                        success = true,
                        errorMessage = null,
                        durationMs = null,
                    )

                repository.logFuzzingOperation(operation)

                val logs = repository.getFuzzingLogs().first()
                assertEquals(1, logs.size)
                assertEquals("op-1", logs[0].id)
                assertEquals(FuzzingOperationType.START, logs[0].operationType)
                assertTrue(logs[0].success)
            }

        @Test
        @DisplayName("Multiple log entries should be retained in order")
        fun multipleLogs() =
            runTest {
                val op1 = FuzzingOperation("op-1", Instant.now(), FuzzingOperationType.START, "dev1", null, true, null, null)
                val op2 = FuzzingOperation("op-2", Instant.now(), FuzzingOperationType.COMPLETE, "dev1", "r1", true, null, 5000L)

                repository.logFuzzingOperation(op1)
                repository.logFuzzingOperation(op2)

                val logs = repository.getFuzzingLogs().first()
                assertEquals(2, logs.size)
                assertEquals("op-1", logs[0].id)
                assertEquals("op-2", logs[1].id)
            }
    }

    // ========== Findings Queries ==========

    @Nested
    @DisplayName("Findings queries")
    inner class FindingsTests {
        @Test
        @DisplayName("getFindingsForResult, getFindingsBySeverity, getFindingsByCategory should return empty lists")
        fun findingsReturnEmpty() =
            runTest {
                val byResult = repository.getFindingsForResult("any-id").first()
                assertTrue(byResult.isEmpty())

                val bySeverity = repository.getFindingsBySeverity(VulnerabilitySeverity.HIGH).first()
                assertTrue(bySeverity.isEmpty())

                val byCategory = repository.getFindingsByCategory(FindingCategory.CRASH).first()
                assertTrue(byCategory.isEmpty())
            }
    }
}
