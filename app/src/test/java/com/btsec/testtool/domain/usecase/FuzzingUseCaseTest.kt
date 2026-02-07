/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.*
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for FuzzingUseCase.
 */
@ExtendWith(MockitoExtension::class)
@DisplayName("FuzzingUseCase Tests")
class FuzzingUseCaseTest {

    @Mock
    private lateinit var fuzzingRepository: FuzzingRepository

    @Mock
    private lateinit var bluetoothRepository: BluetoothRepository

    @Mock
    private lateinit var authorizationUseCase: AuthorizationUseCase

    @Mock
    private lateinit var consentRepository: ConsentRepository

    private lateinit var useCase: FuzzingUseCase

    private lateinit var testDevice: BluetoothDevice

    private lateinit var testConfig: FuzzConfig

    @BeforeEach
    fun setUp() {
        useCase = FuzzingUseCase(
            fuzzingRepository,
            bluetoothRepository,
            authorizationUseCase,
            consentRepository
        )

        testDevice = BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF",
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

        testConfig = FuzzConfig(
            targetDevice = testDevice,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 100,
            packetsPerSecond = 10,
            dataPatterns = emptyList(),
            durationSeconds = 60
        )
    }

    @Test
    @DisplayName("startFuzzing should succeed when authorized")
    fun testStartFuzzingAuthorized() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = listOf(TargetDevice("AA:BB:CC:DD:EE:FF", "Test Device")),
            allowedActions = setOf(TestAction.START_FUZZING),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.getCurrentScope()).thenReturn(flowOf(scope))
        whenever(authorizationUseCase.isTargetInScope(any())).thenReturn(true)
        whenever(fuzzingRepository.startFuzzing(any())).thenReturn(Result.success(Unit))

        val result = useCase.startFuzzing(testConfig)

        assertTrue(result is FuzzingStartResult.Started)
        verify(fuzzingRepository).startFuzzing(testConfig)
    }

    @Test
    @DisplayName("startFuzzing should fail when not authorized")
    fun testStartFuzzingNotAuthorized() = runTest {
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.NotAuthorized("Not authorized"))

        val result = useCase.startFuzzing(testConfig)

        assertTrue(result is FuzzingStartResult.NotAuthorized)
        verify(fuzzingRepository, never()).startFuzzing(any())
    }

    @Test
    @DisplayName("startFuzzing should require consent when denied")
    fun testStartFuzzingConsentDenied() = runTest {
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.ConsentDenied(mock()))

        val result = useCase.startFuzzing(testConfig)

        assertTrue(result is FuzzingStartResult.ConsentRequired)
    }

    @Test
    @DisplayName("startFuzzing should enforce rate limit")
    fun testStartFuzzingRateLimit() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = emptyList(),
            allowedActions = emptySet(),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 10
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.getCurrentScope()).thenReturn(flowOf(scope))

        val highRateConfig = testConfig.copy(packetsPerSecond = 100)
        val result = useCase.startFuzzing(highRateConfig)

        assertTrue(result is FuzzingStartResult.RateLimitExceeded)
        assertEquals(10, (result as FuzzingStartResult.RateLimitExceeded).maxRate)
    }

    @Test
    @DisplayName("startFuzzing should check device scope")
    fun testStartFuzzingDeviceNotInScope() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = emptyList(),
            allowedActions = setOf(TestAction.START_FUZZING),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.getCurrentScope()).thenReturn(flowOf(scope))
        whenever(authorizationUseCase.isTargetInScope(any())).thenReturn(false)

        val result = useCase.startFuzzing(testConfig)

        assertTrue(result is FuzzingStartResult.DeviceNotInScope)
    }

    @Test
    @DisplayName("stopFuzzing should stop active fuzzing")
    fun testStopFuzzing() = runTest {
        whenever(fuzzingRepository.stopFuzzing()).thenReturn(Result.success(Unit))

        val result = useCase.stopFuzzing()

        assertTrue(result.isSuccess)
        verify(fuzzingRepository).stopFuzzing()
    }

    @Test
    @DisplayName("pauseFuzzing should pause active fuzzing")
    fun testPauseFuzzing() = runTest {
        whenever(fuzzingRepository.pauseFuzzing()).thenReturn(Result.success(Unit))

        val result = useCase.pauseFuzzing()

        assertTrue(result.isSuccess)
        verify(fuzzingRepository).pauseFuzzing()
    }

    @Test
    @DisplayName("resumeFuzzing should resume paused fuzzing")
    fun testResumeFuzzing() = runTest {
        whenever(fuzzingRepository.resumeFuzzing()).thenReturn(Result.success(Unit))

        val result = useCase.resumeFuzzing()

        assertTrue(result.isSuccess)
        verify(fuzzingRepository).resumeFuzzing()
    }

    @Test
    @DisplayName("getFuzzingStatus should return current status")
    fun testGetFuzzingStatus() = runTest {
        whenever(fuzzingRepository.getFuzzingStatus())
            .thenReturn(flowOf(FuzzStatus.Idle))

        val status = useCase.getFuzzingStatus().first()

        assertEquals(FuzzStatus.Idle, status)
    }

    @Test
    @DisplayName("getFuzzingProgress should return progress")
    fun testGetFuzzingProgress() = runTest {
        val progress = FuzzProgress(
            packetsSent = 50,
            packetsReceived = 45,
            totalPackets = 100,
            percentage = 0.5f,
            currentPacket = null,
            errors = emptyList()
        )
        whenever(fuzzingRepository.getFuzzingProgress())
            .thenReturn(flowOf(progress))

        val result = useCase.getFuzzingProgress().first()

        assertNotNull(result)
        assertEquals(50, result?.packetsSent)
    }

    @Test
    @DisplayName("getAllFuzzingResults should return all results")
    fun testGetAllResults() = runTest {
        val results = listOf(createTestResult("fuzz-1"))
        whenever(fuzzingRepository.getAllFuzzingResults())
            .thenReturn(flowOf(results))

        val result = useCase.getAllFuzzingResults().first()

        assertEquals(1, result.size)
    }

    @Test
    @DisplayName("getFuzzingResultsForDevice should filter by device")
    fun testGetResultsForDevice() = runTest {
        val results = listOf(createTestResult("fuzz-1"))
        whenever(fuzzingRepository.getFuzzingResultsForDevice(any()))
            .thenReturn(flowOf(results))

        val result = useCase.getFuzzingResultsForDevice("AA:BB:CC:DD:EE:FF").first()

        assertEquals(1, result.size)
        verify(fuzzingRepository).getFuzzingResultsForDevice("AA:BB:CC:DD:EE:FF")
    }

    @Test
    @DisplayName("getFindingsForResult should return findings")
    fun testGetFindingsForResult() = runTest {
        val findings = listOf(createTestFinding())
        whenever(fuzzingRepository.getFindingsForResult(any()))
            .thenReturn(flowOf(findings))

        val result = useCase.getFindingsForResult("fuzz-1").first()

        assertEquals(1, result.size)
    }

    @Test
    @DisplayName("getCriticalFindings should return critical only")
    fun testGetCriticalFindings() = runTest {
        val criticalFinding = createTestFinding(VulnerabilitySeverity.CRITICAL)
        whenever(fuzzingRepository.getFindingsBySeverity(VulnerabilitySeverity.CRITICAL))
            .thenReturn(flowOf(listOf(criticalFinding)))

        val result = useCase.getCriticalFindings().first()

        assertEquals(1, result.size)
        assertEquals(VulnerabilitySeverity.CRITICAL, result.first().severity)
    }

    @Test
    @DisplayName("getFuzzingStatistics should return statistics")
    fun testGetFuzzingStatistics() = runTest {
        val stats = FuzzingStatistics(
            totalTests = 10,
            completedTests = 8,
            totalPacketsSent = 1000,
            totalFindings = 5,
            criticalFindings = 1,
            highFindings = 2
        )
        whenever(fuzzingRepository.getFuzzingStatistics())
            .thenReturn(flowOf(stats))

        val result = useCase.getFuzzingStatistics().first()

        assertEquals(10, result.totalTests)
        assertEquals(5, result.totalFindings)
    }

    @Test
    @DisplayName("getAvailablePatterns should return patterns")
    fun testGetAvailablePatterns() = runTest {
        val patterns = listOf(createTestPattern())
        whenever(fuzzingRepository.getAvailablePatterns())
            .thenReturn(flowOf(patterns))

        val result = useCase.getAvailablePatterns().first()

        assertEquals(1, result.size)
    }

    @Test
    @DisplayName("getPatternsForType should filter by type")
    fun testGetPatternsForType() = runTest {
        val patterns = listOf(createTestPattern())
        whenever(fuzzingRepository.getPatternsForType(any()))
            .thenReturn(patterns)

        val result = useCase.getPatternsForType(PatternType.OVERLONG)

        assertEquals(1, result.size)
        verify(fuzzingRepository).getPatternsForType(PatternType.OVERLONG)
    }

    @Test
    @DisplayName("getKnownExploitPatterns should return exploit patterns")
    fun testGetKnownExploitPatterns() = runTest {
        val patterns = listOf(createTestPattern())
        whenever(fuzzingRepository.getKnownExploitPatterns())
            .thenReturn(patterns)

        val result = useCase.getKnownExploitPatterns()

        assertEquals(1, result.size)
    }

    @Test
    @DisplayName("createRecommendedConfig should create safe config")
    fun testCreateRecommendedConfig() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = emptyList(),
            allowedActions = emptySet(),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.getCurrentScope()).thenReturn(flowOf(scope))

        val config = useCase.createRecommendedConfig(testDevice)

        assertEquals(testDevice, config.targetDevice)
        assertEquals(FuzzMethod.MUTATION, config.fuzzMethod)
        assertEquals(1000, config.packetCount)
        assertTrue(config.packetsPerSecond <= 50)
        assertTrue(config.stopOnError)
        assertTrue(config.capturePackets)
    }

    @Test
    @DisplayName("createAggressiveConfig should create aggressive config")
    fun testCreateAggressiveConfig() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = emptyList(),
            allowedActions = emptySet(),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.getCurrentScope()).thenReturn(flowOf(scope))

        val config = useCase.createAggressiveConfig(testDevice)

        assertEquals(testDevice, config.targetDevice)
        assertEquals(FuzzMethod.RANDOM, config.fuzzMethod)
        assertEquals(10000, config.packetCount)
        assertEquals(100, config.packetsPerSecond)
        assertFalse(config.stopOnError)
        assertFalse(config.stopOnDisconnect)
    }

    // Helper functions

    private fun createTestResult(id: String): FuzzResult {
        return FuzzResult(
            id = id,
            config = testConfig,
            startTime = Instant.now().minusSeconds(60),
            endTime = Instant.now(),
            status = FuzzStatus.COMPLETED,
            packetsSent = 100,
            packetsReceived = 95,
            errors = emptyList(),
            findings = emptyList(),
            captureFile = null
        )
    }

    private fun createTestFinding(severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH): FuzzFinding {
        return FuzzFinding(
            id = "finding-1",
            type = FuzzFindingType.CRASH,
            severity = severity,
            description = "Test finding",
            packetData = byteArrayOf(0x01, 0x02),
            timestamp = Instant.now(),
            reproductionSteps = emptyList()
        )
    }

    private fun createTestPattern(): FuzzDataPattern {
        return FuzzDataPattern(
            name = "Buffer Overflow",
            description = "Long data",
            patternType = PatternType.OVERLONG,
            data = ByteArray(512) { 0x41 }
        )
    }
}
