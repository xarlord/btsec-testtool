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
 * Unit tests for KeyExtractionUseCase.
 */
@ExtendWith(MockitoExtension::class)
@DisplayName("KeyExtractionUseCase Tests")
class KeyExtractionUseCaseTest {

    @Mock
    private lateinit var keyExtractionRepository: KeyExtractionRepository

    @Mock
    private lateinit var authorizationUseCase: AuthorizationUseCase

    @Mock
    private lateinit var consentRepository: ConsentRepository

    private lateinit var useCase: KeyExtractionUseCase

    private lateinit var testDevice: BluetoothDevice

    @BeforeEach
    fun setUp() {
        useCase = KeyExtractionUseCase(
            keyExtractionRepository,
            authorizationUseCase,
            consentRepository
        )

        testDevice = BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF",
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

    @Test
    @DisplayName("extractKey should succeed when authorized")
    fun testExtractKeyAuthorized() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = listOf(TargetDevice("AA:BB:CC:DD:EE:FF", "Test Device")),
            allowedActions = setOf(TestAction.EXTRACT_KEYS),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.isTargetInScope(any())).thenReturn(true)
        whenever(keyExtractionRepository.extractKey(any(), any(), any()))
            .thenReturn(flowOf(ExtractionProgress.Started(testDevice, KeyType.LTK)))

        val result = useCase.extractKey(testDevice, KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING)

        assertTrue(result is KeyExtractionStartResult.Started)
        verify(keyExtractionRepository).extractKey(testDevice, KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING)
    }

    @Test
    @DisplayName("extractKey should fail when not authorized")
    fun testExtractKeyNotAuthorized() = runTest {
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.NotAuthorized("Not authorized"))

        val result = useCase.extractKey(testDevice, KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING)

        assertTrue(result is KeyExtractionStartResult.NotAuthorized)
        verify(keyExtractionRepository, never()).extractKey(any(), any(), any())
    }

    @Test
    @DisplayName("extractKey should require consent when denied")
    fun testExtractKeyConsentDenied() = runTest {
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.ConsentDenied(mock()))

        val result = useCase.extractKey(testDevice, KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING)

        assertTrue(result is KeyExtractionStartResult.ConsentRequired)
    }

    @Test
    @DisplayName("extractKey should fail when device not in scope")
    fun testExtractKeyDeviceNotInScope() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = emptyList(),
            allowedActions = setOf(TestAction.EXTRACT_KEYS),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.isTargetInScope(any())).thenReturn(false)

        val result = useCase.extractKey(testDevice, KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING)

        assertTrue(result is KeyExtractionStartResult.DeviceNotInScope)
    }

    @Test
    @DisplayName("extractAllKeys should extract all key types")
    fun testExtractAllKeys() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = listOf(TargetDevice("AA:BB:CC:DD:EE:FF", "Test Device")),
            allowedActions = setOf(TestAction.EXTRACT_KEYS),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.isTargetInScope(any())).thenReturn(true)
        whenever(keyExtractionRepository.extractAllKeys(any()))
            .thenReturn(flowOf(ExtractionProgress.Started(testDevice, KeyType.LTK)))

        val result = useCase.extractAllKeys(testDevice)

        assertTrue(result is KeyExtractionStartResult.Started)
        verify(keyExtractionRepository).extractAllKeys(testDevice)
    }

    @Test
    @DisplayName("cancelExtraction should cancel active extraction")
    fun testCancelExtraction() = runTest {
        whenever(keyExtractionRepository.cancelExtraction())
            .thenReturn(Result.success(Unit))

        val result = useCase.cancelExtraction()

        assertTrue(result.isSuccess)
        verify(keyExtractionRepository).cancelExtraction()
    }

    @Test
    @DisplayName("getExtractionStatus should return current status")
    fun testGetExtractionStatus() = runTest {
        whenever(keyExtractionRepository.getExtractionStatus())
            .thenReturn(flowOf(ExtractionStatus.Idle))

        val status = useCase.getExtractionStatus().first()

        assertEquals(ExtractionStatus.Idle, status)
    }

    @Test
    @DisplayName("getExtractionProgress should return progress")
    fun testGetExtractionProgress() = runTest {
        val progress = ExtractionProgress.Progress(
            targetDevice = testDevice,
            keyType = KeyType.LTK,
            percentage = 0.5f,
            currentStep = "Monitoring pairing..."
        )
        whenever(keyExtractionRepository.getExtractionProgress())
            .thenReturn(flowOf(progress))

        val result = useCase.getExtractionProgress().first()

        assertNotNull(result)
        assertEquals(KeyType.LTK, result?.keyType)
    }

    @Test
    @DisplayName("getAllExtractionResults should return all results")
    fun testGetAllResults() = runTest {
        val results = listOf(createTestResult("key-1"))
        whenever(keyExtractionRepository.getAllExtractionResults())
            .thenReturn(flowOf(results))

        val result = useCase.getAllExtractionResults().first()

        assertEquals(1, result.size)
    }

    @Test
    @DisplayName("getExtractionResultsForDevice should filter by device")
    fun testGetResultsForDevice() = runTest {
        val results = listOf(createTestResult("key-1"))
        whenever(keyExtractionRepository.getExtractionResultsForDevice(any()))
            .thenReturn(flowOf(results))

        val result = useCase.getExtractionResultsForDevice("AA:BB:CC:DD:EE:FF").first()

        assertEquals(1, result.size)
        verify(keyExtractionRepository).getExtractionResultsForDevice("AA:BB:CC:DD:EE:FF")
    }

    @Test
    @DisplayName("getSuccessfulExtractions should return successful only")
    fun testGetSuccessfulExtractions() = runTest {
        val successResult = createTestResult("key-1", extracted = true)
        whenever(keyExtractionRepository.getSuccessfulExtractions())
            .thenReturn(flowOf(listOf(successResult)))

        val result = useCase.getSuccessfulExtractions().first()

        assertEquals(1, result.size)
        assertTrue(result.first().extracted)
    }

    @Test
    @DisplayName("getExtractionsByKeyType should filter by key type")
    fun testGetExtractionsByKeyType() = runTest {
        val ltkResult = createTestResult("key-1", KeyType.LTK)
        whenever(keyExtractionRepository.getExtractionResultsByKeyType(any()))
            .thenReturn(flowOf(listOf(ltkResult)))

        val result = useCase.getExtractionsByKeyType(KeyType.LTK).first()

        assertEquals(1, result.size)
        assertEquals(KeyType.LTK, result.first().keyType)
    }

    @Test
    @DisplayName("analyzeKeySecurity should return analysis when authorized")
    fun testAnalyzeKeySecurityAuthorized() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = listOf(TargetDevice("AA:BB:CC:DD:EE:FF", "Test Device")),
            allowedActions = setOf(TestAction.EXTRACT_KEYS),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.isTargetInScope(any())).thenReturn(true)

        val analysis = KeySecurityAnalysis(
            deviceAddress = "AA:BB:CC:DD:EE:FF",
            deviceName = "Test Device",
            analysisDate = Instant.now(),
            overallScore = SecurityScore.HIGH,
            findings = emptyList(),
            extractedKeys = emptyList(),
            encryptionStrength = EncryptionStrength.STRONG,
            recommendations = emptyList()
        )
        whenever(keyExtractionRepository.analyzeKeySecurity(any()))
            .thenReturn(analysis)

        val result = useCase.analyzeKeySecurity(testDevice)

        assertEquals("AA:BB:CC:DD:EE:FF", result.deviceAddress)
        assertEquals(SecurityScore.HIGH, result.overallScore)
    }

    @Test
    @DisplayName("analyzeKeySecurity should return error when not authorized")
    fun testAnalyzeKeySecurityNotAuthorized() = runTest {
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.NotAuthorized("Not authorized"))

        val result = useCase.analyzeKeySecurity(testDevice)

        assertEquals(SecurityScore.CRITICAL, result.overallScore)
        assertTrue(result.findings.any { it.description.contains("Authorization required") })
    }

    @Test
    @DisplayName("checkForWeakKeys should return findings when authorized")
    fun testCheckForWeakKeysAuthorized() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = listOf(TargetDevice("AA:BB:CC:DD:EE:FF", "Test Device")),
            allowedActions = setOf(TestAction.EXTRACT_KEYS),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.isTargetInScope(any())).thenReturn(true)

        val findings = listOf(
            WeakKeyFinding(
                keyType = KeyType.LTK,
                severity = VulnerabilitySeverity.MEDIUM,
                description = "Weak key detected",
                recommendation = "Use stronger key"
            )
        )
        whenever(keyExtractionRepository.checkForWeakKeys(any()))
            .thenReturn(findings)

        val result = useCase.checkForWeakKeys(testDevice)

        assertEquals(1, result.size)
        assertEquals(KeyType.LTK, result.first().keyType)
    }

    @Test
    @DisplayName("checkForWeakKeys should return empty when not authorized")
    fun testCheckForWeakKeysNotAuthorized() = runTest {
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.NotAuthorized("Not authorized"))

        val result = useCase.checkForWeakKeys(testDevice)

        assertTrue(result.isEmpty())
    }

    @Test
    @DisplayName("verifyKey should verify key validity")
    fun testVerifyKey() = runTest {
        val keyValue = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        whenever(keyExtractionRepository.verifyKey(any(), any(), any()))
            .thenReturn(true)

        val result = useCase.verifyKey(KeyType.LTK, keyValue, testDevice)

        assertTrue(result)
        verify(keyExtractionRepository).verifyKey(KeyType.LTK, keyValue, testDevice)
    }

    @Test
    @DisplayName("startPairingMonitor should start monitoring")
    fun testStartPairingMonitor() = runTest {
        val capture = PairingCapture(
            deviceAddress = "AA:BB:CC:DD:EE:FF",
            keyType = KeyType.LTK,
            keyValue = null,
            timestamp = Instant.now()
        )
        whenever(keyExtractionRepository.startPairingMonitor())
            .thenReturn(flowOf(capture))

        val result = useCase.startPairingMonitor().first()

        assertNotNull(result)
        assertEquals("AA:BB:CC:DD:EE:FF", result.deviceAddress)
    }

    @Test
    @DisplayName("stopPairingMonitor should stop monitoring")
    fun testStopPairingMonitor() = runTest {
        whenever(keyExtractionRepository.stopPairingMonitor())
            .thenReturn(Result.success(Unit))

        val result = useCase.stopPairingMonitor()

        assertTrue(result.isSuccess)
        verify(keyExtractionRepository).stopPairingMonitor()
    }

    @Test
    @DisplayName("isPairingMonitorActive should return status")
    fun testIsPairingMonitorActive() = runTest {
        whenever(keyExtractionRepository.isPairingMonitorActive())
            .thenReturn(flowOf(false))

        val isActive = useCase.isPairingMonitorActive().first()

        assertFalse(isActive)
    }

    @Test
    @DisplayName("analyzeEncryptionStrength should return analysis when authorized")
    fun testAnalyzeEncryptionStrengthAuthorized() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = listOf(TargetDevice("AA:BB:CC:DD:EE:FF", "Test Device")),
            allowedActions = setOf(TestAction.SCAN_VULNERABILITIES),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.isTargetInScope(any())).thenReturn(true)

        val analysis = EncryptionAnalysis(
            deviceAddress = "AA:BB:CC:DD:EE:FF",
            encryptionEnabled = true,
            encryptionKeySize = 128,
            supportsSecureConnections = true,
            usingSecureConnections = true,
            pairingMethod = PairingMethod.JUST_WORKS,
            encryptionMode = EncryptionMode.AES_CCM,
            findings = emptyList()
        )
        whenever(keyExtractionRepository.analyzeEncryptionStrength(any()))
            .thenReturn(analysis)

        val result = useCase.analyzeEncryptionStrength(testDevice)

        assertTrue(result.encryptionEnabled)
        assertEquals(128, result.encryptionKeySize)
    }

    @Test
    @DisplayName("supportsSecureConnections should check support")
    fun testSupportsSecureConnections() = runTest {
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = listOf(TargetDevice("AA:BB:CC:DD:EE:FF", "Test Device")),
            allowedActions = setOf(TestAction.SCAN_VULNERABILITIES),
            validFrom = Instant.now(),
            validUntil = Instant.now().plusSeconds(3600),
            maxPacketsPerSecond = 100
        )
        whenever(authorizationUseCase.requestActionAuthorization(any(), any()))
            .thenReturn(ActionAuthorizationResult.Authorized(mock(), scope))
        whenever(authorizationUseCase.isTargetInScope(any())).thenReturn(true)
        whenever(keyExtractionRepository.supportsSecureConnections(any()))
            .thenReturn(true)

        val result = useCase.supportsSecureConnections(testDevice)

        assertTrue(result)
    }

    @Test
    @DisplayName("getKeyExtractionStatistics should return statistics")
    fun testGetKeyExtractionStatistics() = runTest {
        val stats = KeyExtractionStatistics(
            totalExtractions = 10,
            successfulExtractions = 5,
            failedExtractions = 5,
            extractedKeyTypes = listOf(KeyType.LTK, KeyType.IRK),
            lastExtractionDate = Instant.now()
        )
        whenever(keyExtractionRepository.getKeyExtractionStatistics())
            .thenReturn(flowOf(stats))

        val result = useCase.getKeyExtractionStatistics().first()

        assertEquals(10, result.totalExtractions)
        assertEquals(5, result.successfulExtractions)
    }

    @Test
    @DisplayName("getDeviceKeySummary should return summary")
    fun testGetDeviceKeySummary() = runTest {
        val result = createTestResult("key-1")
        whenever(keyExtractionRepository.getExtractionResultsForDevice(any()))
            .thenReturn(flowOf(listOf(result)))
        whenever(keyExtractionRepository.getStatisticsForDevice(any()))
            .thenReturn(DeviceKeyExtractionStatistics(
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                totalExtractions = 1,
                successfulExtractions = 0,
                extractedKeyTypes = emptyList(),
                lastExtractionDate = Instant.now()
            ))

        val summary = useCase.getDeviceKeySummary("AA:BB:CC:DD:EE:FF")

        assertEquals("AA:BB:CC:DD:EE:FF", summary.deviceAddress)
        assertEquals(1, summary.totalExtractions)
    }

    // Helper functions

    private fun createTestResult(
        id: String,
        keyType: KeyType = KeyType.LTK,
        extracted: Boolean = false
    ): KeyExtractionResult {
        return KeyExtractionResult(
            id = id,
            targetDevice = testDevice,
            keyType = keyType,
            extracted = extracted,
            keyValue = if (extracted) byteArrayOf(0x01, 0x02) else null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.LOW,
            timestamp = Instant.now()
        )
    }
}
