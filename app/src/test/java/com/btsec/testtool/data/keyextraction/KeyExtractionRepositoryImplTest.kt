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
import com.btsec.testtool.domain.repository.*
import io.mockk.every
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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for KeyExtractionRepositoryImpl — verifies CRUD on extraction results,
 * key analysis, encryption analysis, pairing monitor lifecycle, key database operations,
 * statistics, logging, and KNOB attack probing.
 *
 * Android Context is mocked via MockK since the tests run outside of an
 * Android device/emulator. BluetoothAdapter is unavailable so encryption analysis
 * falls back to the unbonded path.
 *
 * This is for AUTHORIZED security testing only.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("KeyExtractionRepositoryImpl")
class KeyExtractionRepositoryImplTest {

    private lateinit var context: Context
    private lateinit var probe: KeyExtractionProbe
    private lateinit var repository: KeyExtractionRepositoryImpl

    private val testDevice = BluetoothDevice(
        address = "AA:BB:CC:DD:EE:FF",
        name = "Test BLE Device",
        type = BluetoothType.BLE,
        deviceClass = DeviceClass.PHONE,
        bondState = BondState.NONE,
        rssi = -45,
        txPower = 4,
        firstSeen = Instant.now(),
        lastSeen = Instant.now()
    )

    private val testDevice2 = BluetoothDevice(
        address = "11:22:33:44:55:66",
        name = "Classic Device",
        type = BluetoothType.CLASSIC,
        deviceClass = DeviceClass.COMPUTER,
        bondState = BondState.BONDED,
        rssi = -70,
        txPower = null,
        firstSeen = Instant.now(),
        lastSeen = Instant.now()
    )

    private fun createExtractionResult(
        id: String = "ext-${System.nanoTime()}",
        device: BluetoothDevice = testDevice,
        keyType: KeyType = KeyType.LTK,
        extracted: Boolean = false,
        keyValue: ByteArray? = null,
        method: ExtractionMethod = ExtractionMethod.PASSIVE_MONITORING,
        confidence: ExtractionConfidence = ExtractionConfidence.LOW,
        timestamp: Instant = Instant.now()
    ) = KeyExtractionResult(
        id = id,
        targetDevice = device,
        keyType = keyType,
        extracted = extracted,
        keyValue = keyValue,
        method = method,
        confidence = confidence,
        timestamp = timestamp
    )

    /**
     * Test probe that allows configuring negotiation results for testing.
     */
    private class TestProbe(
        private val negotiationResults: Map<Int, KeyNegotiationResult> = emptyMap(),
        private val encryptionInfo: EncryptionInfo? = null,
        private val bonded: Boolean = false
    ) : KeyExtractionProbe {

        override suspend fun negotiateKeySize(keySizeBytes: Int): KeyNegotiationResult {
            return negotiationResults[keySizeBytes] ?: KeyNegotiationResult.Rejected(minimumKeySize = 7)
        }

        override suspend fun readCharacteristic(serviceUuid: String, charUuid: String): ByteArray? = null

        override fun getEncryptionInfo(): EncryptionInfo? = encryptionInfo

        override fun isBonded(): Boolean = bonded

        override fun close() {}
    }

    @BeforeEach
    fun setUp() {
        context = mockk(relaxed = true)
        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns null
        probe = TestProbe()
        repository = KeyExtractionRepositoryImpl(context, probe)
    }

    // ========== KNOB Attack Probing ==========

    @Nested
    @DisplayName("KNOB attack probing")
    inner class KnobAttackTests {

        @Test
        @DisplayName("extractKey should detect KNOB vulnerability when device accepts 1-byte key")
        fun testExtractKey_knobVulnerable() = runTest {
            // Probe accepts 1-byte key (KNOB vulnerable)
            val vulnerableProbe = TestProbe(
                negotiationResults = mapOf(1 to KeyNegotiationResult.Accepted(acceptedKeySize = 1)),
                encryptionInfo = null
            )
            repository = KeyExtractionRepositoryImpl(context, vulnerableProbe)

            val progressList = repository.extractKey(
                testDevice, KeyType.LTK, ExtractionMethod.ACTIVE_PROMPT
            ).first { it.status == ExtractionStatus.COMPLETED }

            assertEquals(ExtractionStatus.COMPLETED, progressList.status)
            assertEquals(100, progressList.progressPercentage)

            // Verify result was saved with extracted=true
            val results = repository.getAllExtractionResults().first()
            assertEquals(1, results.size)
            assertTrue(results[0].extracted)
            assertEquals(ExtractionConfidence.HIGH, results[0].confidence)
            assertTrue(results[0].notes?.contains("KNOB vulnerable") == true)
        }

        @Test
        @DisplayName("extractKey should report safe when device rejects all unsafe key sizes")
        fun testExtractKey_knobSafe() = runTest {
            // All key sizes rejected (safe device)
            val safeProbe = TestProbe(
                negotiationResults = emptyMap(), // defaults to Rejected for all
                encryptionInfo = EncryptionInfo(
                    keySize = 16,
                    encryptionType = "AES-CCM",
                    isSecureConnection = true
                )
            )
            repository = KeyExtractionRepositoryImpl(context, safeProbe)

            repository.extractKey(
                testDevice, KeyType.LTK, ExtractionMethod.ACTIVE_PROMPT
            ).first { it.status == ExtractionStatus.COMPLETED }

            val results = repository.getAllExtractionResults().first()
            assertEquals(1, results.size)
            assertFalse(results[0].extracted)
            assertEquals(ExtractionConfidence.MEDIUM, results[0].confidence)
            assertTrue(results[0].notes?.contains("16 bytes") == true)
        }

        @Test
        @DisplayName("extractKey should handle unavailable platform gracefully")
        fun testExtractKey_unavailable() = runTest {
            // Platform cannot probe
            val unavailableProbe = TestProbe(
                negotiationResults = mapOf(1 to KeyNegotiationResult.Unavailable),
                encryptionInfo = null
            )
            repository = KeyExtractionRepositoryImpl(context, unavailableProbe)

            repository.extractKey(
                testDevice, KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING
            ).first { it.status == ExtractionStatus.COMPLETED }

            val results = repository.getAllExtractionResults().first()
            assertEquals(1, results.size)
            assertFalse(results[0].extracted)
            assertEquals(ExtractionConfidence.LOW, results[0].confidence)
            assertTrue(results[0].notes?.contains("Could not probe") == true)
        }

        @Test
        @DisplayName("extractKey should report MEDIUM confidence with encryption info but no vulnerability")
        fun testExtractKey_existingEncryption() = runTest {
            // Device has encryption info but no negotiation vulnerability
            val encProbe = TestProbe(
                negotiationResults = emptyMap(), // all rejected
                encryptionInfo = EncryptionInfo(
                    keySize = 16,
                    encryptionType = "AES-CCM",
                    isSecureConnection = false
                )
            )
            repository = KeyExtractionRepositoryImpl(context, encProbe)

            repository.extractKey(
                testDevice, KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING
            ).first { it.status == ExtractionStatus.COMPLETED }

            val results = repository.getAllExtractionResults().first()
            assertEquals(1, results.size)
            assertFalse(results[0].extracted)
            assertEquals(ExtractionConfidence.MEDIUM, results[0].confidence)
        }

        @Test
        @DisplayName("extractKey should detect vulnerability with 3-byte key acceptance")
        fun testExtractKey_knobVulnerable3Byte() = runTest {
            // Device accepts 3-byte key (still vulnerable)
            val probe3byte = TestProbe(
                negotiationResults = mapOf(
                    1 to KeyNegotiationResult.Rejected(minimumKeySize = 3),
                    2 to KeyNegotiationResult.Rejected(minimumKeySize = 3),
                    3 to KeyNegotiationResult.Accepted(acceptedKeySize = 3)
                ),
                encryptionInfo = null
            )
            repository = KeyExtractionRepositoryImpl(context, probe3byte)

            repository.extractKey(
                testDevice, KeyType.LTK, ExtractionMethod.ACTIVE_PROMPT
            ).first { it.status == ExtractionStatus.COMPLETED }

            val results = repository.getAllExtractionResults().first()
            assertTrue(results[0].extracted)
            assertEquals(ExtractionConfidence.HIGH, results[0].confidence)
            assertTrue(results[0].notes?.contains("3-byte") == true)
        }

        @Test
        @DisplayName("extractKey should handle negotiation errors gracefully")
        fun testExtractKey_negotiationError() = runTest {
            val errorProbe = TestProbe(
                negotiationResults = mapOf(1 to KeyNegotiationResult.Error("Connection lost")),
                encryptionInfo = null
            )
            repository = KeyExtractionRepositoryImpl(context, errorProbe)

            repository.extractKey(
                testDevice, KeyType.LTK, ExtractionMethod.ACTIVE_PROMPT
            ).first { it.status == ExtractionStatus.COMPLETED }

            val results = repository.getAllExtractionResults().first()
            assertFalse(results[0].extracted)
            assertEquals(ExtractionConfidence.LOW, results[0].confidence)
        }
    }

    // ========== Result CRUD ==========

    @Nested
    @DisplayName("Extraction result CRUD operations")
    inner class ResultCrudTests {

        @Test
        @DisplayName("saveExtractionResult should store result and getAllExtractionResults should return it")
        fun saveAndGetAll() = runTest {
            val result = createExtractionResult(id = "ext-1")

            val saveOutcome = repository.saveExtractionResult(result)
            assertTrue(saveOutcome.isSuccess)

            val all = repository.getAllExtractionResults().first()
            assertEquals(1, all.size)
            assertEquals("ext-1", all[0].id)
        }

        @Test
        @DisplayName("getExtractionResult should return result by ID or null if not found")
        fun getResultById() = runTest {
            val r1 = createExtractionResult(id = "ext-1")
            val r2 = createExtractionResult(id = "ext-2")
            repository.saveExtractionResult(r1)
            repository.saveExtractionResult(r2)

            val found = repository.getExtractionResult("ext-1")
            assertNotNull(found)
            assertEquals("ext-1", found.id)

            val notFound = repository.getExtractionResult("nonexistent")
            assertNull(notFound)
        }

        @Test
        @DisplayName("deleteExtractionResult should remove the specified result")
        fun deleteResult() = runTest {
            val r1 = createExtractionResult(id = "ext-1")
            val r2 = createExtractionResult(id = "ext-2")
            repository.saveExtractionResult(r1)
            repository.saveExtractionResult(r2)

            val outcome = repository.deleteExtractionResult("ext-1")
            assertTrue(outcome.isSuccess)

            val remaining = repository.getAllExtractionResults().first()
            assertEquals(1, remaining.size)
            assertEquals("ext-2", remaining[0].id)
        }

        @Test
        @DisplayName("getExtractionResultsForDevice should filter by device address")
        fun getResultsForDevice() = runTest {
            val r1 = createExtractionResult(id = "ext-1", device = testDevice)
            val r2 = createExtractionResult(id = "ext-2", device = testDevice2)
            repository.saveExtractionResult(r1)
            repository.saveExtractionResult(r2)

            val filtered = repository.getExtractionResultsForDevice("AA:BB:CC:DD:EE:FF").first()
            assertEquals(1, filtered.size)
            assertEquals("ext-1", filtered[0].id)
        }

        @Test
        @DisplayName("getExtractionResultsByKeyType should filter by key type")
        fun getResultsByKeyType() = runTest {
            val ltkResult = createExtractionResult(id = "ext-1", keyType = KeyType.LTK)
            val irkResult = createExtractionResult(id = "ext-2", keyType = KeyType.IRK)
            repository.saveExtractionResult(ltkResult)
            repository.saveExtractionResult(irkResult)

            val filtered = repository.getExtractionResultsByKeyType(KeyType.LTK).first()
            assertEquals(1, filtered.size)
            assertEquals("ext-1", filtered[0].id)
        }

        @Test
        @DisplayName("getSuccessfulExtractions should return only extracted results")
        fun getSuccessfulExtractions() = runTest {
            val success = createExtractionResult(
                id = "ext-ok",
                extracted = true,
                keyValue = byteArrayOf(0x01, 0x02, 0x03),
                confidence = ExtractionConfidence.HIGH
            )
            val failure = createExtractionResult(id = "ext-fail", extracted = false)
            repository.saveExtractionResult(success)
            repository.saveExtractionResult(failure)

            val successful = repository.getSuccessfulExtractions().first()
            assertEquals(1, successful.size)
            assertEquals("ext-ok", successful[0].id)
        }
    }

    // ========== Extraction Lifecycle ==========

    @Nested
    @DisplayName("Extraction lifecycle controls")
    inner class LifecycleTests {

        @Test
        @DisplayName("cancelExtraction should update status to CANCELLED")
        fun cancelExtraction() = runTest {
            val outcome = repository.cancelExtraction()
            assertTrue(outcome.isSuccess)
            assertEquals(ExtractionStatus.CANCELLED, repository.getExtractionStatus().first())
        }
    }

    // ========== Key Analysis ==========

    @Nested
    @DisplayName("Key security analysis")
    inner class KeyAnalysisTests {

        @Test
        @DisplayName("analyzeKeySecurity should return POOR score for unbonded device")
        fun analyzeKeySecurityUnbonded() = runTest {
            val analysis = repository.analyzeKeySecurity(testDevice)

            assertEquals(testDevice.address, analysis.deviceAddress)
            assertEquals(SecurityScore.POOR, analysis.overallScore)
            assertEquals(EncryptionStrength.NONE, analysis.encryptionStrength)
            assertTrue(analysis.recommendations.contains("Enable encryption by pairing with the device"))
        }

        @Test
        @DisplayName("checkForWeakKeys should return empty list (not implemented)")
        fun checkForWeakKeys() = runTest {
            val findings = repository.checkForWeakKeys(testDevice)
            assertTrue(findings.isEmpty())
        }

        @Test
        @DisplayName("verifyKey should return false (not implemented)")
        fun verifyKey() = runTest {
            val result = repository.verifyKey(KeyType.LTK, byteArrayOf(0x01), testDevice)
            assertFalse(result)
        }

        @Test
        @DisplayName("deriveKey should return null (not implemented)")
        fun deriveKey() = runTest {
            val extracted = createExtractionResult(
                extracted = true,
                keyValue = byteArrayOf(0x01, 0x02)
            )
            val derived = repository.deriveKey(extracted, KeyType.IRK)
            assertNull(derived)
        }
    }

    // ========== Pairing Monitor ==========

    @Nested
    @DisplayName("Pairing monitor lifecycle")
    inner class PairingMonitorTests {

        @Test
        @DisplayName("stopPairingMonitor should deactivate monitor")
        fun stopPairingMonitor() = runTest {
            val outcome = repository.stopPairingMonitor()
            assertTrue(outcome.isSuccess)
            assertFalse(repository.isPairingMonitorActive().first())
        }

        @Test
        @DisplayName("isPairingMonitorActive should reflect state after stop")
        fun pairingMonitorState() = runTest {
            assertFalse(repository.isPairingMonitorActive().first())
            repository.stopPairingMonitor()
            assertFalse(repository.isPairingMonitorActive().first())
        }
    }

    // ========== Key Database ==========

    @Nested
    @DisplayName("Key database operations")
    inner class KeyDatabaseTests {

        @Test
        @DisplayName("isKnownDefaultKey should return false (not implemented)")
        fun isKnownDefaultKey() = runTest {
            val result = repository.isKnownDefaultKey(KeyType.LTK, byteArrayOf(0x00))
            assertFalse(result)
        }

        @Test
        @DisplayName("getDefaultKeyInfo should return null (not implemented)")
        fun getDefaultKeyInfo() = runTest {
            val info = repository.getDefaultKeyInfo(byteArrayOf(0x00))
            assertNull(info)
        }

        @Test
        @DisplayName("addToKeyDatabase should return success (no-op)")
        fun addToKeyDatabase() = runTest {
            val outcome = repository.addToKeyDatabase("AA:BB:CC:DD:EE:FF", KeyType.LTK, byteArrayOf(0x01))
            assertTrue(outcome.isSuccess)
        }

        @Test
        @DisplayName("lookupKeyInDatabase should return null (not implemented)")
        fun lookupKeyInDatabase() = runTest {
            val key = repository.lookupKeyInDatabase("AA:BB:CC:DD:EE:FF", KeyType.LTK)
            assertNull(key)
        }
    }

    // ========== Encryption Analysis ==========

    @Nested
    @DisplayName("Encryption analysis")
    inner class EncryptionAnalysisTests {

        @Test
        @DisplayName("analyzeEncryptionStrength should return NONE encryption when adapter unavailable")
        fun encryptionStrengthNoAdapter() = runTest {
            val analysis = repository.analyzeEncryptionStrength(testDevice)

            assertEquals(testDevice.address, analysis.deviceAddress)
            assertFalse(analysis.encryptionEnabled)
            assertEquals(0, analysis.encryptionKeySize)
            assertFalse(analysis.usingSecureConnections)
            assertEquals(PairingMethod.JUST_WORKS, analysis.pairingMethod)
            assertEquals(EncryptionMode.NONE, analysis.encryptionMode)
            assertTrue(analysis.findings.isNotEmpty())
        }

        @Test
        @DisplayName("supportsSecureConnections should return false when adapter unavailable")
        fun supportsSecureConnectionsNoAdapter() = runTest {
            val result = repository.supportsSecureConnections(testDevice)
            assertFalse(result)
        }

        @Test
        @DisplayName("getEncryptionKeySize should return null when adapter unavailable")
        fun encryptionKeySizeNoAdapter() = runTest {
            val result = repository.getEncryptionKeySize(testDevice)
            assertNull(result)
        }
    }

    // ========== Statistics ==========

    @Nested
    @DisplayName("Key extraction statistics")
    inner class StatisticsTests {

        @Test
        @DisplayName("getKeyExtractionStatistics should aggregate results correctly")
        fun extractionStatistics() = runTest {
            val successResult = createExtractionResult(
                id = "ext-1",
                keyType = KeyType.LTK,
                extracted = true,
                keyValue = byteArrayOf(0x01),
                method = ExtractionMethod.PASSIVE_MONITORING
            )
            val failResult = createExtractionResult(
                id = "ext-2",
                keyType = KeyType.IRK,
                extracted = false,
                method = ExtractionMethod.ACTIVE_PROMPT
            )
            repository.saveExtractionResult(successResult)
            repository.saveExtractionResult(failResult)

            val stats = repository.getKeyExtractionStatistics().first()
            assertEquals(2, stats.totalExtractions)
            assertEquals(1, stats.successfulExtractions)
            assertEquals(1, stats.failedExtractions)
            assertEquals(0.5, stats.successRate)
            assertEquals(1, stats.extractionsByType[KeyType.LTK])
            assertEquals(1, stats.extractionsByType[KeyType.IRK])
            assertEquals(1, stats.extractionsByMethod[ExtractionMethod.PASSIVE_MONITORING])
            assertEquals(1, stats.extractionsByMethod[ExtractionMethod.ACTIVE_PROMPT])
        }

        @Test
        @DisplayName("getKeyExtractionStatistics with no results should return zeroed stats")
        fun emptyStatistics() = runTest {
            val stats = repository.getKeyExtractionStatistics().first()
            assertEquals(0, stats.totalExtractions)
            assertEquals(0, stats.successfulExtractions)
            assertEquals(0, stats.failedExtractions)
            assertEquals(0.0, stats.successRate)
            assertNull(stats.mostExtractedDevice)
        }

        @Test
        @DisplayName("getStatisticsForDevice should return per-device stats")
        fun deviceStatistics() = runTest {
            val r1 = createExtractionResult(
                id = "ext-1", device = testDevice,
                keyType = KeyType.LTK, extracted = true,
                keyValue = byteArrayOf(0x01)
            )
            val r2 = createExtractionResult(
                id = "ext-2", device = testDevice2,
                keyType = KeyType.IRK, extracted = false
            )
            repository.saveExtractionResult(r1)
            repository.saveExtractionResult(r2)

            val stats = repository.getStatisticsForDevice("AA:BB:CC:DD:EE:FF")
            assertEquals("AA:BB:CC:DD:EE:FF", stats.deviceAddress)
            assertEquals(1, stats.totalExtractions)
            assertEquals(1, stats.successfulExtractions)
            assertEquals(listOf(KeyType.LTK), stats.extractedKeyTypes)
        }
    }

    // ========== Logging ==========

    @Nested
    @DisplayName("Extraction operation logging")
    inner class LoggingTests {

        @Test
        @DisplayName("logExtractionOperation should store and retrieve operation")
        fun logAndRetrieve() = runTest {
            val operation = KeyExtractionOperation(
                id = "op-1",
                timestamp = Instant.now(),
                operationType = ExtractionOperationType.START,
                targetDevice = "AA:BB:CC:DD:EE:FF",
                keyType = KeyType.LTK,
                method = ExtractionMethod.PASSIVE_MONITORING,
                success = true,
                errorMessage = null,
                durationMs = null
            )

            repository.logExtractionOperation(operation)

            val logs = repository.getExtractionLogs().first()
            assertEquals(1, logs.size)
            assertEquals("op-1", logs[0].id)
            assertEquals(ExtractionOperationType.START, logs[0].operationType)
            assertEquals(KeyType.LTK, logs[0].keyType)
            assertTrue(logs[0].success)
        }

        @Test
        @DisplayName("Multiple log entries should be retained in order")
        fun multipleLogs() = runTest {
            val op1 = KeyExtractionOperation(
                "op-1", Instant.now(), ExtractionOperationType.START,
                "AA:BB:CC:DD:EE:FF", KeyType.LTK, null, true, null, null
            )
            val op2 = KeyExtractionOperation(
                "op-2", Instant.now(), ExtractionOperationType.COMPLETE,
                "AA:BB:CC:DD:EE:FF", KeyType.LTK, ExtractionMethod.PASSIVE_MONITORING,
                true, null, 3000L
            )

            repository.logExtractionOperation(op1)
            repository.logExtractionOperation(op2)

            val logs = repository.getExtractionLogs().first()
            assertEquals(2, logs.size)
            assertEquals("op-1", logs[0].id)
            assertEquals("op-2", logs[1].id)
        }
    }
}
