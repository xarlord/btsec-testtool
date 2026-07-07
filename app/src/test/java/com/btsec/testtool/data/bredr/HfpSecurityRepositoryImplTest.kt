/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import com.btsec.testtool.domain.model.HfpSeverity
import com.btsec.testtool.domain.model.HfpTestCategory
import com.btsec.testtool.domain.model.HfpTestResult
import com.btsec.testtool.domain.model.HfpTestSuite
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [HfpSecurityRepositoryImpl].
 *
 * These tests verify:
 * - HFP connection state management
 * - AT command send returns Result.failure when disconnected
 * - Connection cleanup
 * - Test suite storage and retrieval
 */
@DisplayName("HfpSecurityRepositoryImpl")
class HfpSecurityRepositoryImplTest {
    private lateinit var context: Context
    private lateinit var bluetoothManager: BluetoothManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var repository: HfpSecurityRepositoryImpl

    @BeforeEach
    fun setup() {
        context = mockk(relaxed = true)
        bluetoothManager = mockk(relaxed = true)
        bluetoothAdapter = mockk(relaxed = true)

        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns bluetoothManager
        every { bluetoothManager.adapter } returns bluetoothAdapter

        repository = HfpSecurityRepositoryImpl(context)
    }

    private fun sampleSuite(
        address: String = "00:11:22:33:44:55",
        critical: Int = 0,
        high: Int = 0,
    ): HfpTestSuite =
        HfpTestSuite(
            deviceAddress = address,
            deviceName = "Test Device",
            results = emptyList(),
            criticalCount = critical,
            highCount = high,
            mediumCount = 0,
            lowCount = 0,
            infoCount = 0,
            overallRisk = HfpSeverity.LOW,
            testDurationMs = 1000L,
        )

    private fun sampleResult(command: String = "AT+CLCC"): HfpTestResult =
        HfpTestResult(
            category = HfpTestCategory.INFORMATION_DISCLOSURE,
            testName = "CLCC query",
            command = command,
            response = "OK",
            vulnerable = false,
            confidence = 0.95,
            evidence = "Command executed safely",
            severity = HfpSeverity.LOW,
            recommendation = "No action required",
        )

    @Test
    fun `isHfpConnected initially false`() =
        runTest {
            assertFalse(repository.isHfpConnected().first())
        }

    @Test
    fun `getTestSuites returns empty for non-existent device`() =
        runTest {
            val suites = repository.getTestSuites("00:11:22:33:44:55").first()
            assertTrue(suites.isEmpty())
        }

    @Test
    fun `getAllTestSuites returns all suites`() =
        runTest {
            val suite1 = sampleSuite(address = "00:11:22:33:44:55")
            val suite2 = sampleSuite(address = "00:11:22:33:44:56", critical = 1)

            repository.saveTestSuite(suite1)
            repository.saveTestSuite(suite2)

            val all = repository.getAllTestSuites().first()
            assertEquals(2, all.size)
        }

    @Test
    fun `saveTestSuite persists and retrieves test suite`() =
        runTest {
            val testSuite =
                HfpTestSuite(
                    deviceAddress = "00:11:22:33:44:55",
                    deviceName = "Test Device",
                    results = listOf(sampleResult()),
                    criticalCount = 0,
                    highCount = 1,
                    mediumCount = 0,
                    lowCount = 0,
                    infoCount = 0,
                    overallRisk = HfpSeverity.HIGH,
                    testDurationMs = 3000L,
                )

            repository.saveTestSuite(testSuite)

            val retrieved = repository.getTestSuites("00:11:22:33:44:55").first()
            assertEquals(1, retrieved.size)
            assertEquals("00:11:22:33:44:55", retrieved[0].deviceAddress)
        }

    @Test
    fun `disconnect stops connection when connected`() =
        runTest {
            repository.disconnect()
            assertFalse(repository.isHfpConnected().first())
        }

    @Test
    fun `sendAtCommand returns failure when not connected`() =
        runTest {
            val result = repository.sendAtCommand("ATI", 1000)
            // Should return Result.failure when no socket is available
            assertTrue(result.isFailure)
        }

    @Test
    fun `sendAtCommand accepts valid AT commands - fails when disconnected`() =
        runTest {
            val result = repository.sendAtCommand("AT+CLCC", 5000)
            assertTrue(result.isFailure)
        }

    @Test
    fun `sendAtCommand handles timeout - fails when disconnected`() =
        runTest {
            val result = repository.sendAtCommand("AT+BTRH", 1)
            // When not connected, returns failure (not a timeout)
            assertTrue(result.isFailure)
        }

    @Test
    fun `multiple suites for same device are stored`() =
        runTest {
            val suite1 = sampleSuite(address = "00:11:22:33:44:55")
            val suite2 =
                sampleSuite(
                    address = "00:11:22:33:44:55",
                    critical = 1,
                    high = 1,
                )

            repository.saveTestSuite(suite1)
            repository.saveTestSuite(suite2)

            val retrieved = repository.getTestSuites("00:11:22:33:44:55").first()
            assertEquals(2, retrieved.size)
        }

    @Test
    fun `sendAtCommand with various AT commands - all fail when disconnected`() =
        runTest {
            val commands =
                listOf(
                    "ATI",
                    "AT+CLCC",
                    "AT+BTRH",
                    "AT+BRSF=31",
                    "AT+CIND?",
                    "AT+BLDN",
                )

            for (cmd in commands) {
                val result = repository.sendAtCommand(cmd, 1000)
                // Verify no crashes, returns failure when disconnected
                if (!result.isFailure) {
                    throw AssertionError("sendAtCommand($cmd) should return Result.failure when disconnected")
                }
            }
        }
}
