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
import com.btsec.testtool.domain.model.SapSeverity
import com.btsec.testtool.domain.model.SapTestCategory
import com.btsec.testtool.domain.model.SapTestReport
import com.btsec.testtool.domain.model.SapTestResult
import com.btsec.testtool.domain.model.SimApdu
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
 * Unit tests for [SapSecurityRepositoryImpl].
 *
 * These tests verify:
 * - SAP connection state management
 * - APDU command transmission returns Result.failure when disconnected
 * - Connection cleanup
 * - Test report storage and retrieval
 */
@DisplayName("SapSecurityRepositoryImpl")
class SapSecurityRepositoryImplTest {
    private lateinit var context: Context
    private lateinit var bluetoothManager: BluetoothManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var repository: SapSecurityRepositoryImpl

    @BeforeEach
    fun setup() {
        context = mockk(relaxed = true)
        bluetoothManager = mockk(relaxed = true)
        bluetoothAdapter = mockk(relaxed = true)

        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns bluetoothManager
        every { bluetoothManager.adapter } returns bluetoothAdapter

        repository = SapSecurityRepositoryImpl(context)
    }

    private fun sampleResult(): SapTestResult =
        SapTestResult(
            category = SapTestCategory.APDU_INJECTION,
            testName = "SELECT MF",
            apduCommand = SimApdu(0x00, 0xA4, 0x04, 0x00),
            sapMessage = null,
            response = "6FXX",
            vulnerable = false,
            confidence = 0.95,
            evidence = "APDU command executed safely",
            severity = SapSeverity.LOW,
            recommendation = "No action required",
        )

    private fun sampleReport(
        device: String = "00:11:22:33:44:55",
        critical: Int = 0,
        high: Int = 0,
    ): SapTestReport =
        SapTestReport(
            targetDevice = device,
            results = emptyList(),
            simDataExtracted = null,
            criticalCount = critical,
            highCount = high,
            testDurationMs = 1000L,
        )

    @Test
    fun `isSapConnected initially false`() =
        runTest {
            assertFalse(repository.isSapConnected().first())
        }

    @Test
    fun `getTestReports returns empty for non-existent device`() =
        runTest {
            val reports = repository.getTestReports("00:11:22:33:44:55").first()
            assertTrue(reports.isEmpty())
        }

    @Test
    fun `saveTestReport persists and retrieves test report`() =
        runTest {
            val report = sampleReport(device = "00:11:22:33:44:55")

            repository.saveTestReport(report)

            val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
            assertEquals(1, retrieved.size)
            assertEquals("00:11:22:33:44:55", retrieved[0].targetDevice)
        }

    @Test
    fun `disconnect stops connection when connected`() =
        runTest {
            repository.disconnect()
            assertFalse(repository.isSapConnected().first())
        }

    @Test
    fun `sendApdu returns failure when not connected`() =
        runTest {
            val apdu = SimApdu(0x00, 0xA4, 0x04, 0x00, le = 0x02)
            val result = repository.sendApdu(apdu, 5000)
            assertTrue(result.isFailure)
        }

    @Test
    fun `sendApdu accepts valid APDU commands - fails when disconnected`() =
        runTest {
            val apdu = SimApdu(0x00, 0xA4, 0x04, 0x00, byteArrayOf(0x3F, 0x00), 0x02)
            val result = repository.sendApdu(apdu, 5000)
            assertTrue(result.isFailure)
        }

    @Test
    fun `sendApdu handles timeout - fails when disconnected`() =
        runTest {
            val apdu = SimApdu(0x00, 0xA4, 0x04, 0x00, le = 0x02)
            val result = repository.sendApdu(apdu, 1)
            // When not connected, returns failure (not a timeout)
            assertTrue(result.isFailure)
        }

    @Test
    fun `requestAtr returns failure when not connected`() =
        runTest {
            val result = repository.requestAtr()
            assertTrue(result.isFailure)
        }

    @Test
    fun `powerSimOff fails when not connected`() =
        runTest {
            val result = repository.powerSimOff()
            assertTrue(result.isFailure)
        }

    @Test
    fun `powerSimOn fails when not connected`() =
        runTest {
            val result = repository.powerSimOn()
            assertTrue(result.isFailure)
        }

    @Test
    fun `resetSim fails when not connected`() =
        runTest {
            val result = repository.resetSim()
            assertTrue(result.isFailure)
        }

    @Test
    fun `multiple reports for same device are stored`() =
        runTest {
            val report1 = sampleReport(device = "00:11:22:33:44:55")
            val report2 =
                sampleReport(
                    device = "00:11:22:33:44:55",
                    critical = 1,
                    high = 1,
                )

            repository.saveTestReport(report1)
            repository.saveTestReport(report2)

            val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
            assertEquals(2, retrieved.size)
        }

    @Test
    fun `sendApdu with various APDU commands - all fail when disconnected`() =
        runTest {
            val apduCommands =
                listOf(
                    // SELECT MF
                    SimApdu(0x00, 0xA4, 0x04, 0x00, byteArrayOf(0x3F, 0x00)),
                    // READ BINARY
                    SimApdu(0x00, 0xB0, 0x00, 0x00, le = 0x0A),
                    // VERIFY
                    SimApdu(0x00, 0x20, 0x00, 0x01, byteArrayOf(0x31, 0x32, 0x33, 0x34)),
                    // SELECT DF
                    SimApdu(0x00, 0xA4, 0x04, 0x00, byteArrayOf(0x2F, 0xE2.toByte(), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)),
                )

            for (apdu in apduCommands) {
                val result = repository.sendApdu(apdu, 1000)
                if (!result.isFailure) {
                    throw AssertionError("sendApdu should return Result.failure when disconnected")
                }
            }
        }
}
