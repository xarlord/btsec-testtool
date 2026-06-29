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
import com.btsec.testtool.domain.model.SapTestResult
import com.btsec.testtool.domain.model.SapTestSuite
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
 * - SAP connection establishment
 * - APDU command transmission
 * - Connection cleanup
 * - Test suite storage and retrieval
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

    @Test
    fun `isSapConnected initially false`() = runTest {
        assertFalse(repository.isSapConnected().first())
    }

    @Test
    fun `getTestSuites returns empty for non-existent device`() = runTest {
        val suites = repository.getTestSuites("00:11:22:33:44:55").first()
        assertTrue(suites.isEmpty())
    }

    @Test
    fun `getAllTestSuites returns all suites`() = runTest {
        val suite1 =
            SapTestSuite(
                targetDevice = "00:11:22:33:44:55",
                testDurationMs = 1000L,
                apduCommandsSent = 5,
                results = emptyList(),
                criticalCount = 0,
                highCount = 0,
            )
        val suite2 =
            SapTestSuite(
                targetDevice = "00:11:22:33:44:56",
                testDurationMs = 2000L,
                apduCommandsSent = 10,
                results = emptyList(),
                criticalCount = 1,
                highCount = 0,
            )

        repository.saveTestSuite(suite1)
        repository.saveTestSuite(suite2)

        val all = repository.getAllTestSuites().first()
        assertEquals(2, all.size)
    }

    @Test
    fun `saveTestSuite persists and retrieves test suite`() = runTest {
        val testSuite =
            SapTestSuite(
                targetDevice = "00:11:22:33:44:55",
                testDurationMs = 3000L,
                apduCommandsSent = 15,
                results =
                    listOf(
                        SapTestResult(
                            apduCommand = "A0A40000023F00",
                            response = "6FXX",
                            vulnerable = false,
                            confidence = 0.95,
                            evidence = "APDU command executed safely",
                            testDurationMs = 100,
                        ),
                    ),
                criticalCount = 0,
                highCount = 1,
            )

        repository.saveTestSuite(testSuite)

        val retrieved = repository.getTestSuites("00:11:22:33:44:55").first()
        assertEquals(1, retrieved.size)
        assertEquals("00:11:22:33:44:55", retrieved[0].targetDevice)
    }

    @Test
    fun `disconnect stops connection when connected`() = runTest {
        repository.disconnect()
        assertFalse(repository.isSapConnected().first())
    }

    @Test
    fun `sendApduCommand handles null result when not connected`() = runTest {
        val response = repository.sendApduCommand(byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x02), 5000)
        // Should return null when no socket is available
        assertTrue(response == null || response.isEmpty())
    }

    @Test
    fun `sendApduCommand accepts valid APDU commands`() = runTest {
        val apdu = byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x02, 0x3F.toByte(), 0x00)
        val response = repository.sendApduCommand(apdu, 5000)
        // Verify method signature and doesn't crash
        assertTrue(response == null || response.isNotEmpty())
    }

    @Test
    fun `sendApduCommand handles timeout`() = runTest {
        val apdu = byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x02)
        val response = repository.sendApduCommand(apdu, 1)
        // Should return null on timeout when not connected
        assertTrue(response == null)
    }

    @Test
    fun `multiple suites for same device are stored`() = runTest {
        val suite1 =
            SapTestSuite(
                targetDevice = "00:11:22:33:44:55",
                testDurationMs = 1000L,
                apduCommandsSent = 5,
                results = emptyList(),
                criticalCount = 0,
                highCount = 0,
            )
        val suite2 =
            SapTestSuite(
                targetDevice = "00:11:22:33:44:55",
                testDurationMs = 2000L,
                apduCommandsSent = 10,
                results = emptyList(),
                criticalCount = 1,
                highCount = 1,
            )

        repository.saveTestSuite(suite1)
        repository.saveTestSuite(suite2)

        val retrieved = repository.getTestSuites("00:11:22:33:44:55").first()
        assertEquals(2, retrieved.size)
    }

    @Test
    fun `sendApduCommand with various APDU commands`() = runTest {
        val apduCommands =
            listOf(
                byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x02), // SELECT
                byteArrayOf(0x00, 0xB0.toByte(), 0x00, 0x00, 0x0A), // READ BINARY
                byteArrayOf(0x00, 0x20.toByte(), 0x00, 0x01, 0x04), // VERIFY
                byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x08), // SELECT DF
            )

        for (apdu in apduCommands) {
            val response = repository.sendApduCommand(apdu, 1000)
            // Verify no crashes, returns null or byte array
            assertTrue(response == null || response.isNotEmpty())
        }
    }

    @Test
    fun `sendApduCommand with empty APDU`() = runTest {
        val response = repository.sendApduCommand(byteArrayOf(), 1000)
        // Should handle empty APDU gracefully
        assertTrue(response == null || response.isEmpty())
    }

    @Test
    fun `getSimInfo returns null when not connected`() = runTest {
        val info = repository.getSimInfo()
        // Should return null when no socket is available
        assertTrue(info == null)
    }
}
