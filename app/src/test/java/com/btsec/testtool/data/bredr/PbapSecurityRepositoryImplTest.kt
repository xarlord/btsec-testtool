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
import com.btsec.testtool.domain.model.PbapAccessResult
import com.btsec.testtool.domain.model.PhonebookType
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
 * Unit tests for [PbapSecurityRepositoryImpl].
 *
 * These tests verify:
 * - PBAP connection establishment
 * - Phonebook access (stub behavior with OBEX framing note)
 * - Connection cleanup
 * - Test report storage and retrieval
 */
@DisplayName("PbapSecurityRepositoryImpl")
class PbapSecurityRepositoryImplTest {
    private lateinit var context: Context
    private lateinit var bluetoothManager: BluetoothManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var repository: PbapSecurityRepositoryImpl

    @BeforeEach
    fun setup() {
        context = mockk(relaxed = true)
        bluetoothManager = mockk(relaxed = true)
        bluetoothAdapter = mockk(relaxed = true)

        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns bluetoothManager
        every { bluetoothManager.adapter } returns bluetoothAdapter

        repository = PbapSecurityRepositoryImpl(context)
    }

    @Test
    fun `isPbapConnected initially false`() = runTest {
        assertFalse(repository.isPbapConnected().first())
    }

    @Test
    fun `getTestReports returns empty for non-existent device`() = runTest {
        val reports = repository.getTestReports("00:11:22:33:44:55").first()
        assertTrue(reports.isEmpty())
    }

    @Test
    fun `saveTestReport persists and retrieves test report`() = runTest {
        val testReport =
            com.btsec.testtool.domain.model.PbmapTestReport(
                targetDevice = "00:11:22:33:44:55",
                testDurationMs = 3000L,
                entriesAccessed = 10,
                results =
                    listOf(
                        PbapAccessResult(
                            phonebookType = PhonebookType.MAIN,
                            accessible = false,
                            entryCount = 0,
                            entries = emptyList(),
                            requiredAuth = true,
                            testDurationMs = 500,
                        ),
                    ),
                criticalCount = 0,
                highCount = 1,
            )

        repository.saveTestReport(testReport)

        val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
        assertEquals(1, retrieved.size)
        assertEquals("00:11:22:33:44:55", retrieved[0].targetDevice)
    }

    @Test
    fun `disconnect stops connection when connected`() = runTest {
        repository.disconnect()
        assertFalse(repository.isPbapConnected().first())
    }

    @Test
    fun `accessPhonebook returns stub result with requiredAuth true`() = runTest {
        val result = repository.accessPhonebook(PhonebookType.MAIN)

        assertFalse(result.accessible)
        assertEquals(0, result.entryCount)
        assertTrue(result.requiredAuth)
        assertEquals(PhonebookType.MAIN, result.phonebookType)
    }

    @Test
    fun `accessPhonebook handles all phonebook types`() = runTest {
        val types =
            listOf(
                PhonebookType.MAIN,
                PhonebookType.SIM,
                PhonebookType.FAVORITES,
                PhonebookType.RECEIVED,
                PhonebookType.DIALED,
                PhonebookType.MISSED,
            )

        for (type in types) {
            val result = repository.accessPhonebook(type)
            assertFalse(result.accessible)
            assertEquals(type, result.phonebookType)
            assertTrue(result.requiredAuth)
        }
    }

    @Test
    fun `multiple reports for same device are stored`() = runTest {
        val report1 =
            com.btsec.testtool.domain.model.PbmapTestReport(
                targetDevice = "00:11:22:33:44:55",
                testDurationMs = 1000L,
                entriesAccessed = 5,
                results = emptyList(),
                criticalCount = 0,
                highCount = 0,
            )
        val report2 =
            com.btsec.testtool.domain.model.PbmapTestReport(
                targetDevice = "00:11:22:33:44:55",
                testDurationMs = 2000L,
                entriesAccessed = 15,
                results = emptyList(),
                criticalCount = 1,
                highCount = 1,
            )

        repository.saveTestReport(report1)
        repository.saveTestReport(report2)

        val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
        assertEquals(2, retrieved.size)
    }
}
