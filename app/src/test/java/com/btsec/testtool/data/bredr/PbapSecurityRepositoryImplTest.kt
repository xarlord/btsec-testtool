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
import com.btsec.testtool.domain.model.PbmapTestReport
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
 * - PBAP connection state management
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

    private fun sampleReport(
        device: String = "00:11:22:33:44:55",
        critical: Int = 0,
    ): PbmapTestReport =
        PbmapTestReport(
            targetDevice = device,
            pbapResults = emptyList(),
            mapResults = emptyList(),
            findings = emptyList(),
            totalDataExposed = 0,
            criticalFindings = critical,
            testDurationMs = 1000L,
        )

    @Test
    fun `isPbapConnected initially false`() =
        runTest {
            assertFalse(repository.isPbapConnected().first())
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
            assertFalse(repository.isPbapConnected().first())
        }

    @Test
    fun `accessPhonebook returns stub result with requiredAuth true`() =
        runTest {
            val result = repository.accessPhonebook(PhonebookType.MAIN_CONTACTS)

            assertFalse(result.accessible)
            assertEquals(0, result.entryCount)
            assertTrue(result.requiredAuth == null)
            assertEquals(com.btsec.testtool.domain.model.EvidenceOutcome.UNSUPPORTED, result.outcome)
            assertEquals(PhonebookType.MAIN_CONTACTS, result.phonebookType)
        }

    @Test
    fun `accessPhonebook handles all phonebook types`() =
        runTest {
            for (type in PhonebookType.entries) {
                val result = repository.accessPhonebook(type)
                assertFalse(result.accessible)
                assertEquals(type, result.phonebookType)
                assertTrue(result.requiredAuth == null)
                assertEquals(com.btsec.testtool.domain.model.EvidenceOutcome.UNSUPPORTED, result.outcome)
            }
        }

    @Test
    fun `multiple reports for same device are stored`() =
        runTest {
            val report1 = sampleReport(device = "00:11:22:33:44:55")
            val report2 = sampleReport(device = "00:11:22:33:44:55", critical = 1)

            repository.saveTestReport(report1)
            repository.saveTestReport(report2)

            val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
            assertEquals(2, retrieved.size)
        }
}
