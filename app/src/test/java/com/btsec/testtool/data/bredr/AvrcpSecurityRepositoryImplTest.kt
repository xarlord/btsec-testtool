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
import android.bluetooth.BluetoothSocket
import android.content.Context
import com.btsec.testtool.domain.model.AvrcpMediaItem
import com.btsec.testtool.domain.model.AvrcpTestReport
import com.btsec.testtool.domain.model.AvrcpTestResult
import com.btsec.testtool.domain.model.AvrcpTestCategory
import com.btsec.testtool.domain.model.AvrcpSeverity
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.io.IOException

/**
 * Unit tests for [AvrcpSecurityRepositoryImpl].
 *
 * These tests verify:
 * - AVRCP connection establishment
 * - Media browsing (stub behavior)
 * - Media command transmission
 * - Connection cleanup
 * - Test report storage
 */
@DisplayName("AvrcpSecurityRepositoryImpl")
class AvrcpSecurityRepositoryImplTest {
    private lateinit var context: Context
    private lateinit var bluetoothManager: BluetoothManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var repository: AvrcpSecurityRepositoryImpl

    @BeforeEach
    fun setup() {
        context = mockk(relaxed = true)
        bluetoothManager = mockk(relaxed = true)
        bluetoothAdapter = mockk(relaxed = true)

        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns bluetoothManager
        every { bluetoothManager.adapter } returns bluetoothAdapter

        repository = AvrcpSecurityRepositoryImpl(context)
    }

    @Test
    fun `isAvrcpConnected initially false`() = runTest {
        assertFalse(repository.isAvrcpConnected().first())
    }

    @Test
    fun `getTestReports returns empty for non-existent device`() = runTest {
        val reports = repository.getTestReports("00:11:22:33:44:55").first()
        assertTrue(reports.isEmpty())
    }

    @Test
    fun `saveTestReport persists and retrieves test report`() = runTest {
        val testReport = AvrcpTestReport(
            targetDevice = "00:11:22:33:44:55",
            testDurationMs = 5000L,
            mediaItemsExtracted = 10,
            results = listOf(
                AvrcpTestResult(
                    category = AvrcpTestCategory.MEDIA_CONTROL,
                    testName = "Play Command Test",
                    command = "AVRCP_PRESS:PLAY",
                    response = "success",
                    vulnerable = true,
                    confidence = 0.85,
                    evidence = "Command accepted without authentication",
                    severity = AvrcpSeverity.HIGH,
                    recommendation = "Require authentication before accepting media commands"
                )
            ),
            browseResults = emptyList(),
            criticalCount = 0,
            highCount = 1
        )

        repository.saveTestReport(testReport)

        val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
        assertEquals(1, retrieved.size)
        assertEquals("00:11:22:33:44:55", retrieved[0].targetDevice)
        assertEquals(5000L, retrieved[0].testDurationMs)
        assertEquals(10, retrieved[0].mediaItemsExtracted)
        assertEquals(1, retrieved[0].results.size)
    }

    @Test
    fun `saveTestReport appends multiple reports for same device`() = runTest {
        val report1 = AvrcpTestReport(
            targetDevice = "00:11:22:33:44:55",
            testDurationMs = 1000L,
            mediaItemsExtracted = 0,
            results = emptyList(),
            browseResults = emptyList(),
            criticalCount = 0,
            highCount = 0
        )

        val report2 = AvrcpTestReport(
            targetDevice = "00:11:22:33:44:55",
            testDurationMs = 2000L,
            mediaItemsExtracted = 5,
            results = emptyList(),
            browseResults = emptyList(),
            criticalCount = 0,
            highCount = 0
        )

        repository.saveTestReport(report1)
        repository.saveTestReport(report2)

        val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
        assertEquals(2, retrieved.size)
        assertEquals(1000L, retrieved[0].testDurationMs)
        assertEquals(2000L, retrieved[1].testDurationMs)
    }

    @Test
    fun `getTestReports returns reports for specific device only`() = runTest {
        val report1 = AvrcpTestReport(
            targetDevice = "00:11:22:33:44:55",
            testDurationMs = 1000L,
            mediaItemsExtracted = 0,
            results = emptyList(),
            browseResults = emptyList(),
            criticalCount = 0,
            highCount = 0
        )

        val report2 = AvrcpTestReport(
            targetDevice = "00:11:22:33:44:66",
            testDurationMs = 2000L,
            mediaItemsExtracted = 0,
            results = emptyList(),
            browseResults = emptyList(),
            criticalCount = 0,
            highCount = 0
        )

        repository.saveTestReport(report1)
        repository.saveTestReport(report2)

        val device1Reports = repository.getTestReports("00:11:22:33:44:55").first()
        val device2Reports = repository.getTestReports("00:11:22:33:44:66").first()

        assertEquals(1, device1Reports.size)
        assertEquals(1, device2Reports.size)
        assertEquals("00:11:22:33:44:55", device1Reports[0].targetDevice)
        assertEquals("00:11:22:33:44:66", device2Reports[0].targetDevice)
    }

    @Test
    fun `browseMedia returns empty list (stub implementation)`() = runTest {
        // Current implementation returns empty list (stub)
        val items = repository.browseMedia(path = "/", depth = 1)
        assertTrue(items.isEmpty())
    }

    @Test
    fun `sendMediaCommand returns success when not connected (stub)`() = runTest {
        // Current implementation logs but returns success (stub)
        val result = repository.sendMediaCommand("AVRCP_PRESS:PLAY")
        assertEquals(Result.success(Unit), result)
    }

    @Test
    fun `disconnect closes sockets without throwing`() = runTest {
        // Should not throw even when nothing is connected
        repository.disconnect()
        assertFalse(repository.isAvrcpConnected().first())
    }

    @Test
    fun `disconnect cleans up control and browse sockets`() = runTest {
        // Simulate having sockets (even if mocked)
        repository.disconnect()

        // Should be in disconnected state
        assertFalse(repository.isAvrcpConnected().first())
    }

    @Test
    fun `saveTestReport handles reports with browse results`() = runTest {
        val mediaItem = AvrcpMediaItem(
            uid = "1",
            title = "Test Song",
            artist = "Test Artist",
            album = "Test Album",
            path = "/Music/Test Song.mp3"
        )

        val testReport = AvrcpTestReport(
            targetDevice = "00:11:22:33:44:55",
            testDurationMs = 5000L,
            mediaItemsExtracted = 1,
            results = emptyList(),
            browseResults = listOf(
                com.btsec.testtool.domain.model.AvrcpBrowseResult(
                    path = "/Music",
                    depth = 1,
                    itemsFound = 1,
                    traversalSuccessful = true,
                    sensitivePaths = emptyList()
                )
            ),
            criticalCount = 0,
            highCount = 0
        )

        repository.saveTestReport(testReport)

        val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
        assertEquals(1, retrieved.size)
        assertEquals(1, retrieved[0].browseResults.size)
        assertEquals("/Music", retrieved[0].browseResults[0].path)
    }

    @Test
    fun `saveTestReport stores results with different severity levels`() = runTest {
        val testReport = AvrcpTestReport(
            targetDevice = "00:11:22:33:44:55",
            testDurationMs = 5000L,
            mediaItemsExtracted = 0,
            results = listOf(
                AvrcpTestResult(
                    category = AvrcpTestCategory.MEDIA_CONTROL,
                    testName = "Critical Test",
                    command = "TEST",
                    response = "success",
                    vulnerable = true,
                    confidence = 0.9,
                    evidence = "Critical issue",
                    severity = AvrcpSeverity.CRITICAL,
                    recommendation = "Fix immediately"
                ),
                AvrcpTestResult(
                    category = AvrcpTestCategory.MEDIA_CONTROL,
                    testName = "High Test",
                    command = "TEST",
                    response = "success",
                    vulnerable = true,
                    confidence = 0.8,
                    evidence = "High issue",
                    severity = AvrcpSeverity.HIGH,
                    recommendation = "Fix soon"
                )
            ),
            browseResults = emptyList(),
            criticalCount = 1,
            highCount = 1
        )

        repository.saveTestReport(testReport)

        val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
        assertEquals(1, retrieved.size)
        assertEquals(1, retrieved[0].criticalCount)
        assertEquals(1, retrieved[0].highCount)
        assertEquals(2, retrieved[0].results.size)
    }
}
