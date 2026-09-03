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
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import com.btsec.testtool.domain.model.L2capFixedChannel
import com.btsec.testtool.domain.model.L2capSeverity
import com.btsec.testtool.domain.model.L2capTestCategory
import com.btsec.testtool.domain.model.L2capTestReport
import com.btsec.testtool.domain.model.L2capTestResult
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
import org.junit.jupiter.api.assertThrows
import java.util.UUID

/**
 * Unit tests for [L2capSecurityRepositoryImpl].
 *
 * These tests verify:
 * - Fixed channel enumeration
 * - Signaling command transmission
 * - Information queries
 * - Test report storage and retrieval
 * - Connection state management
 */
@DisplayName("L2capSecurityRepositoryImpl")
class L2capSecurityRepositoryImplTest {
    private lateinit var context: Context
    private lateinit var bluetoothManager: BluetoothManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var repository: L2capSecurityRepositoryImpl

    @BeforeEach
    fun setup() {
        context = mockk(relaxed = true)
        bluetoothManager = mockk(relaxed = true)
        bluetoothAdapter = mockk(relaxed = true)

        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns bluetoothManager
        every { bluetoothManager.adapter } returns bluetoothAdapter

        repository = L2capSecurityRepositoryImpl(context)
    }

    /**
     * Build a mock [android.os.ParcelUuid] that returns the given UUID string.
     * In plain JVM tests, ParcelUuid.fromString() returns null, so we mock it.
     */
    private fun parcelUuid(uuidStr: String): android.os.ParcelUuid =
        mockk {
            every { uuid } returns UUID.fromString(uuidStr)
        }

    @Test
    fun `enumerateFixedChannels returns empty for null device`() =
        runTest {
            every { bluetoothAdapter.getRemoteDevice(any<String>()) } returns null

            val channels = repository.enumerateFixedChannels("00:11:22:33:44:55")
            assertTrue(channels.isEmpty())
        }

    @Test
    fun `enumerateFixedChannels returns ATT and SMP for BLE`() =
        runTest {
            val mockDevice = mockk<BluetoothDevice>(relaxed = true)
            every { bluetoothAdapter.getRemoteDevice(any<String>()) } returns mockDevice
            every { mockDevice.uuids } returns emptyArray()

            val channels = repository.enumerateFixedChannels("00:11:22:33:44:55")

            assertTrue(channels.any { it.cid == 0x0004 }, "Should include ATT (CID 0x0004)")
            assertTrue(channels.any { it.cid == 0x0006 }, "Should include SMP (CID 0x0006)")
        }

    @Test
    fun `enumerateFixedChannels includes signaling for BR-EDR devices`() =
        runTest {
            val mockDevice = mockk<BluetoothDevice>(relaxed = true)
            val uuids =
                arrayOf(
                    parcelUuid("00001101-0000-1000-8000-00805F9B34FB"),
                )

            every { bluetoothAdapter.getRemoteDevice(any<String>()) } returns mockDevice
            every { mockDevice.uuids } returns uuids

            val channels = repository.enumerateFixedChannels("00:11:22:33:44:55")

            assertTrue(channels.any { it.cid == 0x0001 }, "Should include Signaling (CID 0x0001)")
        }

    @Test
    fun `sendSignalingCommand returns null when no L2CAP socket available`() =
        runTest {
            val result =
                repository.sendSignalingCommand(
                    deviceAddress = "00:11:22:33:44:55",
                    channelId = 1,
                    payload = byteArrayOf(0x01, 0x02, 0x03),
                    timeoutMs = 1000L,
                )

            // No BluetoothSocket in JVM tests — returns null when socket cannot be established
            assertEquals(null, result)
        }

    @Test
    fun `sendSignalingCommand builds little-endian signaling packet`() =
        runTest {
            val command = com.btsec.testtool.domain.model.L2capSignalCommand.INFORMATION_REQUEST
            val payload = ByteArray(0x0102)
            val packet =
                repository.buildL2capSignalingPacket(
                    channelId = 0x1234,
                    command = command,
                    identifier = 0x01,
                    data = payload,
                )

            // L2CAP header: length(2 LE) + CID(2 LE) = 4 bytes
            // Signaling header: code(1) + identifier(1) + length(2 LE) = 4 bytes
            assertEquals(4 + 4 + payload.size, packet.size)

            // L2CAP payload length is 0x0106; CID is 0x1234.
            assertEquals(0x06, packet[0].toInt() and 0xFF, "Length low byte")
            assertEquals(0x01, packet[1].toInt() and 0xFF, "Length high byte")
            assertEquals(0x34, packet[2].toInt() and 0xFF, "CID low byte")
            assertEquals(0x12, packet[3].toInt() and 0xFF, "CID high byte")

            assertEquals(0x0A, packet[4].toInt() and 0xFF, "Code should be INFORMATION_REQUEST (0x0A)")
            assertEquals(0x01, packet[5].toInt() and 0xFF, "Identifier")
            assertEquals(0x02, packet[6].toInt() and 0xFF, "Sig length low byte")
            assertEquals(0x01, packet[7].toInt() and 0xFF, "Sig length high byte")
        }

    @Test
    fun `buildInformationRequestPayload uses little-endian info type`() =
        runTest {
            val payload = repository.buildInformationRequestPayload(0x1234)
            assertEquals(2, payload.size)
            assertEquals(0x34, payload[0].toInt() and 0xFF)
            assertEquals(0x12, payload[1].toInt() and 0xFF)
        }

    @Test
    fun `buildL2capSignalingPacket accepts maximum encodable data length`() {
        val packet =
            repository.buildL2capSignalingPacket(
                channelId = 0x0001,
                command = com.btsec.testtool.domain.model.L2capSignalCommand.ECHO_REQUEST,
                identifier = 0xFF,
                data = ByteArray(0xFFFB),
            )

        assertEquals(0xFF, packet[0].toInt() and 0xFF)
        assertEquals(0xFF, packet[1].toInt() and 0xFF)
        assertEquals(0xFB, packet[6].toInt() and 0xFF)
        assertEquals(0xFF, packet[7].toInt() and 0xFF)
    }

    @Test
    fun `buildL2capSignalingPacket rejects overflowing data length`() {
        assertThrows<IllegalArgumentException> {
            repository.buildL2capSignalingPacket(
                channelId = 0x0001,
                command = com.btsec.testtool.domain.model.L2capSignalCommand.ECHO_REQUEST,
                identifier = 0x01,
                data = ByteArray(0xFFFC),
            )
        }
    }

    @Test
    fun `buildL2capSignalingPacket rejects out-of-range fields`() {
        assertThrows<IllegalArgumentException> {
            repository.buildL2capSignalingPacket(-1, null, 1, byteArrayOf())
        }
        assertThrows<IllegalArgumentException> {
            repository.buildL2capSignalingPacket(0x10000, null, 1, byteArrayOf())
        }
        assertThrows<IllegalArgumentException> {
            repository.buildL2capSignalingPacket(1, null, 0, byteArrayOf())
        }
        assertThrows<IllegalArgumentException> {
            repository.buildL2capSignalingPacket(1, null, 0x100, byteArrayOf())
        }
    }

    @Test
    fun `buildInformationRequestPayload rejects out-of-range info type`() {
        assertThrows<IllegalArgumentException> {
            repository.buildInformationRequestPayload(-1)
        }
        assertThrows<IllegalArgumentException> {
            repository.buildInformationRequestPayload(0x10000)
        }
    }

    @Test
    fun `nextIdentifier wraps from 255 to 1 without emitting zero`() {
        repeat(255) {
            assertTrue(repository.nextIdentifier() in 1..0xFF)
        }

        assertEquals(1, repository.nextIdentifier())
    }

    @Test
    fun `queryInformation returns null when no L2CAP socket available`() =
        runTest {
            val result =
                repository.queryInformation(
                    deviceAddress = "00:11:22:33:44:55",
                    infoType = 1,
                )

            // No BluetoothSocket in JVM tests — returns null
            assertEquals(null, result)
        }

    @Test
    fun `isL2capConnected initially false`() =
        runTest {
            assertFalse(repository.isL2capConnected().first())
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
            val testReport =
                L2capTestReport(
                    targetDevice = "00:11:22:33:44:55",
                    testDurationMs = 5000L,
                    discoveredChannels =
                        listOf(
                            L2capFixedChannel.SIGNALING,
                            L2capFixedChannel.ATT,
                        ),
                    supportedFeatures = listOf("Extended Flow Control", "Streaming Mode"),
                    results =
                        listOf(
                            L2capTestResult(
                                category = L2capTestCategory.INFORMATION_QUERY,
                                testName = "MTU Query",
                                signalCommand = null,
                                requestPayload = "01",
                                responsePayload = "00",
                                vulnerable = false,
                                confidence = 0.9,
                                evidence = "Proper response received",
                                severity = L2capSeverity.INFO,
                                recommendation = "No action required",
                            ),
                        ),
                    criticalCount = 0,
                    highCount = 0,
                )

            repository.saveTestReport(testReport)

            val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
            assertEquals(1, retrieved.size)
            assertEquals("00:11:22:33:44:55", retrieved[0].targetDevice)
            assertEquals(5000L, retrieved[0].testDurationMs)
            assertEquals(1, retrieved[0].results.size)
        }

    @Test
    fun `saveTestReport appends multiple reports for same device`() =
        runTest {
            val report1 =
                L2capTestReport(
                    targetDevice = "00:11:22:33:44:55",
                    testDurationMs = 1000L,
                    discoveredChannels = emptyList(),
                    supportedFeatures = emptyList(),
                    results = emptyList(),
                    criticalCount = 0,
                    highCount = 0,
                )

            val report2 =
                L2capTestReport(
                    targetDevice = "00:11:22:33:44:55",
                    testDurationMs = 2000L,
                    discoveredChannels = emptyList(),
                    supportedFeatures = emptyList(),
                    results = emptyList(),
                    criticalCount = 0,
                    highCount = 0,
                )

            repository.saveTestReport(report1)
            repository.saveTestReport(report2)

            val retrieved = repository.getTestReports("00:11:22:33:44:55").first()
            assertEquals(2, retrieved.size)
            assertEquals(1000L, retrieved[0].testDurationMs)
            assertEquals(2000L, retrieved[1].testDurationMs)
        }

    @Test
    fun `getTestReports returns reports for specific device only`() =
        runTest {
            val report1 =
                L2capTestReport(
                    targetDevice = "00:11:22:33:44:55",
                    testDurationMs = 1000L,
                    discoveredChannels = emptyList(),
                    supportedFeatures = emptyList(),
                    results = emptyList(),
                    criticalCount = 0,
                    highCount = 0,
                )

            val report2 =
                L2capTestReport(
                    targetDevice = "00:11:22:33:44:66",
                    testDurationMs = 2000L,
                    discoveredChannels = emptyList(),
                    supportedFeatures = emptyList(),
                    results = emptyList(),
                    criticalCount = 0,
                    highCount = 0,
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
    fun `enumerateFixedChannels removes duplicate channels`() =
        runTest {
            val mockDevice = mockk<BluetoothDevice>(relaxed = true)
            every { bluetoothAdapter.getRemoteDevice(any<String>()) } returns mockDevice
            every { mockDevice.uuids } returns emptyArray()

            val channels = repository.enumerateFixedChannels("00:11:22:33:44:55")

            val uniqueCids = channels.map { it.cid }.toSet()
            assertEquals(channels.size, uniqueCids.size, "No duplicate CIDs should exist")
        }
}
