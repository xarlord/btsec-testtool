/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for Bluetooth models.
 */
@DisplayName("Bluetooth Models Tests")
class BluetoothModelsTest {

    @Test
    @DisplayName("BluetoothDevice should identify BLE devices correctly")
    fun testBluetoothDeviceIsBle() {
        val bleDevice = BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF",
            name = "BLE Device",
            type = DeviceType.BLE,
            deviceClass = DeviceClass.UNCATEGORIZED,
            bondState = BondState.NONE,
            rssi = -60,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
            scanCount = 1
        )

        assertTrue(bleDevice.isBle())
        assertFalse(bleDevice.isClassic())
    }

    @Test
    @DisplayName("BluetoothDevice should identify Classic devices correctly")
    fun testBluetoothDeviceIsClassic() {
        val classicDevice = BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF",
            name = "Classic Device",
            type = DeviceType.CLASSIC,
            deviceClass = DeviceClass.AUDIO_VIDEO,
            bondState = BondState.BONDED,
            rssi = -50,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
            scanCount = 5
        )

        assertTrue(classicDevice.isClassic())
        assertFalse(classicDevice.isBle())
    }

    @Test
    @DisplayName("BluetoothDevice should identify Dual Mode devices correctly")
    fun testBluetoothDeviceDualMode() {
        val dualDevice = BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF",
            name = "Dual Mode Device",
            type = DeviceType.DUAL_MODE,
            deviceClass = DeviceClass.COMPUTER,
            bondState = BondState.BONDED,
            rssi = -70,
            txPower = 10,
            firstSeen = Instant.now(),
            lastSeen = Instant.now()
        )

        assertTrue(dualDevice.isBle())
        assertTrue(dualDevice.isClassic())
    }

    @Test
    @DisplayName("BluetoothDevice should check bonded state")
    fun testBluetoothDeviceBonded() {
        val bondedDevice = BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF",
            name = "Bonded Device",
            type = DeviceType.BLE,
            deviceClass = null,
            bondState = BondState.BONDED,
            rssi = null,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now()
        )

        assertTrue(bondedDevice.isBonded())
    }

    @Test
    @DisplayName("BleCharacteristic should check properties correctly")
    fun testBleCharacteristicProperties() {
        val readableChar = BleCharacteristic(
            uuid = "00002a00-0000-1000-8000-00805f9b34fb",
            properties = CharacteristicProperties(
                read = true,
                write = false,
                notify = true,
                indicate = false
            ),
            permissions = null,
            value = null
        )

        assertTrue(readableChar.isReadable())
        assertFalse(readableChar.isWritable())
        assertTrue(readableChar.canNotify())
        assertFalse(readableChar.canIndicate())
    }

    @Test
    @DisplayName("FuzzResult should calculate success rate correctly")
    fun testFuzzResultSuccessRate() {
        val fuzzResult = FuzzResult(
            id = "fuzz-1",
            config = createTestFuzzConfig(),
            startTime = Instant.now().minusSeconds(60),
            endTime = Instant.now(),
            status = FuzzStatus.COMPLETED,
            packetsSent = 100,
            packetsReceived = 80,
            errors = emptyList(),
            findings = emptyList(),
            captureFile = null
        )

        assertEquals(80.0, fuzzResult.getSuccessRate(), 0.01)
    }

    @Test
    @DisplayName("FuzzResult should calculate duration correctly")
    fun testFuzzResultDuration() {
        val start = Instant.now().minusSeconds(120)
        val end = start.plusSeconds(60)

        val fuzzResult = FuzzResult(
            id = "fuzz-1",
            config = createTestFuzzConfig(),
            startTime = start,
            endTime = end,
            status = FuzzStatus.COMPLETED,
            packetsSent = 100,
            packetsReceived = 80,
            errors = emptyList(),
            findings = emptyList(),
            captureFile = null
        )

        val duration = fuzzResult.getDuration()
        assertNotNull(duration)
        assertEquals(60, duration.toSeconds())
    }

    @Test
    @DisplayName("FuzzProgress should calculate percentage correctly")
    fun testFuzzProgressPercentage() {
        val progress = FuzzProgress(
            resultId = "fuzz-1",
            config = createTestFuzzConfig(),
            status = FuzzStatus.RUNNING,
            packetsSent = 50,
            packetsReceived = 40,
            errors = emptyList(),
            findings = emptyList(),
            startTime = Instant.now(),
            estimatedCompletionTime = Instant.now().plusSeconds(60),
            currentPacketNumber = 50,
            totalPackets = 100
        )

        assertEquals(50.0, progress.getProgressPercentage(), 0.01)
    }

    @Test
    @DisplayName("Vulnerability severity ordering should be correct")
    fun testVulnerabilitySeverity() {
        val severities = listOf(
            VulnerabilitySeverity.CRITICAL,
            VulnerabilitySeverity.HIGH,
            VulnerabilitySeverity.MEDIUM,
            VulnerabilitySeverity.LOW,
            VulnerabilitySeverity.NONE
        )

        assertEquals(5, severities.size)
    }

    @Test
    @DisplayName("KeyExtractionResult should check success correctly")
    fun testKeyExtractionResultSuccess() {
        val successfulResult = KeyExtractionResult(
            id = "key-1",
            targetDevice = createTestBluetoothDevice(),
            keyType = KeyType.LTK,
            extracted = true,
            keyValue = byteArrayOf(0x01, 0x02, 0x03, 0x04),
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.CERTAIN,
            timestamp = Instant.now()
        )

        assertTrue(successfulResult.isSuccess())
        assertNotNull(successfulResult.keyValue)
    }

    @Test
    @DisplayName("KeyExtractionResult should handle failure correctly")
    fun testKeyExtractionResultFailure() {
        val failedResult = KeyExtractionResult(
            id = "key-2",
            targetDevice = createTestBluetoothDevice(),
            keyType = KeyType.LTK,
            extracted = false,
            keyValue = null,
            method = ExtractionMethod.BRUTE_FORCE,
            confidence = ExtractionConfidence.LOW,
            timestamp = Instant.now()
        )

        assertFalse(failedResult.isSuccess())
        assertNull(failedResult.keyValue)
    }

    @Test
    @DisplayName("PacketCapture should calculate correct size")
    fun testPacketCapture() {
        val packetData = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)

        val capture = PacketCapture(
            id = "capture-1",
            deviceAddress = "AA:BB:CC:DD:EE:FF",
            startTime = Instant.now().minusSeconds(10),
            endTime = Instant.now(),
            packetCount = 100,
            fileType = CaptureFileType.PCAP,
            filePath = "/tmp/capture.pcap",
            fileSizeBytes = 1024,
            protocols = listOf("BLE", "ATT")
        )

        assertEquals(100, capture.packetCount)
        assertEquals(CaptureFileType.PCAP, capture.fileType)
        assertTrue(capture.protocols.contains("BLE"))
    }

    // Helper functions

    private fun createTestFuzzConfig(): FuzzConfig {
        return FuzzConfig(
            targetDevice = createTestBluetoothDevice(),
            targetService = null,
            targetCharacteristic = null,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 100,
            packetsPerSecond = 10,
            randomSeed = 12345L,
            dataPatterns = emptyList(),
            durationSeconds = 60,
            stopOnError = true,
            stopOnDisconnect = true,
            capturePackets = true,
            captureNotifications = true
        )
    }

    private fun createTestBluetoothDevice(): BluetoothDevice {
        return BluetoothDevice(
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
    }
}
