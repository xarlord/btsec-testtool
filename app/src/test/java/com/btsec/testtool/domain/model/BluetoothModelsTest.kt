/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.DisplayName
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for Bluetooth domain models defined in BluetoothModels.kt.
 *
 * Covers data class construction, default values, copy/equals,
 * helper methods, and edge cases.
 */
@DisplayName("Bluetooth Models Tests")
class BluetoothModelsTest {

    // ── BluetoothDevice ──

    @Test
    @DisplayName("BluetoothDevice should construct with all fields")
    fun bluetoothDeviceConstruction() {
        val now = Instant.now()
        val device = BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF",
            name = "Test Device",
            type = BluetoothType.BLE,
            deviceClass = DeviceClass.PHONE,
            bondState = BondState.BONDED,
            rssi = -42,
            txPower = 4,
            firstSeen = now,
            lastSeen = now
        )
        assertEquals("AA:BB:CC:DD:EE:FF", device.address)
        assertEquals("Test Device", device.name)
        assertEquals(BluetoothType.BLE, device.type)
        assertEquals(DeviceClass.PHONE, device.deviceClass)
        assertEquals(BondState.BONDED, device.bondState)
        assertEquals(-42, device.rssi)
        assertEquals(4, device.txPower)
        assertEquals(now, device.firstSeen)
        assertEquals(now, device.lastSeen)
    }

    @Test
    @DisplayName("BluetoothDevice defaults: scanCount=1, empty services/manufacturerData")
    fun bluetoothDeviceDefaults() {
        val device = createTestDevice()
        assertEquals(1, device.scanCount)
        assertTrue(device.services.isEmpty())
        assertTrue(device.manufacturerData.isEmpty())
    }

    @Test
    @DisplayName("BluetoothDevice nullable fields should accept null")
    fun bluetoothDeviceNullables() {
        val device = BluetoothDevice(
            address = "00:11:22:33:44:55", name = null,
            type = BluetoothType.UNKNOWN, deviceClass = null,
            bondState = BondState.NONE, rssi = null, txPower = null,
            firstSeen = Instant.now(), lastSeen = Instant.now()
        )
        assertNull(device.name)
        assertNull(device.deviceClass)
        assertNull(device.rssi)
        assertNull(device.txPower)
    }

    @Test
    @DisplayName("BluetoothDevice.isBle() returns true for BLE and DUAL_MODE")
    fun bluetoothDeviceIsBle() {
        assertTrue(createTestDevice(type = BluetoothType.BLE).isBle())
        assertTrue(createTestDevice(type = BluetoothType.DUAL_MODE).isBle())
        assertFalse(createTestDevice(type = BluetoothType.CLASSIC).isBle())
        assertFalse(createTestDevice(type = BluetoothType.UNKNOWN).isBle())
    }

    @Test
    @DisplayName("BluetoothDevice.isClassic() returns true for CLASSIC and DUAL_MODE")
    fun bluetoothDeviceIsClassic() {
        assertTrue(createTestDevice(type = BluetoothType.CLASSIC).isClassic())
        assertTrue(createTestDevice(type = BluetoothType.DUAL_MODE).isClassic())
        assertFalse(createTestDevice(type = BluetoothType.BLE).isClassic())
    }

    @Test
    @DisplayName("BluetoothDevice.isBonded() returns true only for BONDED")
    fun bluetoothDeviceIsBonded() {
        assertTrue(createTestDevice(bondState = BondState.BONDED).isBonded())
        assertFalse(createTestDevice(bondState = BondState.NONE).isBonded())
        assertFalse(createTestDevice(bondState = BondState.BONDING).isBonded())
    }

    @Test
    @DisplayName("BluetoothDevice copy should create equal instance with modified fields")
    fun bluetoothDeviceCopy() {
        val original = createTestDevice()
        val copied = original.copy(name = "New Name", rssi = -80)
        assertEquals("New Name", copied.name)
        assertEquals(-80, copied.rssi)
        assertEquals(original.address, copied.address)
    }

    @Test
    @DisplayName("BluetoothDevice equals/hashCode based on all fields")
    fun bluetoothDeviceEquality() {
        val d1 = createTestDevice()
        val d2 = createTestDevice()
        assertEquals(d1, d2)
        assertEquals(d1.hashCode(), d2.hashCode())

        val d3 = d1.copy(name = "Different")
        assertFalse(d1 == d3)
    }

    // ── BluetoothType enum ──

    @Test
    @DisplayName("BluetoothType should have all expected values")
    fun bluetoothTypeValues() {
        val values = BluetoothType.values()
        assertEquals(4, values.size)
        assertTrue(values.contains(BluetoothType.BLE))
        assertTrue(values.contains(BluetoothType.CLASSIC))
        assertTrue(values.contains(BluetoothType.DUAL_MODE))
        assertTrue(values.contains(BluetoothType.UNKNOWN))
    }

    // ── ConnectionState sealed class ──

    @Test
    @DisplayName("ConnectionState.Disconnected is a data object")
    fun connectionStateDisconnected() {
        val state = ConnectionState.Disconnected
        assertNotNull(state)
        assertEquals(ConnectionState.Disconnected, ConnectionState.Disconnected)
    }

    @Test
    @DisplayName("ConnectionState.Error holds message")
    fun connectionStateError() {
        val state = ConnectionState.Error("timeout")
        assertEquals("timeout", state.message)
    }

    @Test
    @DisplayName("ConnectionState all subtypes are distinct")
    fun connectionStateDistinct() {
        val states = setOf(
            ConnectionState.Disconnected,
            ConnectionState.Connecting,
            ConnectionState.Connected,
            ConnectionState.Disconnecting,
            ConnectionState.Error("err")
        )
        assertEquals(5, states.size)
    }

    // ── BleCharacteristic ──

    @Test
    @DisplayName("BleCharacteristic.isReadable delegates to properties")
    fun bleCharacteristicReadable() {
        val char = BleCharacteristic(
            uuid = "0001", properties = CharacteristicProperties(read = true),
            permissions = null, value = null
        )
        assertTrue(char.isReadable())

        val charNoRead = char.copy(properties = CharacteristicProperties(read = false))
        assertFalse(charNoRead.isReadable())
    }

    @Test
    @DisplayName("BleCharacteristic.isWritable checks write and writeWithoutResponse")
    fun bleCharacteristicWritable() {
        val writeChar = BleCharacteristic("0001", CharacteristicProperties(write = true), null)
        assertTrue(writeChar.isWritable())

        val wnrChar = BleCharacteristic("0001", CharacteristicProperties(writeWithoutResponse = true), null)
        assertTrue(wnrChar.isWritable())

        val noWrite = BleCharacteristic("0001", CharacteristicProperties(), null)
        assertFalse(noWrite.isWritable())
    }

    @Test
    @DisplayName("BleCharacteristic.canNotify checks notify and indicate")
    fun bleCharacteristicNotify() {
        val notifyChar = BleCharacteristic("0001", CharacteristicProperties(notify = true), null)
        assertTrue(notifyChar.canNotify())

        val indicateChar = BleCharacteristic("0001", CharacteristicProperties(indicate = true), null)
        assertTrue(indicateChar.canNotify())

        val noNotify = BleCharacteristic("0001", CharacteristicProperties(), null)
        assertFalse(noNotify.canNotify())
    }

    // ── CharacteristicProperties ──

    @Test
    @DisplayName("CharacteristicProperties defaults all false")
    fun characteristicPropertiesDefaults() {
        val props = CharacteristicProperties()
        assertFalse(props.read)
        assertFalse(props.write)
        assertFalse(props.writeWithoutResponse)
        assertFalse(props.notify)
        assertFalse(props.indicate)
        assertFalse(props.signedWrite)
        assertFalse(props.extendedProperties)
    }

    // ── CharacteristicPermissions ──

    @Test
    @DisplayName("CharacteristicPermissions defaults: readAllowed=true, writeAllowed=true, rest false")
    fun characteristicPermissionsDefaults() {
        val perms = CharacteristicPermissions()
        assertTrue(perms.readAllowed)
        assertTrue(perms.writeAllowed)
        assertFalse(perms.readEncrypted)
        assertFalse(perms.readEncryptedMitm)
        assertFalse(perms.writeEncrypted)
        assertFalse(perms.writeEncryptedMitm)
        assertFalse(perms.writeSigned)
        assertFalse(perms.writeSignedMitm)
    }

    // ── FuzzResult ──

    @Test
    @DisplayName("FuzzResult.getDuration calculates correctly")
    fun fuzzResultDuration() {
        val start = Instant.now()
        val end = start.plusSeconds(60)
        val result = createFuzzResult(startTime = start, endTime = end)
        val duration = result.getDuration()
        assertNotNull(duration)
        assertEquals(60, duration!!.seconds)
    }

    @Test
    @DisplayName("FuzzResult.getDuration returns null when endTime is null")
    fun fuzzResultDurationNull() {
        val result = createFuzzResult(endTime = null)
        assertNull(result.getDuration())
    }

    @Test
    @DisplayName("FuzzResult.getSuccessRate calculates correctly")
    fun fuzzResultSuccessRate() {
        val result = createFuzzResult(packetsSent = 100, packetsReceived = 80)
        assertEquals(80.0, result.getSuccessRate(), 0.01)
    }

    @Test
    @DisplayName("FuzzResult.getSuccessRate returns 0 for zero packets sent")
    fun fuzzResultSuccessRateZeroSent() {
        val result = createFuzzResult(packetsSent = 0, packetsReceived = 0)
        assertEquals(0.0, result.getSuccessRate(), 0.01)
    }

    // ── KeyExtractionResult ──

    @Test
    @DisplayName("KeyExtractionResult.isSuccess true when extracted=true and keyValue non-null")
    fun keyExtractionSuccess() {
        val result = KeyExtractionResult(
            id = "1", targetDevice = createTestDevice(), keyType = KeyType.LTK,
            extracted = true, keyValue = byteArrayOf(0x01, 0x02),
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.HIGH, timestamp = Instant.now()
        )
        assertTrue(result.isSuccess())
    }

    @Test
    @DisplayName("KeyExtractionResult.isSuccess false when extracted=false")
    fun keyExtractionNotSuccess() {
        val result = KeyExtractionResult(
            id = "1", targetDevice = createTestDevice(), keyType = KeyType.LTK,
            extracted = false, keyValue = null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.LOW, timestamp = Instant.now()
        )
        assertFalse(result.isSuccess())
    }

    @Test
    @DisplayName("KeyExtractionResult.isSuccess false when keyValue is null even if extracted=true")
    fun keyExtractionSuccessNullKey() {
        val result = KeyExtractionResult(
            id = "1", targetDevice = createTestDevice(), keyType = KeyType.LTK,
            extracted = true, keyValue = null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.HIGH, timestamp = Instant.now()
        )
        assertFalse(result.isSuccess())
    }

    // ── VulnerabilitySeverity enum ──

    @Test
    @DisplayName("VulnerabilitySeverity has all expected values")
    fun vulnerabilitySeverityValues() {
        assertEquals(6, VulnerabilitySeverity.values().size)
    }

    // ── VulnerabilityCategory enum ──

    @Test
    @DisplayName("VulnerabilityCategory has all expected values")
    fun vulnerabilityCategoryValues() {
        val cats = VulnerabilityCategory.values()
        assertEquals(12, cats.size)
        assertTrue(cats.any { it == VulnerabilityCategory.PAIRING })
        assertTrue(cats.any { it == VulnerabilityCategory.ENCRYPTION })
    }

    // ── FuzzMethod enum ──

    @Test
    @DisplayName("FuzzMethod has all expected values")
    fun fuzzMethodValues() {
        assertEquals(12, FuzzMethod.values().size)
    }

    // ── SecurityReport ──

    @Test
    @DisplayName("SecurityReport constructs with all fields")
    fun securityReportConstruction() {
        val report = createTestReport()
        assertNotNull(report.id)
        assertEquals("BTSEC-TEST", report.authId)
        assertFalse(report.targetDevices.isEmpty())
    }

    @Test
    @DisplayName("SecurityReport copy preserves fields")
    fun securityReportCopy() {
        val report = createTestReport()
        val copied = report.copy(status = ReportStatus.DRAFT)
        assertEquals(ReportStatus.DRAFT, copied.status)
        assertEquals(report.id, copied.id)
    }

    // ── Helpers ──

    private fun createTestDevice(
        type: BluetoothType = BluetoothType.BLE,
        bondState: BondState = BondState.NONE
    ): BluetoothDevice {
        val now = Instant.now()
        return BluetoothDevice(
            address = "AA:BB:CC:DD:EE:FF", name = "Test", type = type,
            deviceClass = DeviceClass.PHONE, bondState = bondState,
            rssi = -50, txPower = 4, firstSeen = now, lastSeen = now
        )
    }

    private fun createFuzzResult(
        startTime: Instant = Instant.now(),
        endTime: Instant? = startTime.plusSeconds(10),
        packetsSent: Int = 10,
        packetsReceived: Int = 10
    ): FuzzResult {
        return FuzzResult(
            id = "fuzz-1", config = FuzzConfig(
                targetDevice = createTestDevice(), targetService = null,
                targetCharacteristic = null, fuzzMethod = FuzzMethod.RANDOM,
                packetCount = 100, packetsPerSecond = 10, randomSeed = null,
                dataPatterns = emptyList(), durationSeconds = null
            ),
            startTime = startTime, endTime = endTime,
            status = FuzzStatus.COMPLETED, packetsSent = packetsSent,
            packetsReceived = packetsReceived, errors = emptyList(),
            findings = emptyList(), captureFile = null
        )
    }

    private fun createTestReport(): SecurityReport {
        val now = Instant.now()
        return SecurityReport(
            id = "rpt-1", authId = "BTSEC-TEST", title = "Test Report",
            generatedAt = now, testPeriod = ReportPeriod(now, now),
            targetDevices = listOf(createTestDevice()),
            vulnerabilities = emptyList(), fuzzingResults = emptyList(),
            keyExtractionResults = emptyList(), executiveSummary = "Summary",
            findings = emptyList(), recommendations = emptyList(),
            appendix = ReportAppendix(emptyList(), "", emptyList(), emptyMap(), emptyList()),
            status = ReportStatus.FINAL
        )
    }
}
