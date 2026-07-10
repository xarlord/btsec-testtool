/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool

import com.btsec.testtool.domain.model.*
import java.time.Instant

/**
 * Test helper utilities for unit tests.
 */
object TestHelpers {
    /**
     * Create a test Bluetooth device.
     */
    fun createTestBluetoothDevice(
        address: String = "AA:BB:CC:DD:EE:FF",
        name: String = "Test Device",
        type: BluetoothType = BluetoothType.BLE,
    ): BluetoothDevice {
        return BluetoothDevice(
            address = address,
            name = name,
            type = type,
            deviceClass = DeviceClass.UNCATEGORIZED,
            bondState = BondState.NONE,
            rssi = -60,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
            scanCount = 1,
            services = emptyList(),
            manufacturerData = emptyMap(),
        )
    }

    /**
     * Create a test vulnerability definition.
     */
    fun createTestVulnerabilityDefinition(
        cveId: String = "CVE-2024-0001",
        name: String = "Test Vulnerability",
        severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    ): VulnerabilityDefinition {
        return VulnerabilityDefinition(
            cveId = cveId,
            name = name,
            description = "Test vulnerability description",
            severity = severity,
            cvssScore = 7.5,
            category = VulnerabilityCategory.PROTOCOL,
            affectedVersions = "All versions",
            affectedProfiles = listOf("BLE", "Classic"),
            yearDiscovered = 2024,
            references = emptyList(),
            mitigation = "Update firmware",
            testMethodology = "Test description",
        )
    }

    /**
     * Create a test fuzzing configuration.
     */
    fun createTestFuzzConfig(targetDevice: BluetoothDevice = createTestBluetoothDevice()): FuzzConfig {
        return FuzzConfig(
            targetDevice = targetDevice,
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
            captureNotifications = true,
        )
    }

    /**
     * Create a test device info.
     */
    fun createTestDeviceInfo(): DeviceInfo {
        return DeviceInfo(
            platform = "Android",
            model = "Test Device",
            androidVersion = "14",
            appVersion = "1.0.0",
            bluetoothAddress = "AA:BB:CC:DD:EE:FF",
        )
    }

    /**
     * Create a test key extraction result.
     */
    fun createTestKeyExtractionResult(extracted: Boolean = false): KeyExtractionResult {
        return KeyExtractionResult(
            id = "key-1",
            targetDevice = createTestBluetoothDevice(),
            keyType = KeyType.LTK,
            extracted = extracted,
            keyValue = if (extracted) byteArrayOf(0x01, 0x02, 0x03, 0x04) else null,
            method = ExtractionMethod.PASSIVE_MONITORING,
            confidence = ExtractionConfidence.HIGH,
            timestamp = Instant.now(),
        )
    }

    /**
     * Create a test vulnerability.
     */
    fun createTestVulnerability(severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH): Vulnerability {
        return Vulnerability(
            id = "vuln-1",
            cveId = "CVE-2024-0001",
            name = "Test Vulnerability",
            description = "Test description",
            severity = severity,
            cvssScore = 7.5,
            affectedDevice = createTestBluetoothDevice(),
            discoveredAt = Instant.now(),
            category = VulnerabilityCategory.PROTOCOL,
            affectedBluetoothVersions = emptyList(),
            references = emptyList(),
            mitigation = "Update firmware",
            verified = false,
        )
    }
}
