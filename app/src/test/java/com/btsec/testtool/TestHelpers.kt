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
     * Create a test authorization with default values.
     */
    fun createTestAuthorization(
        authId: String = "BTSEC-20260207-A1B2C3D4",
        issuedTo: String = "Security Tester",
        issuedBy: String = "Security Research Team",
    ): Authorization {
        val now = Instant.now()
        return Authorization(
            authId = authId,
            issuedTo = issuedTo,
            issuedBy = issuedBy,
            issuedAt = now,
            expiresAt = now.plusSeconds(86400 * 365),
            authorizedActions =
                setOf(
                    TestAction.SCAN_DEVICES,
                    TestAction.CONNECT_DEVICE,
                    TestAction.START_FUZZING,
                    TestAction.EXTRACT_KEYS,
                    TestAction.SCAN_VULNERABILITIES,
                    TestAction.GENERATE_REPORT,
                ),
            scope = createTestScope(authId),
            signature = "test_signature",
            terms = emptyList(),
        )
    }

    /**
     * Create a test scope with default values.
     */
    fun createTestScope(authId: String = "BTSEC-TEST"): TestScope {
        val now = Instant.now()
        return TestScope(
            authId = authId,
            authorizedTargets =
                listOf(
                    TargetDevice(
                        identifier = "*",
                        deviceType = DeviceType.UNKNOWN,
                        owner = null,
                        location = null,
                    ),
                ),
            allowedActions = TestAction.entries.toSet(),
            validFrom = now.minusSeconds(3600),
            validUntil = now.plusSeconds(86400 * 30),
            maxPacketsPerSecond = 100,
            requiresReport = true,
            disclosureDeadline = now.plusSeconds(86400 * 90),
        )
    }

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
     * Create a test consent record.
     */
    fun createTestConsentRecord(
        authId: String = "BTSEC-TEST",
        authorized: Boolean = true,
    ): ConsentRecord {
        return ConsentRecord(
            id = "consent-1",
            authId = authId,
            action = "SCAN_DEVICES",
            timestamp = Instant.now(),
            authorized = authorized,
            deviceInfo = createTestDeviceInfo(),
            userSignature = if (authorized) "signature" else null,
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
