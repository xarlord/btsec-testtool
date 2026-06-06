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
 * Unit tests for Authorization models.
 */
@DisplayName("Authorization Models Tests")
class AuthorizationModelsTest {

    @Test
    @DisplayName("Authorization data class should have correct field values")
    fun testAuthorizationFieldValues() {
        val authorization = Authorization(
            authId = "BTSEC-20260207-A1B2C3D4",
            issuedTo = "Security Tester",
            issuedBy = "Security Research Team",
            issuedAt = Instant.parse("2026-02-07T00:00:00Z"),
            expiresAt = Instant.parse("2027-02-07T00:00:00Z"),
            authorizedActions = setOf(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE),
            scope = createTestScope(),
            signature = "test_signature",
            terms = listOf("Term 1", "Term 2")
        )

        assertEquals("BTSEC-20260207-A1B2C3D4", authorization.authId)
        assertEquals("Security Tester", authorization.issuedTo)
        assertEquals("Security Research Team", authorization.issuedBy)
        assertTrue(authorization.authorizedActions.contains(TestAction.SCAN_DEVICES))
        assertEquals("test_signature", authorization.signature)
        assertEquals(listOf("Term 1", "Term 2"), authorization.terms)
    }

    @Test
    @DisplayName("TestScope should validate targets correctly")
    fun testTargetInScope() {
        val scope = createTestScope()

        val targetDevice = TargetDevice(
            identifier = "AA:BB:CC:DD:EE:FF",
            deviceType = DeviceType.PHONE,
            owner = "Test Owner",
            location = "Test Location"
        )

        assertTrue(scope.isTargetInScope(targetDevice),
            "Wildcard target should match any device")
    }

    @Test
    @DisplayName("TestScope should validate actions correctly")
    fun testActionAllowed() {
        val scope = createTestScope()

        assertTrue(scope.isActionAllowed(TestAction.SCAN_DEVICES))
        assertTrue(scope.isActionAllowed(TestAction.CONNECT_DEVICE))
        assertFalse(scope.isActionAllowed(TestAction.PACKET_CAPTURE))
    }

    @Test
    @DisplayName("TestScope should check time window correctly")
    fun testValidTimeWindow() {
        val now = Instant.now()
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = emptyList(),
            allowedActions = emptySet(),
            validFrom = now.minusSeconds(3600),
            validUntil = now.plusSeconds(3600),
            maxPacketsPerSecond = 100,
            requiresReport = false,
            disclosureDeadline = now.plusSeconds(86400 * 90)
        )

        assertTrue(scope.isWithinValidWindow(),
            "Current time should be within valid window")
    }

    @Test
    @DisplayName("TestScope should reject outside time window")
    fun testInvalidTimeWindow() {
        val past = Instant.now().minusSeconds(86400 * 30)
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = emptyList(),
            allowedActions = emptySet(),
            validFrom = past.minusSeconds(86400 * 10),
            validUntil = past.plusSeconds(86400 * 10),
            maxPacketsPerSecond = 100,
            requiresReport = false,
            disclosureDeadline = past.plusSeconds(86400 * 90)
        )

        assertFalse(scope.isWithinValidWindow(),
            "Expired time window should be invalid")
    }

    @Test
    @DisplayName("TargetDevice should handle BLE devices")
    fun testTargetDevice() {
        val device = TargetDevice(
            identifier = "AA:BB:CC:DD:EE:FF",
            deviceType = DeviceType.PHONE,
            owner = "Owner",
            location = "Location",
            notes = "Test notes"
        )

        assertEquals("AA:BB:CC:DD:EE:FF", device.identifier)
        assertEquals(DeviceType.PHONE, device.deviceType)
        assertEquals("Owner", device.owner)
        assertEquals("Location", device.location)
        assertEquals("Test notes", device.notes)
    }

    @Test
    @DisplayName("ConsentRecord should track consent properly")
    fun testConsentRecord() {
        val deviceInfo = DeviceInfo(
            platform = "Android",
            model = "Test Model",
            androidVersion = "14",
            appVersion = "1.0.0",
            bluetoothAddress = "AA:BB:CC:DD:EE:FF"
        )

        val consent = ConsentRecord(
            id = "consent-1",
            authId = "BTSEC-TEST",
            action = "SCAN_DEVICES",
            timestamp = Instant.now(),
            authorized = true,
            deviceInfo = deviceInfo,
            userSignature = "signature"
        )

        assertEquals("consent-1", consent.id)
        assertEquals("BTSEC-TEST", consent.authId)
        assertEquals("SCAN_DEVICES", consent.action)
        assertTrue(consent.authorized)
        assertNotNull(consent.userSignature)
    }

    @Test
    @DisplayName("DeviceInfo should contain correct information")
    fun testDeviceInfo() {
        val deviceInfo = DeviceInfo(
            platform = "Android",
            model = "Pixel 7",
            androidVersion = "14",
            appVersion = "1.0.0",
            bluetoothAddress = "AA:BB:CC:DD:EE:FF"
        )

        assertEquals("Android", deviceInfo.platform)
        assertEquals("Pixel 7", deviceInfo.model)
        assertEquals("14", deviceInfo.androidVersion)
        assertEquals("1.0.0", deviceInfo.appVersion)
        assertEquals("AA:BB:CC:DD:EE:FF", deviceInfo.bluetoothAddress)
    }

    // Helper functions

    private fun createTestScope(): TestScope {
        val now = Instant.now()
        return TestScope(
            authId = "BTSEC-20260207-A1B2C3D4",
            authorizedTargets = listOf(
                TargetDevice(
                    identifier = "*",
                    deviceType = DeviceType.UNKNOWN,
                    owner = null,
                    location = null
                )
            ),
            allowedActions = setOf(
                TestAction.SCAN_DEVICES,
                TestAction.CONNECT_DEVICE,
                TestAction.START_FUZZING
            ),
            validFrom = now.minusSeconds(3600),
            validUntil = now.plusSeconds(86400 * 30),
            maxPacketsPerSecond = 100,
            requiresReport = true,
            disclosureDeadline = now.plusSeconds(86400 * 90)
        )
    }
}
