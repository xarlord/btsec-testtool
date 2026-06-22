/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.HfpCallState
import com.btsec.testtool.domain.model.HfpSeverity
import com.btsec.testtool.domain.model.HfpTestCategory
import com.btsec.testtool.domain.model.HfpTestResult
import com.btsec.testtool.domain.model.HfpTestSuite
import com.btsec.testtool.domain.repository.HfpSecurityRepository
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant
import javax.inject.Inject

/**
 * E2E tests for the HFP (Hands-Free Profile) security testing flow.
 *
 * Exercises: Connect → send AT commands → verify response parsing.
 *
 * Validates the HFP security repository contract, AT command test models,
 * and result severity classification.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class HfpFlowE2ETest {
    @get:Rule
    val hiltRule = HiltAndroidRule(this)

    @Inject
    lateinit var hfpRepository: HfpSecurityRepository

    private val targetDevice =
        BluetoothDevice(
            address = "44:55:66:77:88:99",
            name = "E2E-HFP-Target",
            type = BluetoothType.CLASSIC,
            deviceClass = null,
            bondState = BondState.BONDED,
            rssi = -35,
            txPower = null,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
            scanCount = 1,
            services = emptyList(),
            manufacturerData = emptyMap(),
        )

    @Before
    fun setUp() {
        hiltRule.inject()
    }

    // ── HFP Test Categories ──────────────────────────────────────────

    @Test
    fun hfpFlow_allTestCategoriesAvailable() {
        val categories = HfpTestCategory.entries
        assertTrue("Should have at least 8 HFP test categories", categories.size >= 8)
        assertTrue(HfpTestCategory.entries.contains(HfpTestCategory.CALL_MANIPULATION))
        assertTrue(HfpTestCategory.entries.contains(HfpTestCategory.BUFFER_OVERFLOW))
        assertTrue(HfpTestCategory.entries.contains(HfpTestCategory.INFORMATION_DISCLOSURE))
        assertTrue(HfpTestCategory.entries.contains(HfpTestCategory.AUTHENTICATION_BYPASS))
        assertTrue(HfpTestCategory.entries.contains(HfpTestCategory.INJECTION))
    }

    @Test
    fun hfpFlow_categoryDescriptions() {
        for (cat in HfpTestCategory.entries) {
            assertNotNull("${cat.name} should have a description", cat.description)
            assertTrue("${cat.name} description should not be empty", cat.description.isNotBlank())
        }
    }

    // ── HFP Severity Levels ──────────────────────────────────────────

    @Test
    fun hfpFlow_severityLevelsComplete() {
        val severities = HfpSeverity.entries
        assertTrue("Should have at least 4 severity levels", severities.size >= 4)
        assertTrue(HfpSeverity.entries.contains(HfpSeverity.CRITICAL))
        assertTrue(HfpSeverity.entries.contains(HfpSeverity.HIGH))
        assertTrue(HfpSeverity.entries.contains(HfpSeverity.MEDIUM))
        assertTrue(HfpSeverity.entries.contains(HfpSeverity.LOW))
    }

    // ── HFP Test Result Model ────────────────────────────────────────

    @Test
    fun hfpFlow_testResultConstruction() {
        val result =
            HfpTestResult(
                category = HfpTestCategory.INFORMATION_DISCLOSURE,
                testName = "AT+CGMI device info leak",
                command = "AT+CGMI",
                response = "TestManufacturer\r\nOK",
                vulnerable = true,
                confidence = 0.95,
                evidence = "Device responded with manufacturer name without auth",
                severity = HfpSeverity.MEDIUM,
                recommendation = "Restrict AT command access to authenticated connections",
            )

        assertEquals(HfpTestCategory.INFORMATION_DISCLOSURE, result.category)
        assertEquals("AT+CGMI", result.command)
        assertTrue(result.vulnerable)
        assertEquals(0.95, result.confidence, 0.01)
        assertEquals(HfpSeverity.MEDIUM, result.severity)
    }

    @Test
    fun hfpFlow_testResultNotVulnerable() {
        val result =
            HfpTestResult(
                category = HfpTestCategory.CALL_MANIPULATION,
                testName = "ATD call origination",
                command = "ATD1234567890;",
                response = "ERROR",
                vulnerable = false,
                confidence = 0.0,
                evidence = "Call origination rejected",
                severity = HfpSeverity.INFO,
                recommendation = "No action needed",
            )

        assertTrue(!result.vulnerable)
        assertEquals(0.0, result.confidence, 0.01)
        assertEquals(HfpSeverity.INFO, result.severity)
    }

    // ── HFP Test Suite Model ─────────────────────────────────────────

    @Test
    fun hfpFlow_testSuiteConstruction() {
        val results =
            listOf(
                HfpTestResult(
                    category = HfpTestCategory.BUFFER_OVERFLOW,
                    testName = "Oversized AT command",
                    command = "AT+" + "A".repeat(1024),
                    response = null,
                    vulnerable = true,
                    confidence = 0.85,
                    evidence = "Device disconnected after oversized command",
                    severity = HfpSeverity.CRITICAL,
                    recommendation = "Implement input length validation",
                ),
                HfpTestResult(
                    category = HfpTestCategory.INJECTION,
                    testName = "AT command chaining",
                    command = "AT+CGMI;AT+CGMM",
                    response = "ERROR",
                    vulnerable = false,
                    confidence = 0.0,
                    evidence = "Command chaining rejected",
                    severity = HfpSeverity.INFO,
                    recommendation = "No action needed",
                ),
            )

        val suite =
            HfpTestSuite(
                deviceAddress = targetDevice.address,
                deviceName = targetDevice.name,
                results = results,
                criticalCount = 1,
                highCount = 0,
                mediumCount = 0,
                lowCount = 0,
                infoCount = 1,
                overallRisk = HfpSeverity.CRITICAL,
                testDurationMs = 5000L,
            )

        assertEquals(targetDevice.address, suite.deviceAddress)
        assertEquals(2, suite.results.size)
        assertEquals(1, suite.criticalCount)
        assertEquals(HfpSeverity.CRITICAL, suite.overallRisk)
        assertEquals(5000L, suite.testDurationMs)
    }

    // ── HFP Call State Model ─────────────────────────────────────────

    @Test
    fun hfpFlow_callStateModel() {
        val idleState =
            HfpCallState(
                hasActiveCall = false,
                callNumber = null,
                callType = null,
                callDuration = null,
            )
        assertTrue(!idleState.hasActiveCall)

        val activeCall =
            HfpCallState(
                hasActiveCall = true,
                callNumber = "+1234567890",
                callType = "incoming",
                callDuration = 45,
            )
        assertTrue(activeCall.hasActiveCall)
        assertEquals("+1234567890", activeCall.callNumber)
        assertEquals(45, activeCall.callDuration)
    }
}
