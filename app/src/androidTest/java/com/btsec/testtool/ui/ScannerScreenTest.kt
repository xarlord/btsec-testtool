/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.bluetoothRuntimePermissionRule
import com.btsec.testtool.presentation.InstrumentationHiltActivity
import com.btsec.testtool.presentation.feature.scanner.ScannerScreen
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for ScannerScreen.
 *
 * Tests scan controls, device list, user interactions, and state transitions.
 *
 * Updated for the 1.15.x screen refactor: the ScannerScreen composable no
 * longer takes an `authId` parameter. See issue #367.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class ScannerScreenTest {
    @get:Rule(order = 0)
    val bluetoothPermissionsRule = bluetoothRuntimePermissionRule()

    @get:Rule(order = 1)
    val hiltRule = HiltAndroidRule(this)

    @get:Rule(order = 2)
    val composeTestRule = createAndroidComposeRule<InstrumentationHiltActivity>()

    @Before
    fun setUp() {
        hiltRule.inject()
    }

    // ── Initial state rendering ──────────────────────────────────────

    @Test
    fun testScannerScreen_displaysTitle() {
        composeTestRule.setContent {
            ScannerScreen(
                onBack = { },
            )
        }

        composeTestRule
            .onNodeWithText("Device Scanner")
            .assertIsDisplayed()
    }

    @Test
    fun testScannerScreen_displaysStartButton() {
        composeTestRule.setContent {
            ScannerScreen(
                onBack = { },
            )
        }

        composeTestRule
            .onNodeWithText("Start Scan")
            .assertIsDisplayed()
    }

    @Test
    fun testScannerScreen_displaysNoDevicesMessage() {
        composeTestRule.setContent {
            ScannerScreen(
                onBack = { },
            )
        }

        composeTestRule
            .onNodeWithText("No devices found")
            .assertIsDisplayed()
    }

    @Test
    fun testScannerScreen_displaysBackButton() {
        composeTestRule.setContent {
            ScannerScreen(
                onBack = { },
            )
        }

        composeTestRule
            .onNodeWithContentDescription("Navigate up")
            .assertIsDisplayed()
    }

    @Test
    fun testScannerScreen_displaysEmptyHintMessage() {
        composeTestRule.setContent {
            ScannerScreen(
                onBack = { },
            )
        }

        composeTestRule
            .onNodeWithText("No devices found. Tap Start Scan to discover Bluetooth devices.")
            .assertIsDisplayed()
    }

    // ── Interaction: Start/Stop scan state transitions ──────────────

    @Test
    fun testScannerScreen_clickStartScan_showsScanningState() {
        composeTestRule.setContent {
            ScannerScreen(
                onBack = { },
            )
        }

        // Initially shows Start Scan
        composeTestRule
            .onNodeWithText("Start Scan")
            .assertIsDisplayed()

        // Click Start Scan
        composeTestRule
            .onNodeWithText("Start Scan")
            .performClick()

        // Should now show Stop (scanning state)
        composeTestRule
            .onNodeWithText("Stop")
            .assertIsDisplayed()

        // Should show scanning indicator text
        composeTestRule
            .onNodeWithText("Scanning for Bluetooth devices…")
            .assertIsDisplayed()
    }

    @Test
    fun testScannerScreen_clickStopScan_returnsToIdleState() {
        composeTestRule.setContent {
            ScannerScreen(
                onBack = { },
            )
        }

        // Start scanning
        composeTestRule
            .onNodeWithText("Start Scan")
            .performClick()

        // Verify we're in scanning state
        composeTestRule
            .onNodeWithText("Stop")
            .assertIsDisplayed()

        // Stop scanning
        composeTestRule
            .onNodeWithText("Stop")
            .performClick()

        // Should return to Start Scan button
        composeTestRule
            .onNodeWithText("Start Scan")
            .assertIsDisplayed()

        // Should return to empty state
        composeTestRule
            .onNodeWithText("No devices found")
            .assertIsDisplayed()
    }

    @Test
    fun testScannerScreen_scanStateToggleIsReversible() {
        composeTestRule.setContent {
            ScannerScreen(
                onBack = { },
            )
        }

        // Toggle scan state multiple times
        repeat(3) {
            composeTestRule
                .onNodeWithText("Start Scan")
                .performClick()

            composeTestRule
                .onNodeWithText("Stop")
                .assertIsDisplayed()

            composeTestRule
                .onNodeWithText("Stop")
                .performClick()

            composeTestRule
                .onNodeWithText("Start Scan")
                .assertIsDisplayed()
        }
    }

    // ── Callback verification ────────────────────────────────────────

    @Test
    fun testScannerScreen_backButtonCallbackIsWired() {
        var backClicked = false

        composeTestRule.setContent {
            ScannerScreen(
                onBack = { backClicked = true },
            )
        }

        composeTestRule
            .onNodeWithContentDescription("Navigate up")
            .performClick()

        assert(backClicked) { "Back callback should have been invoked" }
    }
}
