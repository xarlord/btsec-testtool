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
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.presentation.feature.scanner.ScannerScreen
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for ScannerScreen.
 *
 * Tests scan controls, device list, user interactions, and state transitions.
 * Enhanced from label-only checks to include interaction and state verification.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class ScannerScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    // ── Initial state rendering ──────────────────────────────────────

    @Test
    fun testScannerScreen_displaysTitle() {
        composeTestRule.setContent {
            ScannerScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onBack = { }
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
                authId = "BTSEC-20260208-A1B2C3D4",
                onBack = { }
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
                authId = "BTSEC-20260208-A1B2C3D4",
                onBack = { }
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
                authId = "BTSEC-20260208-A1B2C3D4",
                onBack = { }
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
                authId = "BTSEC-20260208-A1B2C3D4",
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("No devices found. Start a scan to discover Bluetooth devices.")
            .assertIsDisplayed()
    }

    // ── Interaction: Start/Stop scan state transitions ──────────────

    @Test
    fun testScannerScreen_clickStartScan_showsScanningState() {
        composeTestRule.setContent {
            ScannerScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onBack = { }
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

        // Should now show Stop Scan (scanning state)
        composeTestRule
            .onNodeWithText("Stop Scan")
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
                authId = "BTSEC-20260208-A1B2C3D4",
                onBack = { }
            )
        }

        // Start scanning
        composeTestRule
            .onNodeWithText("Start Scan")
            .performClick()

        // Verify we're in scanning state
        composeTestRule
            .onNodeWithText("Stop Scan")
            .assertIsDisplayed()

        // Stop scanning
        composeTestRule
            .onNodeWithText("Stop Scan")
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
                authId = "BTSEC-20260208-A1B2C3D4",
                onBack = { }
            )
        }

        // Toggle scan state multiple times
        repeat(3) {
            composeTestRule
                .onNodeWithText("Start Scan")
                .performClick()

            composeTestRule
                .onNodeWithText("Stop Scan")
                .assertIsDisplayed()

            composeTestRule
                .onNodeWithText("Stop Scan")
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
                authId = "BTSEC-20260208-A1B2C3D4",
                onBack = { backClicked = true }
            )
        }

        composeTestRule
            .onNodeWithContentDescription("Navigate up")
            .performClick()

        assert(backClicked) { "Back callback should have been invoked" }
    }

    // ── Auth ID rendering ───────────────────────────────────────────

    @Test
    fun testScannerScreen_acceptsDifferentAuthIds() {
        val customAuthId = "BTSEC-20260101-Z9Y8X7W6"
        composeTestRule.setContent {
            ScannerScreen(
                authId = customAuthId,
                onBack = { }
            )
        }

        // Screen renders successfully with different auth ID
        composeTestRule
            .onNodeWithText("Device Scanner")
            .assertIsDisplayed()

        composeTestRule
            .onNodeWithText("Start Scan")
            .assertIsDisplayed()
    }
}
