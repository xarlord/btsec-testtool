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
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.presentation.feature.scanner.ScannerScreen
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for ScannerScreen.
 *
 * Tests scan controls, device list, and user interactions.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class ScannerScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

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
}
