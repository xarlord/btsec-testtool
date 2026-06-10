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
import com.btsec.testtool.presentation.feature.dashboard.DashboardScreen
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for DashboardScreen.
 *
 * Tests navigation elements, authorization info, feature grid,
 * and user interactions. Enhanced to include click interactions
 * and callback verification.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class DashboardScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    // ── Basic rendering ─────────────────────────────────────────────

    @Test
    fun testDashboardScreen_displaysTitle() {
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("BTSec Dashboard")
            .assertIsDisplayed()
    }

    @Test
    fun testDashboardScreen_displaysAuthorizationId() {
        val testAuthId = "BTSEC-20260208-A1B2C3D4"
        composeTestRule.setContent {
            DashboardScreen(
                authId = testAuthId,
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText(testAuthId)
            .assertIsDisplayed()
    }

    @Test
    fun testDashboardScreen_displaysAuthorizationStatus() {
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Authorized")
            .assertIsDisplayed()
    }

    @Test
    fun testDashboardScreen_displaysFeaturesHeader() {
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Features")
            .assertIsDisplayed()
    }

    // ── Feature card rendering ──────────────────────────────────────

    @Test
    fun testDashboardScreen_displaysScannerCard() {
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Scan for Bluetooth devices")
            .assertIsDisplayed()
    }

    @Test
    fun testDashboardScreen_displaysVulnerabilitiesCard() {
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Scan for vulnerabilities")
            .assertIsDisplayed()
    }

    @Test
    fun testDashboardScreen_displaysFuzzerCard() {
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Fuzz Bluetooth protocols")
            .assertIsDisplayed()
    }

    @Test
    fun testDashboardScreen_displaysKeyExtractionCard() {
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Extract Bluetooth keys")
            .assertIsDisplayed()
    }

    @Test
    fun testDashboardScreen_displaysReportsCard() {
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("View and generate reports")
            .assertIsDisplayed()
    }

    // ── Navigation callback verification ────────────────────────────

    @Test
    fun testDashboardScreen_scannerCardClick_invokesCallback() {
        var scannerClicked = false
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { scannerClicked = true },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Scan for Bluetooth devices")
            .performClick()

        assert(scannerClicked) { "Scanner navigation callback should have been invoked" }
    }

    @Test
    fun testDashboardScreen_vulnsCardClick_invokesCallback() {
        var vulnsClicked = false
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { vulnsClicked = true },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Scan for vulnerabilities")
            .performClick()

        assert(vulnsClicked) { "Vulnerabilities navigation callback should have been invoked" }
    }

    @Test
    fun testDashboardScreen_fuzzerCardClick_invokesCallback() {
        var fuzzerClicked = false
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { fuzzerClicked = true },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Fuzz Bluetooth protocols")
            .performClick()

        assert(fuzzerClicked) { "Fuzzer navigation callback should have been invoked" }
    }

    @Test
    fun testDashboardScreen_keysCardClick_invokesCallback() {
        var keysClicked = false
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { keysClicked = true },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Extract Bluetooth keys")
            .performClick()

        assert(keysClicked) { "Key extraction navigation callback should have been invoked" }
    }

    @Test
    fun testDashboardScreen_reportsCardClick_invokesCallback() {
        var reportsClicked = false
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { reportsClicked = true },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("View and generate reports")
            .performClick()

        assert(reportsClicked) { "Reports navigation callback should have been invoked" }
    }

    // ── Back navigation ─────────────────────────────────────────────

    @Test
    fun testDashboardScreen_backButton_invokesCallback() {
        var backClicked = false
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { backClicked = true }
            )
        }

        composeTestRule
            .onNodeWithContentDescription("Navigate back")
            .performClick()

        assert(backClicked) { "Back callback should have been invoked" }
    }

    // ── Auth ID variation ───────────────────────────────────────────

    @Test
    fun testDashboardScreen_differentAuthId_reflectsInCard() {
        val customAuthId = "BTSEC-20260315-CUSTOM987"
        composeTestRule.setContent {
            DashboardScreen(
                authId = customAuthId,
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithText("Authorization ID: $customAuthId")
            .assertExists()
    }

    // ── Settings icon ───────────────────────────────────────────────

    @Test
    fun testDashboardScreen_displaysSettingsIcon() {
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithContentDescription("Settings")
            .assertIsDisplayed()
    }

    @Test
    fun testDashboardScreen_settingsClick_invokesCallback() {
        var settingsClicked = false
        composeTestRule.setContent {
            DashboardScreen(
                authId = "BTSEC-20260208-A1B2C3D4",
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onNavigateToSettings = { settingsClicked = true },
                onBack = { }
            )
        }

        composeTestRule
            .onNodeWithContentDescription("Settings")
            .performClick()

        assert(settingsClicked) { "Settings callback should have been invoked" }
    }
}
