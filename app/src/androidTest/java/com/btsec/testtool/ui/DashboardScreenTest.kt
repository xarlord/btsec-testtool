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
 * Tests navigation elements, feature grid, and user interactions.
 *
 * Updated for the 1.15.x screen refactor: the DashboardScreen composable no
 * longer takes `authId` or `onBack` parameters (the authorization card and
 * back navigation were moved out of the dashboard). See issue #367.
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
            )
        }

        composeTestRule
            .onNodeWithText("BTSec Dashboard")
            .assertIsDisplayed()
    }

    @Test
    fun testDashboardScreen_displaysFeaturesHeader() {
        composeTestRule.setContent {
            DashboardScreen(
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { scannerClicked = true },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { vulnsClicked = true },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { fuzzerClicked = true },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { keysClicked = true },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { reportsClicked = true },
            )
        }

        composeTestRule
            .onNodeWithText("View and generate reports")
            .performClick()

        assert(reportsClicked) { "Reports navigation callback should have been invoked" }
    }

    // ── Settings icon ───────────────────────────────────────────────

    @Test
    fun testDashboardScreen_displaysSettingsIcon() {
        composeTestRule.setContent {
            DashboardScreen(
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
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
                onNavigateToScanner = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToVulns = { },
                onNavigateToReports = { },
                onNavigateToSettings = { settingsClicked = true },
            )
        }

        composeTestRule
            .onNodeWithContentDescription("Settings")
            .performClick()

        assert(settingsClicked) { "Settings callback should have been invoked" }
    }
}
