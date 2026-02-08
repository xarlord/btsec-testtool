/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.ui

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.presentation.feature.dashboard.DashboardScreen
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Screenshot test for DashboardScreen.
 *
 * This test verifies all feature cards are displayed correctly
 * and can be used for visual regression testing.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class DashboardScreenshotTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun testDashboardScreen_allFeatureCardsVisible() {
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

        // Verify header
        composeTestRule
            .onNodeWithText("BTSec Dashboard")
            .assertExists()

        // Verify authorization card
        composeTestRule
            .onNodeWithText("Authorized")
            .assertExists()

        composeTestRule
            .onNodeWithText("Authorization ID: BTSEC-20260208-A1B2C3D4")
            .assertExists()

        // Verify feature cards are displayed
        composeTestRule
            .onNodeWithText("Scanner")
            .assertExists()

        composeTestRule
            .onNodeWithText("Scan for Bluetooth devices")
            .assertExists()

        composeTestRule
            .onNodeWithText("Vulnerabilities")
            .assertExists()

        composeTestRule
            .onNodeWithText("Scan for vulnerabilities")
            .assertExists()

        composeTestRule
            .onNodeWithText("Fuzzer")
            .assertExists()

        composeTestRule
            .onNodeWithText("Fuzz Bluetooth protocols")
            .assertExists()

        composeTestRule
            .onNodeWithText("Key Extraction")
            .assertExists()

        composeTestRule
            .onNodeWithText("Extract Bluetooth keys")
            .assertExists()

        composeTestRule
            .onNodeWithText("Reports")
            .assertExists()

        composeTestRule
            .onNodeWithText("View and generate reports")
            .assertExists()

        // At this point, a screenshot would be captured for visual regression
        // Example using a library like Robolectric or Dropshots:
        // composeTestRule.onRoot().captureToFile(...)
    }

    @Test
    fun testDashboardScreen_authorizationCardContent() {
        val testAuthId = "BTSEC-20260208-TEST1234"
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

        // Verify authorization card displays the correct ID
        composeTestRule
            .onNodeWithText("Authorization ID: $testAuthId")
            .assertExists()

        // Capture screenshot of authorization card for visual testing
    }

    @Test
    fun testDashboardScreen_featureGridLayout() {
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

        // Verify the feature grid structure by checking all features
        val expectedFeatures = listOf(
            "Scanner" to "Scan for Bluetooth devices",
            "Vulnerabilities" to "Scan for vulnerabilities",
            "Fuzzer" to "Fuzz Bluetooth protocols",
            "Key Extraction" to "Extract Bluetooth keys",
            "Reports" to "View and generate reports"
        )

        expectedFeatures.forEach { (title, description) ->
            composeTestRule
                .onNodeWithText(title)
                .assertExists()

            composeTestRule
                .onNodeWithText(description)
                .assertExists()
        }

        // Screenshot the full grid layout for regression testing
    }
}
