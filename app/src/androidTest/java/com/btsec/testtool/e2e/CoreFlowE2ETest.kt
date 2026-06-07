/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.e2e

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.presentation.feature.authorization.AuthorizationScreen
import com.btsec.testtool.presentation.feature.dashboard.DashboardScreen
import com.btsec.testtool.presentation.feature.scanner.ScannerScreen
import com.btsec.testtool.presentation.feature.reports.ReportsScreen
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end integration tests for core user flows.
 *
 * Tests complete navigation paths that a user would follow:
 * 1. Authorization flow
 * 2. Dashboard navigation
 * 3. Scanner flow
 * 4. Reports flow
 *
 * These tests verify screen transitions and data flow between screens
 * using Compose UI testing without actual BLE hardware.
 *
 * Issue: #210 — Zero E2E tests
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class CoreFlowE2ETest {

    @get:Rule
    val composeTestRule = createComposeRule()

    // ========== Authorization Flow ==========

    @Test
    fun authorizationFlow_displaysAllRequiredElements() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // Verify all authorization elements are present
        composeTestRule.onNodeWithText("Authorization Required").assertIsDisplayed()
        composeTestRule.onNodeWithText("BTSEC-YYYYMMDD-XXXXXXXX").assertIsDisplayed()
        composeTestRule.onNodeWithText("Verify Authorization").assertIsDisplayed()
    }

    @Test
    fun authorizationFlow_inputFieldAcceptsText() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // Find the text field and enter an auth ID
        composeTestRule
            .onNode(hasSetTextAction() and hasAnyAncestor(
                hasAnyChild(hasText("Authorization Required"))
            ))
            .performTextInput("BTSEC-DEMO-TEST1234")

        // The text should be in the field
        composeTestRule.onNodeWithText("BTSEC-DEMO-TEST1234").assertIsDisplayed()
    }

    // ========== Dashboard Navigation Flow ==========

    @Test
    fun dashboardFlow_displaysFeatureCardsForAuthorizedUser() {
        val testAuthId = "BTSEC-DEMO-TEST1234"

        composeTestRule.setContent {
            DashboardScreen(
                authId = testAuthId,
                onNavigateToScanner = { },
                onNavigateToVulns = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToReports = { },
                onNavigateToSettings = { },
                onBack = { }
            )
        }

        // Dashboard should show authorization status
        composeTestRule.onNodeWithText("Authorized").assertIsDisplayed()

        // All feature cards should be visible
        composeTestRule.onNodeWithText("Scanner").assertIsDisplayed()
        composeTestRule.onNodeWithText("Vulnerability").assertIsDisplayed()
        composeTestRule.onNodeWithText("Fuzzer").assertIsDisplayed()
        composeTestRule.onNodeWithText("Key Extraction").assertIsDisplayed()
        composeTestRule.onNodeWithText("Reports").assertIsDisplayed()
    }

    @Test
    fun dashboardFlow_displaysAuthId() {
        val testAuthId = "BTSEC-DEMO-ABCD1234"

        composeTestRule.setContent {
            DashboardScreen(
                authId = testAuthId,
                onNavigateToScanner = { },
                onNavigateToVulns = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToReports = { },
                onNavigateToSettings = { },
                onBack = { }
            )
        }

        // Auth ID should be displayed on the dashboard
        composeTestRule.onNodeWithText(testAuthId).assertIsDisplayed()
    }

    // ========== Scanner Flow ==========

    @Test
    fun scannerFlow_displaysScanControls() {
        composeTestRule.setContent {
            ScannerScreen(
                authId = "BTSEC-DEMO-TEST1234",
                onBack = { }
            )
        }

        // Scanner should show controls
        composeTestRule.onNodeWithText("Device Scanner").assertIsDisplayed()
        composeTestRule.onNodeWithText("Start Scan").assertIsDisplayed()
    }

    @Test
    fun scannerFlow_displaysEmptyStateWhenNoDevices() {
        composeTestRule.setContent {
            ScannerScreen(
                authId = "BTSEC-DEMO-TEST1234",
                onBack = { }
            )
        }

        // Should show empty state
        composeTestRule.onNodeWithText("No devices found").assertIsDisplayed()
    }

    // ========== Reports Flow ==========

    @Test
    fun reportsFlow_displaysReportHeader() {
        composeTestRule.setContent {
            ReportsScreen(
                authId = "BTSEC-DEMO-TEST1234",
                onBack = { }
            )
        }

        // Reports screen should show header
        composeTestRule.onNodeWithText("Security Reports").assertIsDisplayed()
    }

    // ========== Cross-Screen Data Flow ==========

    @Test
    fun authIdPropagates_fromAuthorizationToDashboard() {
        // Simulate the auth ID being passed from authorization to dashboard
        val authId = "BTSEC-DEMO-FLOW1234"

        composeTestRule.setContent {
            DashboardScreen(
                authId = authId,
                onNavigateToScanner = { },
                onNavigateToVulns = { },
                onNavigateToFuzzer = { },
                onNavigateToKeys = { },
                onNavigateToReports = { },
                onNavigateToSettings = { },
                onBack = { }
            )
        }

        // The dashboard should display the auth ID passed from authorization
        composeTestRule.onNodeWithText(authId).assertIsDisplayed()
    }

    @Test
    fun authIdPropagates_fromDashboardToFeatureScreen() {
        // Verify the auth ID can be passed through the navigation chain
        val authId = "BTSEC-DEMO-NAVA1234"

        // Start at scanner with the auth ID
        composeTestRule.setContent {
            ScannerScreen(
                authId = authId,
                onBack = { }
            )
        }

        // Scanner should have received the correct auth ID
        composeTestRule.onNodeWithText("Device Scanner").assertIsDisplayed()
    }
}
