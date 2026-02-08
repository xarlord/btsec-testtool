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
import com.btsec.testtool.presentation.feature.dashboard.DashboardScreen
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for DashboardScreen.
 *
 * Tests navigation elements, authorization info, and user interactions.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class DashboardScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

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
}
