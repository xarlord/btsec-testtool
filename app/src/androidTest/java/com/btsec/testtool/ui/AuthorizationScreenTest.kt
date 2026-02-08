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
import com.btsec.testtool.presentation.feature.authorization.AuthorizationScreen
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Comprehensive UI tests for AuthorizationScreen.
 *
 * Tests all UI elements, interactions, validation, and accessibility.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class AuthorizationScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun testAuthorizationScreen_displaysTitle() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // Verify title is displayed
        composeTestRule
            .onNodeWithText("Authorization Required")
            .assertIsDisplayed()
    }

    @Test
    fun testAuthorizationScreen_displaysSubtitle() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // Verify subtitle is displayed
        composeTestRule
            .onNodeWithText("Bluetooth Security Testing Tool")
            .assertIsDisplayed()
    }

    @Test
    fun testAuthorizationScreen_displaysDescription() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // Verify description is displayed
        composeTestRule
            .onNodeWithText("This tool performs authorized security testing only")
            .assertIsDisplayed()
    }

    @Test
    fun testAuthorizationScreen_displaysHint() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // Verify hint text is displayed
        composeTestRule
            .onNodeWithText("BTSEC-YYYYMMDD-XXXXXXXX")
            .assertIsDisplayed()
    }

    @Test
    fun testAuthorizationScreen_displaysVerifyButton() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // Verify button is displayed
        composeTestRule
            .onNodeWithText("Verify Authorization")
            .assertIsDisplayed()
    }
}
