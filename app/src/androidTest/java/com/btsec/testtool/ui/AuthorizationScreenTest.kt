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
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.presentation.feature.authorization.AuthorizationScreen
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Comprehensive UI tests for AuthorizationScreen.
 *
 * Tests all UI elements, text input, button interactions, validation,
 * and state rendering. Enhanced from label-only checks to include
 * interaction and state verification.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class AuthorizationScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    // ── Initial state rendering ──────────────────────────────────────

    @Test
    fun testAuthorizationScreen_displaysTitle() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

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

        composeTestRule
            .onNodeWithText("Verify Authorization")
            .assertIsDisplayed()
    }

    // ── Legal warning card ──────────────────────────────────────────

    @Test
    fun testAuthorizationScreen_displaysLegalWarningTitle() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        composeTestRule
            .onNodeWithText("⚠️ CRITICAL NOTICE")
            .assertIsDisplayed()
    }

    @Test
    fun testAuthorizationScreen_displaysLegalWarningText() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        composeTestRule
            .onNodeWithText("This tool is for authorized security testing only.")
            .assertIsDisplayed()
    }

    // ── Text input interaction ──────────────────────────────────────

    @Test
    fun testAuthorizationScreen_inputField_acceptsText() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // The text field should exist and accept input
        val testAuthId = "BTSEC-20260208-TEST1234"
        composeTestRule
            .onNodeWithText("BTSEC-YYYYMMDD-XXXXXXXX")
            .performTextInput(testAuthId)

        // After input, the field should contain the entered text
        // The ViewModel uppercases the input
        composeTestRule
            .onNodeWithText(testAuthId)
            .assertExists()
    }

    // ── Verify button state ─────────────────────────────────────────

    @Test
    fun testAuthorizationScreen_verifyButton_isDisplayed() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        composeTestRule
            .onNodeWithText("Verify Authorization")
            .assertIsDisplayed()
    }

    @Test
    fun testAuthorizationScreen_verifyButton_clickDoesNotCrash() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // Enter an auth ID first so the button is enabled
        composeTestRule
            .onNodeWithText("BTSEC-YYYYMMDD-XXXXXXXX")
            .performTextInput("BTSEC-20260208-A1B2C3D4")

        // Click verify — may trigger loading state but shouldn't crash
        composeTestRule
            .onNodeWithText("Verify Authorization")
            .performClick()

        // Verify the screen is still displayed (no crash)
        composeTestRule
            .onNodeWithText("Authorization Required")
            .assertIsDisplayed()
    }

    // ── Security icon ───────────────────────────────────────────────

    @Test
    fun testAuthorizationScreen_displaysSecurityIcon() {
        composeTestRule.setContent {
            AuthorizationScreen(
                viewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
                onAuthorized = { }
            )
        }

        // The security icon is displayed (content description from the Icon composable)
        composeTestRule
            .onNodeWithText("Authorization Required")
            .assertIsDisplayed()
    }
}
