/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.navigation

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.btsec.testtool.presentation.feature.authorization.AuthorizationScreen
import com.btsec.testtool.presentation.feature.dashboard.DashboardScreen
import com.btsec.testtool.presentation.feature.fuzzer.FuzzerScreen
import com.btsec.testtool.presentation.feature.keys.KeyExtractionScreen
import com.btsec.testtool.presentation.feature.reports.ReportsScreen
import com.btsec.testtool.presentation.feature.scanner.ScannerScreen
import com.btsec.testtool.presentation.feature.settings.SettingsScreen
import com.btsec.testtool.presentation.feature.vulns.VulnScannerScreen

/**
 * Navigation routes for the application.
 */
object Routes {
    const val AUTHORIZATION = "authorization"
    const val DASHBOARD = "dashboard"
    const val SCANNER = "scanner"
    const val FUZZER = "fuzzer"
    const val KEYS = "keys"
    const val VULNS = "vulns"
    const val REPORTS = "reports"
    const val SETTINGS = "settings"
}

/**
 * Main navigation graph for BTSec Test Tool.
 *
 * This implements the single-activity navigation pattern with all screens
 * as Composable destinations.
 */
@Composable
fun BTSecNavGraph(
    modifier: Modifier = Modifier,
    navController: NavHostController = rememberNavController(),
    startDestination: String = Routes.AUTHORIZATION
) {
    NavHost(
        navController = navController,
        startDestination = startDestination,
        modifier = modifier
    ) {
        // Authorization screen - Entry point
        composable(route = Routes.AUTHORIZATION) {
            AuthorizationScreen(
                onAuthorized = { authId ->
                    // Navigate to dashboard with auth ID
                    navController.navigate("${Routes.DASHBOARD}/$authId") {
                        // Pop authorization from back stack
                        popUpTo(Routes.AUTHORIZATION) { inclusive = true }
                    }
                }
            )
        }

        // Dashboard screen - Main hub
        composable(route = "${Routes.DASHBOARD}/{authId}") { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            DashboardScreen(
                authId = authId,
                onNavigateToScanner = {
                    navController.navigate("${Routes.SCANNER}/$authId")
                },
                onNavigateToFuzzer = {
                    navController.navigate("${Routes.FUZZER}/$authId")
                },
                onNavigateToKeys = {
                    navController.navigate("${Routes.KEYS}/$authId")
                },
                onNavigateToVulns = {
                    navController.navigate("${Routes.VULNS}/$authId")
                },
                onNavigateToReports = {
                    navController.navigate("${Routes.REPORTS}/$authId")
                },
                onNavigateToSettings = {
                    navController.navigate(Routes.SETTINGS)
                },
                onBack = {
                    // Navigate back to authorization
                    navController.navigate(Routes.AUTHORIZATION) {
                        popUpTo(Routes.AUTHORIZATION) { inclusive = true }
                    }
                }
            )
        }

        // Scanner screen
        composable(route = "${Routes.SCANNER}/{authId}") { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            ScannerScreen(

                onBack = { navController.popBackStack() }
            )
        }

        // Fuzzer screen
        composable(route = "${Routes.FUZZER}/{authId}") { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            FuzzerScreen(

                onBack = { navController.popBackStack() }
            )
        }

        // Key Extraction screen
        composable(route = "${Routes.KEYS}/{authId}") { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            KeyExtractionScreen(

                onBack = { navController.popBackStack() }
            )
        }

        // Vulnerability Scanner screen
        composable(route = "${Routes.VULNS}/{authId}") { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            VulnScannerScreen(

                onBack = { navController.popBackStack() }
            )
        }

        // Reports screen
        composable(route = "${Routes.REPORTS}/{authId}") { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            ReportsScreen(

                onBack = { navController.popBackStack() }
            )
        }

        // Settings screen
        composable(route = Routes.SETTINGS) {
            SettingsScreen(
                onBack = { navController.popBackStack() }
            )
        }
    }
}
