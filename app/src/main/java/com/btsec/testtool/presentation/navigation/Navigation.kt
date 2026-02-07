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
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.btsec.testtool.presentation.feature.authorization.AuthorizationScreen
import com.btsec.testtool.presentation.feature.dashboard.DashboardScreen
import com.btsec.testtool.presentation.feature.scanner.ScannerScreen

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
        composable(
            route = "${Routes.DASHBOARD}/{authId}",
            arguments = listOf(navArgument("authId") { type = NavType.String })
        ) { backStackEntry ->
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
                onBack = {
                    // Navigate back to authorization
                    navController.navigate(Routes.AUTHORIZATION) {
                        popUpTo(Routes.AUTHORIZATION) { inclusive = true }
                    }
                }
            )
        }

        // Scanner screen
        composable(
            route = "${Routes.SCANNER}/{authId}",
            arguments = listOf(navArgument("authId") { type = NavType.String })
        ) { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            ScannerScreen(
                authId = authId,
                onBack = { navController.popBackStack() }
            )
        }

        // Fuzzer screen
        composable(
            route = "${Routes.FUZZER}/{authId}",
            arguments = listOf(navArgument("authId") { type = NavType.String })
        ) { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            TODO("Implement FuzzerScreen")
        }

        // Key Extraction screen
        composable(
            route = "${Routes.KEYS}/{authId}",
            arguments = listOf(navArgument("authId") { type = NavType.String })
        ) { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            TODO("Implement KeyExtractionScreen")
        }

        // Vulnerability Scanner screen
        composable(
            route = "${Routes.VULNS}/{authId}",
            arguments = listOf(navArgument("authId") { type = NavType.String })
        ) { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            TODO("Implement VulnScannerScreen")
        }

        // Reports screen
        composable(
            route = "${Routes.REPORTS}/{authId}",
            arguments = listOf(navArgument("authId") { type = NavType.String })
        ) { backStackEntry ->
            val authId = backStackEntry.arguments?.getString("authId") ?: return@composable

            TODO("Implement ReportsScreen")
        }
    }
}
