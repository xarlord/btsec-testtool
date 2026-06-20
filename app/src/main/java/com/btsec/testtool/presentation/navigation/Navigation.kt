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
import com.btsec.testtool.presentation.feature.dashboard.DashboardScreen
import com.btsec.testtool.presentation.feature.fuzzer.FuzzerScreen
import com.btsec.testtool.presentation.feature.hexdump.HexDumpScreen
import com.btsec.testtool.presentation.feature.keys.KeyExtractionScreen
import com.btsec.testtool.presentation.feature.reports.ReportsScreen
import com.btsec.testtool.presentation.feature.diff.ScanDiffScreen
import com.btsec.testtool.presentation.feature.scanner.ScannerScreen
import com.btsec.testtool.presentation.feature.settings.SettingsScreen
import com.btsec.testtool.presentation.feature.vulns.VulnScannerScreen

/**
 * Navigation routes for the application.
 */
object Routes {
    const val DASHBOARD = "dashboard"
    const val SCANNER = "scanner"
    const val FUZZER = "fuzzer"
    const val KEYS = "keys"
    const val VULNS = "vulns"
    const val REPORTS = "reports"
    const val SETTINGS = "settings"
    const val SCAN_DIFF = "diff"
    const val HEXDUMP = "hexdump"
}

/**
 * Main navigation graph for BTSec Test Tool.
 *
 * This implements the single-activity navigation pattern with all screens
 * as Composable destinations. Dashboard is the entry point.
 */
@Composable
fun BTSecNavGraph(
    modifier: Modifier = Modifier,
    navController: NavHostController = rememberNavController(),
    startDestination: String = Routes.DASHBOARD
) {
    NavHost(
        navController = navController,
        startDestination = startDestination,
        modifier = modifier
    ) {
        // Dashboard screen - Entry point (main hub)
        composable(route = Routes.DASHBOARD) {
            DashboardScreen(
                onNavigateToScanner = { navController.navigate(Routes.SCANNER) },
                onNavigateToFuzzer = { navController.navigate(Routes.FUZZER) },
                onNavigateToKeys = { navController.navigate(Routes.KEYS) },
                onNavigateToVulns = { navController.navigate(Routes.VULNS) },
                onNavigateToReports = { navController.navigate(Routes.REPORTS) },
                onNavigateToSettings = { navController.navigate(Routes.SETTINGS) },
            )
        }

        // Scanner screen
        composable(route = Routes.SCANNER) {
            ScannerScreen(
                onBack = { navController.popBackStack() }
            )
        }

        // Fuzzer screen
        composable(route = Routes.FUZZER) {
            FuzzerScreen(
                onBack = { navController.popBackStack() }
            )
        }

        // Key Extraction screen
        composable(route = Routes.KEYS) {
            KeyExtractionScreen(
                onBack = { navController.popBackStack() }
            )
        }

        // Vulnerability Scanner screen
        composable(route = Routes.VULNS) {
            VulnScannerScreen(
                onBack = { navController.popBackStack() }
            )
        }

        // Reports screen
        composable(route = Routes.REPORTS) {
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

        // Scan Diff screen
        composable(route = Routes.SCAN_DIFF) {
            ScanDiffScreen(
                onBack = { navController.popBackStack() }
            )
        }

        // Hex Dump Viewer screen
        composable(
            route = "${Routes.HEXDUMP}/{characteristicUuid}/{serviceUuid}"
        ) { backStackEntry ->
            val characteristicUuid = backStackEntry.arguments?.getString("characteristicUuid") ?: return@composable
            val serviceUuid = backStackEntry.arguments?.getString("serviceUuid") ?: return@composable

            HexDumpScreen(
                characteristicUuid = characteristicUuid,
                serviceUuid = serviceUuid,
                characteristicData = byteArrayOf(), // Data would be passed via SavedStateHandle or shared ViewModel in production
                onBack = { navController.popBackStack() }
            )
        }
    }
}
