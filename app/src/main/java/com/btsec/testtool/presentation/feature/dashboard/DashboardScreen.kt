/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.dashboard

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Scanner
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.btsec.testtool.R

/**
 * Dashboard Screen - Main hub for the application (entry point).
 *
 * Quick access to all features via a feature grid.
 */
@Composable
fun DashboardScreen(
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit,
    onNavigateToSettings: () -> Unit = {},
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.dashboard_title)) },
                actions = {
                    IconButton(onClick = onNavigateToSettings) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Settings"
                        )
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            FeatureGrid(
                onNavigateToScanner = onNavigateToScanner,
                onNavigateToFuzzer = onNavigateToFuzzer,
                onNavigateToKeys = onNavigateToKeys,
                onNavigateToVulns = onNavigateToVulns,
                onNavigateToReports = onNavigateToReports
            )
        }
    }
}

@Composable
private fun FeatureGrid(
    onNavigateToScanner: () -> Unit,
    onNavigateToFuzzer: () -> Unit,
    onNavigateToKeys: () -> Unit,
    onNavigateToVulns: () -> Unit,
    onNavigateToReports: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Features",
            style = MaterialTheme.typography.titleLarge
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            FeatureCard(
                icon = Icons.Filled.Scanner,
                title = stringResource(R.string.nav_scanner),
                description = "Scan for Bluetooth devices",
                onClick = onNavigateToScanner,
                modifier = Modifier.weight(1f)
            )
            FeatureCard(
                icon = Icons.Filled.BugReport,
                title = stringResource(R.string.nav_vulns),
                description = "Scan for vulnerabilities",
                onClick = onNavigateToVulns,
                modifier = Modifier.weight(1f)
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            FeatureCard(
                icon = Icons.Filled.Science,
                title = stringResource(R.string.nav_fuzzer),
                description = "Fuzz Bluetooth protocols",
                onClick = onNavigateToFuzzer,
                modifier = Modifier.weight(1f)
            )
            FeatureCard(
                icon = Icons.Filled.Key,
                title = stringResource(R.string.nav_keys),
                description = "Extract Bluetooth keys",
                onClick = onNavigateToKeys,
                modifier = Modifier.weight(1f)
            )
        }

        FeatureCard(
            icon = Icons.Filled.Assessment,
            title = stringResource(R.string.nav_reports),
            description = "View and generate reports",
            onClick = onNavigateToReports,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun FeatureCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        onClick = onClick,
        modifier = modifier.height(120.dp)
    ) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                modifier = Modifier.size(32.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
