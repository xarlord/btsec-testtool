/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.analytics

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.btsec.testtool.domain.model.AnalyticsSummary
import com.btsec.testtool.domain.model.DeviceRiskEntry
import com.btsec.testtool.domain.model.RiskSeverity

/**
 * Analytics Dashboard screen displaying scan summary, charts, and device risk list.
 *
 * @param onBack Callback to navigate back
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AnalyticsScreen(onBack: () -> Unit) {
    val viewModel: AnalyticsViewModel = hiltViewModel()
    val summary by viewModel.summary.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Analytics Dashboard") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Back",
                        )
                    }
                },
            )
        },
    ) { paddingValues ->
        LazyColumn(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            contentPadding = PaddingValues(vertical = 16.dp),
        ) {
            // Summary cards row
            item {
                SummaryCardsRow(summary = summary)
            }

            // Risk Trend Chart
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors =
                        CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        ),
                ) {
                    RiskTrendChart(
                        trendData = summary.trendData,
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                    )
                }
            }

            // Severity Donut Chart
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors =
                        CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        ),
                ) {
                    SeverityDonutChart(
                        distribution = summary.severityDistribution,
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                    )
                }
            }

            // Category Bar Chart
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors =
                        CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        ),
                ) {
                    CategoryBarChart(
                        breakdown = summary.categoryBreakdown,
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                    )
                }
            }

            // Top Vulnerable Devices section header
            item {
                Text(
                    text = "Top Vulnerable Devices",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            // Top Vulnerable Devices list
            if (summary.topVulnerableDevices.isEmpty()) {
                item {
                    Text(
                        text = "No devices scanned yet.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                items(
                    items = summary.topVulnerableDevices,
                    // ⚡ Bolt: Adding unique key to prevent unnecessary recompositions and improve list rendering performance
                    key = { it.deviceAddress },
                ) { device ->
                    DeviceRiskCard(device = device)
                }
            }

            // Bottom spacing
            item {
                Spacer(modifier = Modifier.height(32.dp))
            }
        }
    }
}

/**
 * Row of summary statistic cards.
 */
@Composable
private fun SummaryCardsRow(summary: AnalyticsSummary) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        SummaryCard(
            title = "Scans",
            value = summary.totalScans.toString(),
            icon = Icons.Default.Security,
            modifier = Modifier.weight(1f),
        )
        SummaryCard(
            title = "Devices",
            value = summary.totalDevices.toString(),
            icon = Icons.Default.Devices,
            modifier = Modifier.weight(1f),
        )
        SummaryCard(
            title = "Vulns",
            value = summary.totalVulnerabilities.toString(),
            icon = Icons.Default.Warning,
            modifier = Modifier.weight(1f),
        )
        SummaryCard(
            title = "Avg Risk",
            value = String.format("%.1f", summary.averageRiskScore),
            icon = Icons.Default.BugReport,
            modifier = Modifier.weight(1f),
        )
    }
}

/**
 * Individual summary statistic card.
 */
@Composable
private fun SummaryCard(
    title: String,
    value: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier,
        colors =
            CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
            ),
    ) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = MaterialTheme.colorScheme.onPrimaryContainer,
                modifier = Modifier.size(24.dp),
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = value,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Text(
                text = title,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        }
    }
}

/**
 * Card displaying a single device's risk information.
 */
@Composable
private fun DeviceRiskCard(device: DeviceRiskEntry) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors =
            CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface,
            ),
    ) {
        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = device.deviceName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = device.deviceAddress,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = "${device.vulnerabilityCount} vulnerabilities",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = String.format("%.1f", device.riskScore),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = severityColor(device.severity),
                )
                Text(
                    text = device.severity.name,
                    style = MaterialTheme.typography.labelSmall,
                    color = severityColor(device.severity),
                )
            }
        }
    }
}

/**
 * Returns the color associated with a risk severity level.
 */
private fun severityColor(severity: RiskSeverity): Color =
    when (severity) {
        RiskSeverity.CRITICAL -> Color(0xFFE53935)
        RiskSeverity.HIGH -> Color(0xFFFB8C00)
        RiskSeverity.MEDIUM -> Color(0xFFF9A825)
        RiskSeverity.LOW -> Color(0xFF43A047)
        RiskSeverity.INFO -> Color(0xFF90A4AE)
    }
