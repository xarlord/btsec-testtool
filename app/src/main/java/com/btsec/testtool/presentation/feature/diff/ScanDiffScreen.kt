/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.diff

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Compare
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.DeviceDiff
import com.btsec.testtool.domain.model.DiffType
import com.btsec.testtool.presentation.feature.scanner.EmptyView

/**
 * Scan Diff Screen — compare two scan sessions side-by-side.
 *
 * Displays a colour-coded list of device differences between a
 * baseline and a comparison scan session.
 *
 * All functionality is for AUTHORIZED security testing only.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanDiffScreen(
    onBack: () -> Unit,
    viewModel: ScanDiffViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsState()

    // Local state for session selectors (simulated with device snapshots)
    var baselineSnapshot by remember { mutableStateOf<List<BluetoothDevice>?>(null) }
    var comparisonSnapshot by remember { mutableStateOf<List<BluetoothDevice>?>(null) }
    var baselineExpanded by remember { mutableStateOf(false) }
    var comparisonExpanded by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan Diff") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Navigate back",
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Session selectors
            SessionSelector(
                label = "Baseline Scan",
                expanded = baselineExpanded,
                onExpandedChange = { baselineExpanded = it },
                selectedLabel = baselineSnapshot?.let { "${it.size} devices" } ?: "Select baseline",
                onSelect = { devices ->
                    baselineSnapshot = devices
                    baselineExpanded = false
                },
                availableDevices = uiState.availableDevices,
            )

            SessionSelector(
                label = "Comparison Scan",
                expanded = comparisonExpanded,
                onExpandedChange = { comparisonExpanded = it },
                selectedLabel = comparisonSnapshot?.let { "${it.size} devices" } ?: "Select comparison",
                onSelect = { devices ->
                    comparisonSnapshot = devices
                    comparisonExpanded = false
                },
                availableDevices = uiState.availableDevices,
            )

            // Compare button
            Button(
                onClick = {
                    val base = baselineSnapshot
                    val comp = comparisonSnapshot
                    if (base != null && comp != null) {
                        viewModel.computeDiff(base, comp)
                    }
                },
                enabled = baselineSnapshot != null && comparisonSnapshot != null,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(
                    imageVector = Icons.Default.Compare,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Compare Scans")
            }

            // Results
            val result = uiState.diffResult
            if (result != null) {
                SummaryCard(summary = result.summary)

                FilterChips(
                    selectedFilter = uiState.selectedFilter,
                    onFilterSelected = { viewModel.setFilter(it) },
                    summary = result.summary,
                )

                if (uiState.filteredDevices.isEmpty()) {
                    EmptyView(
                        message = "No devices match the selected filter.",
                        icon = Icons.Default.Compare,
                    )
                } else {
                    DiffDeviceList(deviceDiffs = uiState.filteredDevices)
                }
            } else if (baselineSnapshot == null && comparisonSnapshot == null) {
                EmptyView(
                    message = "Select two scan sessions to compare.",
                    icon = Icons.Default.Compare,
                )
            }
        }
    }
}

/**
 * Dropdown selector for picking a scan session snapshot.
 */
@Composable
private fun SessionSelector(
    label: String,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    selectedLabel: String,
    onSelect: (List<BluetoothDevice>) -> Unit,
    availableDevices: List<BluetoothDevice>,
) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Box {
            OutlinedButton(
                onClick = { onExpandedChange(!expanded) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(selectedLabel)
            }
            DropdownMenu(
                expanded = expanded,
                onDismissRequest = { onExpandedChange(false) },
            ) {
                // Offer simulated snapshot sizes for demo / testing
                listOf(5, 10, 15, 20).forEach { count ->
                    DropdownMenuItem(
                        text = { Text("Session ($count devices)") },
                        onClick = {
                            onSelect(availableDevices.take(count))
                        },
                    )
                }
                if (availableDevices.isNotEmpty()) {
                    DropdownMenuItem(
                        text = { Text("Current scan (${availableDevices.size} devices)") },
                        onClick = { onSelect(availableDevices) },
                    )
                }
            }
        }
    }
}

/**
 * Summary statistics card.
 */
@Composable
private fun SummaryCard(summary: com.btsec.testtool.domain.model.ScanDiffSummary) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors =
            CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer,
            ),
    ) {
        Row(
            modifier =
                Modifier
                    .padding(12.dp)
                    .fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly,
        ) {
            SummaryStat("Baseline", summary.totalBaseline, Color.Unspecified)
            SummaryStat("Added", summary.addedCount, Color(0xFF4CAF50))
            SummaryStat("Removed", summary.removedCount, Color(0xFFF44336))
            SummaryStat("Modified", summary.modifiedCount, Color(0xFFFF9800))
            SummaryStat("Same", summary.unchangedCount, Color.Gray)
        }
    }
}

@Composable
private fun SummaryStat(
    label: String,
    count: Int,
    color: Color,
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            color = if (color == Color.Unspecified) MaterialTheme.colorScheme.onSecondaryContainer else color,
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
        )
    }
}

/**
 * Filter chip row.
 */
@Composable
private fun FilterChips(
    selectedFilter: DiffTypeFilter,
    onFilterSelected: (DiffTypeFilter) -> Unit,
    summary: com.btsec.testtool.domain.model.ScanDiffSummary,
) {
    ScrollableTabRow(
        selectedTabIndex = selectedFilter.ordinal,
        edgePadding = 0.dp,
        modifier = Modifier.fillMaxWidth(),
    ) {
        val tabs =
            listOf(
                DiffTypeFilter.ALL to "All",
                DiffTypeFilter.ADDED to "Added (${summary.addedCount})",
                DiffTypeFilter.REMOVED to "Removed (${summary.removedCount})",
                DiffTypeFilter.MODIFIED to "Modified (${summary.modifiedCount})",
            )
        tabs.forEachIndexed { index, (filter, label) ->
            Tab(
                selected = selectedFilter == filter,
                onClick = { onFilterSelected(filter) },
                text = { Text(label) },
            )
        }
    }
}

/**
 * LazyColumn of diff device entries.
 */
@Composable
private fun DiffDeviceList(deviceDiffs: List<DeviceDiff>) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        items(deviceDiffs, key = { "${it.device.address}-${it.diffType}" }) { diff ->
            DiffDeviceCard(diff)
        }
    }
}

/**
 * A single diff entry with colour coding.
 */
@Composable
private fun DiffDeviceCard(diff: DeviceDiff) {
    val bgColor =
        when (diff.diffType) {
            DiffType.ADDED -> Color(0xFFE8F5E9) // green tint
            DiffType.REMOVED -> Color(0xFFFFEBEE) // red tint
            DiffType.MODIFIED -> Color(0xFFFFF3E0) // orange tint
            DiffType.UNCHANGED -> Color(0xFFF5F5F5) // grey tint
        }

    val indicatorColor =
        when (diff.diffType) {
            DiffType.ADDED -> Color(0xFF4CAF50)
            DiffType.REMOVED -> Color(0xFFF44336)
            DiffType.MODIFIED -> Color(0xFFFF9800)
            DiffType.UNCHANGED -> Color.Gray
        }

    val typeLabel =
        when (diff.diffType) {
            DiffType.ADDED -> "+ ADDED"
            DiffType.REMOVED -> "- REMOVED"
            DiffType.MODIFIED -> "~ MODIFIED"
            DiffType.UNCHANGED -> "= UNCHANGED"
        }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = bgColor),
    ) {
        Row(modifier = Modifier.padding(12.dp)) {
            // Colour indicator
            Box(
                modifier =
                    Modifier
                        .width(4.dp)
                        .height(48.dp)
                        .background(indicatorColor, MaterialTheme.shapes.small),
            )
            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = diff.device.name ?: "Unknown",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        text = typeLabel,
                        style = MaterialTheme.typography.labelSmall,
                        color = indicatorColor,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = diff.device.address,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                // RSSI change arrow
                if (diff.previousRssi != null && diff.currentRssi != null) {
                    val arrow =
                        if (diff.currentRssi > diff.previousRssi) {
                            "↑"
                        } else if (diff.currentRssi < diff.previousRssi) {
                            "↓"
                        } else {
                            "→"
                        }
                    Text(
                        text = "RSSI: ${diff.previousRssi} $arrow ${diff.currentRssi} dBm",
                        style = MaterialTheme.typography.bodySmall,
                    )
                } else if (diff.currentRssi != null) {
                    Text(
                        text = "RSSI: ${diff.currentRssi} dBm",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                // Changed fields
                if (diff.changedFields.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Changed: ${diff.changedFields.joinToString(", ")}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }
}
