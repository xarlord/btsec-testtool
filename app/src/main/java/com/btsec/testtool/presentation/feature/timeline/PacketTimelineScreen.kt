/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.timeline

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.btsec.testtool.domain.model.CapturedPacket
import com.btsec.testtool.domain.model.PacketDirection
import com.btsec.testtool.domain.model.PacketType

/**
 * BLE Packet Timeline Visualization Screen.
 *
 * Displays captured BLE packets in a timeline with filtering, stats,
 * and hex dump details. For use in AUTHORIZED security testing only.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PacketTimelineScreen(
    authId: String,
    onBack: () -> Unit,
    viewModel: PacketTimelineViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsState()
    val clipboardManager = LocalClipboardManager.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Packet Timeline",
                        style = MaterialTheme.typography.titleMedium,
                    )
                },
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
    ) { paddingValues ->
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
        ) {
            // Stats row
            StatsRow(state = uiState)

            Divider(modifier = Modifier.padding(vertical = 4.dp))

            // Filter row
            FilterRow(
                currentFilter = uiState.filter,
                onTypeFilterChanged = { viewModel.updateTypeFilter(it) },
                onDirectionFilterChanged = { viewModel.updateDirectionFilter(it) },
            )

            // Search bar
            SearchBarRow(
                query = uiState.filter.searchQuery ?: "",
                onQueryChanged = { viewModel.updateSearchQuery(it.ifBlank { null }) },
            )

            // Packet list
            if (uiState.filteredPackets.isEmpty()) {
                Box(
                    modifier =
                        Modifier
                            .fillMaxSize()
                            .weight(1f),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "No packets match the current filter",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                PacketList(
                    packets = uiState.filteredPackets,
                    selectedPacketId = uiState.selectedPacketId,
                    onPacketClick = { viewModel.selectPacket(it) },
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
private fun StatsRow(state: PacketTimelineUiState) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
    ) {
        StatItem(label = "Total", value = "${state.stats.totalPackets}")
        StatItem(label = "Sent", value = "${state.stats.sentCount}")
        StatItem(label = "Received", value = "${state.stats.receivedCount}")
        StatItem(
            label = "Avg Size",
            value = String.format("%.1f B", state.stats.averageSize),
        )
    }
}

@Composable
private fun StatItem(
    label: String,
    value: String,
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun FilterRow(
    currentFilter: com.btsec.testtool.domain.model.PacketFilter,
    onTypeFilterChanged: (PacketType?) -> Unit,
    onDirectionFilterChanged: (PacketDirection?) -> Unit,
) {
    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
    ) {
        // Type filters
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            FilterChip(
                selected = currentFilter.type == null,
                onClick = { onTypeFilterChanged(null) },
                label = { Text("All") },
            )
            PacketType.entries.filter { it != PacketType.UNKNOWN }.forEach { type ->
                FilterChip(
                    selected = currentFilter.type == type,
                    onClick = { onTypeFilterChanged(type) },
                    label = { Text(type.displayName) },
                )
            }
        }

        Spacer(modifier = Modifier.height(4.dp))

        // Direction filters
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            FilterChip(
                selected = currentFilter.direction == null,
                onClick = { onDirectionFilterChanged(null) },
                label = { Text("Both") },
            )
            PacketDirection.entries.forEach { direction ->
                FilterChip(
                    selected = currentFilter.direction == direction,
                    onClick = { onDirectionFilterChanged(direction) },
                    label = {
                        Text(
                            when (direction) {
                                PacketDirection.SENT -> "↑ Sent"
                                PacketDirection.RECEIVED -> "↓ Received"
                            },
                        )
                    },
                )
            }
        }
    }
}

@Composable
private fun SearchBarRow(
    query: String,
    onQueryChanged: (String) -> Unit,
) {
    val focusManager = LocalFocusManager.current
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChanged,
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
        keyboardActions = KeyboardActions(onDone = { focusManager.clearFocus() }),
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
        placeholder = { Text("Search packets...") },
        leadingIcon = {
            Icon(
                imageVector = Icons.Default.Search,
                contentDescription = "Search",
            )
        },
        singleLine = true,
    )
}

@Composable
private fun PacketList(
    packets: List<CapturedPacket>,
    selectedPacketId: String?,
    onPacketClick: (String?) -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        items(
            items = packets,
            key = { it.id },
        ) { packet ->
            PacketRow(
                packet = packet,
                isSelected = packet.id == selectedPacketId,
                onClick = {
                    onPacketClick(
                        if (packet.id == selectedPacketId) null else packet.id,
                    )
                },
            )
        }
    }
}

@Composable
private fun PacketRow(
    packet: CapturedPacket,
    isSelected: Boolean,
    onClick: () -> Unit,
) {
    val typeColor = Color(packet.type.colorHex)

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick),
        colors =
            CardDefaults.cardColors(
                containerColor =
                    if (isSelected) {
                        MaterialTheme.colorScheme.primaryContainer
                    } else {
                        MaterialTheme.colorScheme.surface
                    },
            ),
    ) {
        Column(modifier = Modifier.padding(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                // Type badge
                Box(
                    modifier =
                        Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(typeColor),
                )

                Spacer(modifier = Modifier.width(8.dp))

                // Type name
                Text(
                    text = packet.type.displayName,
                    style = MaterialTheme.typography.labelSmall,
                    color = typeColor,
                )

                Spacer(modifier = Modifier.width(8.dp))

                // Direction arrow
                Text(
                    text =
                        when (packet.direction) {
                            PacketDirection.SENT -> "↑"
                            PacketDirection.RECEIVED -> "↓"
                        },
                    style = MaterialTheme.typography.bodySmall,
                    color =
                        when (packet.direction) {
                            PacketDirection.SENT -> MaterialTheme.colorScheme.primary
                            PacketDirection.RECEIVED -> MaterialTheme.colorScheme.tertiary
                        },
                )

                Spacer(modifier = Modifier.width(8.dp))

                // Timestamp
                Text(
                    text = formatPacketTimestamp(packet.timestamp),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                Spacer(modifier = Modifier.weight(1f))

                // Size
                Text(
                    text = "${packet.size} B",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // Hex preview (first 16 bytes)
            Text(
                text =
                    packet.data.take(16).joinToString(" ") {
                        String.format("%02x", it)
                    },
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = 16.dp, top = 2.dp),
            )

            // Expanded details
            if (isSelected) {
                ExpandedPacketDetails(packet = packet)
            }
        }
    }
}

@Composable
private fun ExpandedPacketDetails(packet: CapturedPacket) {
    val clipboardManager = LocalClipboardManager.current

    Divider(modifier = Modifier.padding(vertical = 4.dp))

    // Source / Destination
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
    ) {
        Text(
            text = "From: ${packet.source}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = "To: ${packet.destination}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
    }

    Spacer(modifier = Modifier.height(4.dp))

    // Full hex dump
    val hexRows = formatHexDump(packet.data)
    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .horizontalScroll(rememberScrollState()),
    ) {
        hexRows.forEach { row ->
            Text(
                text = row,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
            )
        }
    }

    Spacer(modifier = Modifier.height(4.dp))

    // Copy button
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.End,
    ) {
        IconButton(
            onClick = {
                val hexText =
                    packet.data.joinToString(" ") {
                        String.format("%02x", it)
                    }
                clipboardManager.setText(AnnotatedString(hexText))
            },
        ) {
            Icon(
                imageVector = Icons.Default.ContentCopy,
                contentDescription = "Copy hex to clipboard",
                modifier = Modifier.size(16.dp),
            )
        }
    }
}

private fun formatPacketTimestamp(timestampMs: Long): String {
    val instant = java.time.Instant.ofEpochMilli(timestampMs)
    val formatter =
        java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
            .withZone(java.time.ZoneId.systemDefault())
    return formatter.format(instant)
}

private fun formatHexDump(
    data: ByteArray,
    bytesPerRow: Int = 16,
): List<String> {
    if (data.isEmpty()) return emptyList()
    return data.toList().chunked(bytesPerRow).mapIndexed { index, chunk ->
        val offset = String.format("%04x: ", index * bytesPerRow)
        val hex = chunk.joinToString(" ") { String.format("%02x", it) }
        val ascii =
            chunk.joinToString("") {
                if (it in 0x20..0x7E) it.toChar().toString() else "."
            }
        "$offset${hex.padEnd(bytesPerRow * 3 - 1)}  $ascii"
    }
}
