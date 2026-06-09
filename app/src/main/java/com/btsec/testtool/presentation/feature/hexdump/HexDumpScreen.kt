/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.hexdump

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.btsec.testtool.domain.model.HexDumpEntry
import com.btsec.testtool.domain.model.HexDumpViewMode

/**
 * Hex Dump Viewer Screen for GATT characteristic values.
 *
 * Displays characteristic data in hex dump format with support for
 * searching, view mode toggling (hex/text/binary), and clipboard copy.
 * For use in AUTHORIZED security testing only.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HexDumpScreen(
    characteristicUuid: String,
    serviceUuid: String,
    characteristicData: ByteArray,
    onBack: () -> Unit,
    viewModel: HexDumpViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val clipboardManager = LocalClipboardManager.current

    LaunchedEffect(characteristicUuid) {
        viewModel.loadCharacteristicData(
            data = characteristicData,
            characteristicUuid = characteristicUuid,
            serviceUuid = serviceUuid
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Hex Dump",
                        style = MaterialTheme.typography.titleMedium
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Navigate back"
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = {
                            val text = viewModel.getFullDumpForCopy()
                            clipboardManager.setText(AnnotatedString(text))
                            viewModel.onCopiedToClipboard()
                        }
                    ) {
                        Icon(
                            imageVector = Icons.Default.ContentCopy,
                            contentDescription = "Copy to clipboard"
                        )
                    }
                }
            )
        }
    ) { paddingValues ->
        when (val state = uiState) {
            is HexDumpUiState.Loading -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(paddingValues),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            }
            is HexDumpUiState.Error -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(paddingValues),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = state.message,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
            is HexDumpUiState.Success -> {
                HexDumpContent(
                    state = state,
                    viewModel = viewModel,
                    modifier = Modifier.padding(paddingValues)
                )
            }
        }
    }
}

@Composable
private fun HexDumpContent(
    state: HexDumpUiState.Success,
    viewModel: HexDumpViewModel,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier.fillMaxSize()) {
        // UUID info
        CharacteristicInfo(
            characteristicUuid = state.result.characteristicUuid,
            serviceUuid = state.result.serviceUuid,
            size = state.result.size
        )

        Divider(modifier = Modifier.padding(vertical = 4.dp))

        // View mode toggle
        ViewModeToggle(
            currentMode = state.viewMode,
            onModeChanged = { viewModel.setViewMode(it) }
        )

        // Search bar
        SearchBar(
            query = state.searchQuery,
            onQueryChanged = { viewModel.search(it) },
            resultCount = state.displayEntries.size,
            totalCount = state.result.entries.size
        )

        // Content based on view mode
        when (state.viewMode) {
            HexDumpViewMode.HEX -> {
                HexView(
                    entries = state.displayEntries,
                    modifier = Modifier.weight(1f)
                )
            }
            HexDumpViewMode.TEXT -> {
                TextView(
                    text = viewModel.getTextRepresentation(),
                    modifier = Modifier.weight(1f)
                )
            }
            HexDumpViewMode.BINARY -> {
                BinaryView(
                    binary = viewModel.getBinaryRepresentation(),
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Copy snackbar feedback
        if (state.copiedToClipboard) {
            Snackbar(
                modifier = Modifier.padding(16.dp),
                action = {
                    TextButton(onClick = { viewModel.resetCopiedState() }) {
                        Text("Dismiss")
                    }
                }
            ) {
                Text("Copied to clipboard")
            }
        }
    }
}

@Composable
private fun CharacteristicInfo(
    characteristicUuid: String,
    serviceUuid: String,
    size: Int
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = "Characteristic",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = characteristicUuid,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Service",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = serviceUuid,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Size: $size bytes",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun ViewModeToggle(
    currentMode: HexDumpViewMode,
    onModeChanged: (HexDumpViewMode) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        HexDumpViewMode.entries.forEach { mode ->
            FilterChip(
                selected = currentMode == mode,
                onClick = { onModeChanged(mode) },
                label = { Text(mode.name) }
            )
        }
    }
}

@Composable
private fun SearchBar(
    query: String,
    onQueryChanged: (String) -> Unit,
    resultCount: Int,
    totalCount: Int
) {
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChanged,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        placeholder = { Text("Search in dump...") },
        leadingIcon = {
            Icon(
                imageVector = Icons.Default.Search,
                contentDescription = "Search"
            )
        },
        singleLine = true,
        supportingText = if (query.isNotBlank()) {
            { Text("$resultCount / $totalCount lines") }
        } else null
    )
}

@Composable
private fun HexView(
    entries: List<HexDumpEntry>,
    modifier: Modifier = Modifier
) {
    if (entries.isEmpty()) {
        Box(
            modifier = modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "No data to display",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        return
    }

    LazyColumn(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp),
        contentPadding = PaddingValues(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        items(
            items = entries,
            key = { it.offset }
        ) { entry ->
            HexDumpLine(entry = entry)
        }
    }
}

@Composable
private fun HexDumpLine(entry: HexDumpEntry) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 8.dp, vertical = 1.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Offset
        Text(
            text = String.format("%08X", entry.offset),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        // Hex bytes
        Text(
            text = entry.hexBytes,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
        // ASCII representation
        Text(
            text = "|${entry.asciiRepresentation}|",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
private fun TextView(
    text: String,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .padding(16.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.horizontalScroll(rememberScrollState())
        )
    }
}

@Composable
private fun BinaryView(
    binary: String,
    modifier: Modifier = Modifier
) {
    LazyColumn(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp),
        contentPadding = PaddingValues(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        item {
            Text(
                text = binary,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .horizontalScroll(rememberScrollState())
            )
        }
    }
}
