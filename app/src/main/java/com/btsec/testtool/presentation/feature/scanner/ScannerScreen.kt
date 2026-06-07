/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.scanner

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.BluetoothSearching
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.btsec.testtool.R
import com.btsec.testtool.domain.model.BluetoothDevice

/**
 * Scanner Screen - Bluetooth device scanning.
 */
@Composable
fun ScannerScreen(
    authId: String,
    onBack: () -> Unit
) {
    val viewModel: ScannerViewModel = androidx.hilt.navigation.compose.hiltViewModel()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            ScannerTopBar(onBack = onBack)
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            ScanControls(
                isScanning = uiState.isScanning,
                deviceCount = uiState.devices.size,
                onStartScan = { viewModel.startScan(authId) },
                onStopScan = { viewModel.stopScan() }
            )
            Spacer(modifier = Modifier.height(16.dp))
            ScannerContent(
                uiState = uiState,
                authId = authId,
                viewModel = viewModel
            )
        }
    }
}

@Composable
private fun ScannerTopBar(onBack: () -> Unit) {
    TopAppBar(
        title = { Text(stringResource(R.string.scanner_title)) },
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.Default.ArrowBack,
                    contentDescription = stringResource(R.string.cd_navigate_up)
                )
            }
        }
    )
}

@Composable
private fun ScannerContent(
    uiState: ScannerUiState,
    authId: String,
    viewModel: ScannerViewModel
) {
    when {
        uiState.error != null -> {
            ErrorView(
                error = uiState.error!!,
                onRetry = {
                    viewModel.clearError()
                    viewModel.startScan(authId)
                }
            )
        }
        uiState.isScanning -> {
            ScanningIndicator()
        }
        uiState.devices.isEmpty() -> {
            EmptyView(
                message = stringResource(R.string.scanner_no_devices_hint),
                icon = Icons.Default.BluetoothSearching
            )
        }
        else -> {
            DeviceList(
                devices = uiState.devices,
                isScanning = uiState.isScanning,
                onDeviceSelected = { device ->
                    viewModel.selectDevice(device.address)
                }
            )
        }
    }
}

@Composable
private fun ScanningIndicator() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.scanner_scanning_bt),
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun ScanControls(
    isScanning: Boolean,
    deviceCount: Int,
    onStartScan: () -> Unit,
    onStopScan: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = if (deviceCount > 0) {
                stringResource(R.string.scanner_devices_found, deviceCount)
            } else {
                stringResource(R.string.scanner_no_devices)
            },
            style = MaterialTheme.typography.titleMedium
        )
        Row {
            if (isScanning) {
                Button(onClick = onStopScan, colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                )) { Text(stringResource(R.string.scanner_stop)) }
            } else {
                Button(onClick = onStartScan) { Text(stringResource(R.string.scanner_start)) }
            }
        }
    }
}

@Composable
private fun DeviceList(devices: List<BluetoothDevice>, isScanning: Boolean, onDeviceSelected: (BluetoothDevice) -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(devices) { device ->
            DeviceCard(device = device, onClick = { onDeviceSelected(device) })
        }
    }
}

@Composable
private fun DeviceCard(device: BluetoothDevice, onClick: () -> Unit = {}) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(text = device.name ?: "Unknown", style = MaterialTheme.typography.titleMedium)
            Text(text = device.address, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * Reusable empty state view.
 */
@Composable
fun EmptyView(
    message: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector = Icons.Default.BluetoothSearching
) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.outline
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = message,
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Reusable error view with retry button.
 */
@Composable
fun ErrorView(
    error: String,
    onRetry: () -> Unit
) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                imageVector = Icons.Default.ArrowBack,
                contentDescription = stringResource(R.string.cd_error),
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.error
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = error,
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.error
            )
            Spacer(modifier = Modifier.height(16.dp))
            FilledTonalButton(onClick = onRetry) {
                Text(stringResource(R.string.retry))
            }
        }
    }
}
