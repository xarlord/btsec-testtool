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
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.R
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.usecase.BluetoothScanningUseCase
import com.btsec.testtool.domain.usecase.ScanResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Scanner Screen - Bluetooth device scanning.
 */
@Composable
fun ScannerScreen(
    authId: String,
    onBack: () -> Unit
) {
    val isScanning = remember { mutableStateOf(false) }
    val devices = remember { mutableStateOf(emptyList<BluetoothDevice>()) }
    val error = remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.scanner_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Navigate back"
                        )
                    }
                }
            )
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            ScanControls(
                isScanning = isScanning.value,
                deviceCount = devices.value.size,
                onStartScan = {
                    isScanning.value = true
                    error.value = null
                },
                onStopScan = { isScanning.value = false }
            )
            Spacer(modifier = Modifier.height(16.dp))
            when {
                error.value != null -> {
                    ErrorView(
                        error = error.value!!,
                        onRetry = {
                            error.value = null
                            isScanning.value = true
                        }
                    )
                }
                isScanning.value -> {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            CircularProgressIndicator()
                            Spacer(modifier = Modifier.height(16.dp))
                            Text(
                                text = "Scanning for Bluetooth devices…",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                }
                devices.value.isEmpty() -> {
                    EmptyView(
                        message = "No devices found. Start a scan to discover Bluetooth devices.",
                        icon = Icons.Default.BluetoothSearching
                    )
                }
                else -> {
                    DeviceList(devices = devices.value, isScanning = isScanning.value)
                }
            }
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
private fun DeviceList(devices: List<BluetoothDevice>, isScanning: Boolean) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(devices) { device ->
            DeviceCard(device = device)
        }
    }
}

@Composable
private fun DeviceCard(device: BluetoothDevice) {
    Card(modifier = Modifier.fillMaxWidth()) {
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
                contentDescription = "Error occurred",
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
                Text("Retry")
            }
        }
    }
}

/**
 * ViewModel for the Scanner screen.
 */
@HiltViewModel
class ScannerViewModel @Inject constructor(
    private val scanningUseCase: BluetoothScanningUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(ScannerUiState())
    val uiState: StateFlow<ScannerUiState> = _uiState.asStateFlow()

    init {
        collectScanResults()
    }

    private fun collectScanResults() {
        viewModelScope.launch {
            scanningUseCase.getScanResults().collect { devices ->
                _uiState.value = _uiState.value.copy(
                    devices = devices,
                    deviceCount = devices.size
                )
            }
        }
        viewModelScope.launch {
            scanningUseCase.isScanning().collect { scanning ->
                _uiState.value = _uiState.value.copy(isScanning = scanning)
            }
        }
    }

    fun startScan(authId: String) {
        viewModelScope.launch {
            when (val result = scanningUseCase.startScan()) {
                is ScanResult.Started -> {
                    // Scan started successfully
                }
                is ScanResult.ConsentRequired -> {
                    _uiState.value = _uiState.value.copy(
                        error = "Consent required for scanning"
                    )
                }
                is ScanResult.NotAuthorized -> {
                    _uiState.value = _uiState.value.copy(
                        error = "Not authorized for scanning"
                    )
                }
                is ScanResult.Error -> {
                    _uiState.value = _uiState.value.copy(
                        error = result.message
                    )
                }
                else -> {}
            }
        }
    }

    fun stopScan() {
        viewModelScope.launch {
            scanningUseCase.stopScan()
        }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }
}

/**
 * UI state for the Scanner screen.
 */
data class ScannerUiState(
    val devices: List<com.btsec.testtool.domain.model.BluetoothDevice> = emptyList(),
    val deviceCount: Int = 0,
    val isScanning: Boolean = false,
    val error: String? = null
)
