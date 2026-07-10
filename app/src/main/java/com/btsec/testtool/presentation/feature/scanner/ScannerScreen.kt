/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.scanner

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.BluetoothDisabled
import androidx.compose.material.icons.filled.BluetoothSearching
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
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
 * Get required BT permissions for current Android version.
 */
fun getRequiredBtPermissions(): List<String> {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        listOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
        )
    } else {
        listOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
    }
}

/**
 * Scanner Screen - Bluetooth device scanning (BLE + Classic).
 *
 * Requests runtime permissions before scanning starts.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScannerScreen(onBack: () -> Unit) {
    val viewModel: ScannerViewModel = androidx.hilt.navigation.compose.hiltViewModel()
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    // Track permission state
    var hasPermissions by remember { mutableStateOf(checkBtPermissions(context)) }
    var showPermissionRationale by remember { mutableStateOf(false) }

    // Permission launcher — re-checks after system dialog
    val permissionLauncher =
        rememberLauncherForActivityResult(
            ActivityResultContracts.RequestMultiplePermissions(),
        ) { results ->
            hasPermissions = results.values.all { it }
            if (hasPermissions) {
                viewModel.startScan()
            } else {
                showPermissionRationale = true
            }
        }

    // Permission rationale dialog
    if (showPermissionRationale) {
        AlertDialog(
            onDismissRequest = { showPermissionRationale = false },
            title = { Text("Bluetooth Permissions Required") },
            text = {
                Text(
                    "This app needs Bluetooth Scan and Connect permissions to discover " +
                        "nearby Bluetooth devices. Without these permissions, scanning " +
                        "cannot work.\n\nPlease grant the permissions in Settings.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showPermissionRationale = false
                    permissionLauncher.launch(getRequiredBtPermissions().toTypedArray())
                }) { Text("Request Again") }
            },
            dismissButton = {
                TextButton(onClick = { showPermissionRationale = false }) { Text("Cancel") }
            },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.scanner_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = stringResource(R.string.cd_navigate_up),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            // Permission status banner
            if (!hasPermissions) {
                Card(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                    colors =
                        CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                        ),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "Bluetooth permissions not granted",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Scanning requires BLUETOOTH_SCAN and BLUETOOTH_CONNECT permissions. Tap below to grant.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Button(onClick = {
                            permissionLauncher.launch(getRequiredBtPermissions().toTypedArray())
                        }) {
                            Icon(Icons.Default.Security, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text("Grant Permissions")
                        }
                    }
                }
            }

            // Scan controls
            ScanControls(
                isScanning = uiState.isScanning,
                deviceCount = uiState.devices.size,
                canScan = hasPermissions,
                onStartScan = {
                    if (hasPermissions) {
                        viewModel.startScan()
                    } else {
                        permissionLauncher.launch(getRequiredBtPermissions().toTypedArray())
                    }
                },
                onStopScan = { viewModel.stopScan() },
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Content
            when {
                uiState.error != null -> {
                    ErrorView(
                        error = uiState.error!!,
                        onRetry = {
                            viewModel.clearError()
                            viewModel.startScan()
                        },
                    )
                }
                uiState.isScanning && uiState.devices.isEmpty() -> {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center,
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            CircularProgressIndicator()
                            Spacer(modifier = Modifier.height(16.dp))
                            Text(
                                text = "Scanning for Bluetooth devices…",
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }
                }
                uiState.devices.isEmpty() -> {
                    EmptyView(
                        message = "No devices found. Tap Start Scan to discover Bluetooth devices.",
                        icon = Icons.Default.BluetoothSearching,
                    )
                }
                else -> {
                    DeviceList(
                        devices = uiState.devices,
                        isScanning = uiState.isScanning,
                        onDeviceSelected = { device ->
                            viewModel.selectDevice(device.address)
                        },
                    )
                }
            }
        }
    }
}

/**
 * Check if all required BT permissions are granted.
 */
fun checkBtPermissions(context: android.content.Context): Boolean {
    return getRequiredBtPermissions().all { perm ->
        ContextCompat.checkSelfPermission(context, perm) == PackageManager.PERMISSION_GRANTED
    }
}

@Composable
private fun ScanControls(
    isScanning: Boolean,
    deviceCount: Int,
    canScan: Boolean,
    onStartScan: () -> Unit,
    onStopScan: () -> Unit,
) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text =
                if (deviceCount > 0) {
                    "$deviceCount device${if (deviceCount != 1) "s" else ""} found"
                } else {
                    "No devices found"
                },
            style = MaterialTheme.typography.titleMedium,
        )
        Row {
            if (isScanning) {
                Button(
                    onClick = onStopScan,
                    colors =
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                        ),
                ) { Text("Stop") }
            } else {
                Button(
                    onClick = onStartScan,
                    // Always enabled — taps trigger permission request if needed
                    enabled = true,
                ) { Text("Start Scan") }
            }
        }
    }
}

@Composable
private fun DeviceList(
    devices: List<BluetoothDevice>,
    isScanning: Boolean,
    onDeviceSelected: (BluetoothDevice) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(devices, key = { it.address }) { device ->
            DeviceCard(device = device, onClick = { onDeviceSelected(device) })
        }
    }
}

@Composable
private fun DeviceCard(
    device: BluetoothDevice,
    onClick: () -> Unit = {},
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(text = device.name ?: "Unknown", style = MaterialTheme.typography.titleMedium)
            Text(text = device.address, style = MaterialTheme.typography.bodySmall)
            Row(
                modifier = Modifier.padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AssistChip(onClick = {}, label = { Text(device.type.name) })
                if (device.rssi != null) {
                    AssistChip(onClick = {}, label = { Text("${device.rssi} dBm") })
                }
            }
        }
    }
}

/**
 * Reusable empty state view.
 */
@Composable
fun EmptyView(
    message: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector = Icons.Default.BluetoothSearching,
) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.outline,
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = message,
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
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
    onRetry: () -> Unit,
) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                imageVector = Icons.Default.BluetoothDisabled,
                contentDescription = "Error",
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.error,
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = error,
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.error,
            )
            Spacer(modifier = Modifier.height(16.dp))
            FilledTonalButton(onClick = onRetry) {
                Text(stringResource(R.string.retry))
            }
        }
    }
}

/**
 * ViewModel for the Scanner screen.
 */
@HiltViewModel
class ScannerViewModel
    @Inject
    constructor(
        private val scanningUseCase: BluetoothScanningUseCase,
    ) : ViewModel() {
        private val _uiState = MutableStateFlow(ScannerUiState())
        val uiState: StateFlow<ScannerUiState> = _uiState.asStateFlow()

        init {
            collectScanResults()
        }

        private fun collectScanResults() {
            viewModelScope.launch {
                scanningUseCase.getScanResults().collect { devices ->
                    _uiState.value =
                        _uiState.value.copy(
                            devices = devices,
                            deviceCount = devices.size,
                        )
                }
            }
            viewModelScope.launch {
                scanningUseCase.isScanning().collect { scanning ->
                    _uiState.value = _uiState.value.copy(isScanning = scanning)
                }
            }
        }

        fun startScan() {
            viewModelScope.launch {
                _uiState.value = _uiState.value.copy(error = null)
                when (val result = scanningUseCase.startScan()) {
                    is ScanResult.Started -> { /* scan started */ }
                    is ScanResult.Error -> {
                        _uiState.value = _uiState.value.copy(error = result.message)
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

        fun selectDevice(address: String) {
            scanningUseCase.selectDevice(address)
        }
    }

/**
 * UI state for the Scanner screen.
 */
data class ScannerUiState(
    val devices: List<BluetoothDevice> = emptyList(),
    val deviceCount: Int = 0,
    val isScanning: Boolean = false,
    val error: String? = null,
)
