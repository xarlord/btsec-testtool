/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.data.authorization.AuthorizationBackend
import com.btsec.testtool.service.BluetoothState
import com.btsec.testtool.service.BluetoothStateManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit
) {
    val viewModel: SettingsViewModel = androidx.hilt.navigation.compose.hiltViewModel()
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Navigate back")
                    }
                }
            )
        }
    ) { padding ->
        SettingsList(padding = padding, uiState = uiState, viewModel = viewModel)
    }
}

@Composable
private fun SettingsList(
    padding: PaddingValues,
    uiState: SettingsUiState,
    viewModel: SettingsViewModel
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item { BluetoothStatusCard(uiState) }
        item { PermissionsCard(uiState, viewModel) }
        item { AuthorizationCard(uiState, viewModel) }
        item { DataManagementCard(viewModel) }
        item { AboutCard() }
    }
}

@Composable
private fun BluetoothStatusCard(uiState: SettingsUiState) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Bluetooth Status", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    when (uiState.btState) {
                        BluetoothState.ON -> Icons.Default.Bluetooth
                        BluetoothState.OFF -> Icons.Default.BluetoothDisabled
                        else -> Icons.Default.BluetoothSearching
                    },
                    contentDescription = "Bluetooth status",
                    tint = when (uiState.btState) {
                        BluetoothState.ON -> MaterialTheme.colorScheme.primary
                        BluetoothState.OFF -> MaterialTheme.colorScheme.error
                        else -> MaterialTheme.colorScheme.outline
                    }
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    when (uiState.btState) {
                        BluetoothState.ON -> "Bluetooth Enabled"
                        BluetoothState.OFF -> "Bluetooth Disabled"
                        BluetoothState.TURNING_ON -> "Turning On..."
                        BluetoothState.TURNING_OFF -> "Turning Off..."
                        BluetoothState.UNAVAILABLE -> "Bluetooth Unavailable"
                    }
                )
            }

            if (uiState.btState != BluetoothState.ON) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Bluetooth must be enabled for scanning and testing.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

@Composable
private fun PermissionsCard(uiState: SettingsUiState, viewModel: SettingsViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Permissions", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

            val perms = listOf(
                "Bluetooth Scan" to uiState.hasBtScan,
                "Bluetooth Connect" to uiState.hasBtConnect,
                "Location Access" to uiState.hasLocation,
                "Notifications" to true
            )
            perms.forEach { (name, granted) ->
                PermissionRow(name, granted)
            }

            if (!uiState.allPermissionsGranted) {
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = { viewModel.requestPermissions() }) {
                    Text("Request Permissions")
                }
            }
        }
    }
}

@Composable
private fun PermissionRow(name: String, granted: Boolean) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(vertical = 4.dp)
    ) {
        Icon(
            if (granted) Icons.Default.CheckCircle else Icons.Default.Cancel,
            contentDescription = if (granted) "Permission granted" else "Permission denied",
            tint = if (granted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            modifier = Modifier.size(20.dp)
        )
        Spacer(Modifier.width(8.dp))
        Text(name, modifier = Modifier.weight(1f))
        Text(
            if (granted) "Granted" else "Denied",
            style = MaterialTheme.typography.labelSmall,
            color = if (granted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
        )
    }
}

@Composable
private fun AuthorizationCard(uiState: SettingsUiState, viewModel: SettingsViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Authorization", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

            ServerUrlSection(uiState, viewModel)
            Divider(modifier = Modifier.padding(vertical = 12.dp))
            DemoModeSection(uiState, viewModel)
        }
    }
}

@Composable
private fun ServerUrlSection(uiState: SettingsUiState, viewModel: SettingsViewModel) {
    var serverUrl by remember { mutableStateOf(uiState.serverUrl) }
    OutlinedTextField(
        value = serverUrl,
        onValueChange = { serverUrl = it },
        label = { Text("Server URL") },
        placeholder = { Text("https://auth.btsec.example.com") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true
    )
    Spacer(Modifier.height(8.dp))
    FilledTonalButton(
        onClick = { viewModel.updateServerUrl(serverUrl) },
        modifier = Modifier.fillMaxWidth()
    ) {
        Icon(Icons.Default.Save, contentDescription = "Save settings")
        Spacer(Modifier.width(4.dp))
        Text("Save Server URL")
    }
}

@Composable
private fun DemoModeSection(uiState: SettingsUiState, viewModel: SettingsViewModel) {
    Text("Demo Mode", style = MaterialTheme.typography.titleSmall)
    Text(
        "Use BTSEC-DEMO-XXXXXXXX format for offline testing without server verification.",
        style = MaterialTheme.typography.bodySmall
    )
    Spacer(Modifier.height(8.dp))
    OutlinedButton(
        onClick = { viewModel.generateDemoAuth() },
        modifier = Modifier.fillMaxWidth()
    ) {
        Icon(Icons.Default.VpnKey, contentDescription = "Demo authorization")
        Spacer(Modifier.width(4.dp))
        Text("Generate Demo Authorization ID")
    }

    if (uiState.demoAuthId != null) {
        Spacer(Modifier.height(8.dp))
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
            Text(
                uiState.demoAuthId!!,
                modifier = Modifier.padding(12.dp),
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun DataManagementCard(viewModel: SettingsViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Data Management", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

            OutlinedButton(
                onClick = { viewModel.clearAuthorization() },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Logout, contentDescription = "Sign out")
                Spacer(Modifier.width(4.dp))
                Text("Clear Authorization")
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = { viewModel.clearAllData() },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
            ) {
                Icon(Icons.Default.DeleteForever, contentDescription = "Clear data")
                Spacer(Modifier.width(4.dp))
                Text("Clear All Data")
            }
        }
    }
}

@Composable
private fun AboutCard() {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("About", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text("BTSec TestTool ${com.btsec.testtool.BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.bodyMedium)
            Text("Bluetooth Security Testing Tool", style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(4.dp))
            Text(
                "⚠️ This tool is for AUTHORIZED security testing only.\n" +
                "Unauthorized use is prohibited and may be illegal.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
    }
}

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val authBackend: AuthorizationBackend,
    private val btStateManager: BluetoothStateManager
) : ViewModel() {

    private val _uiState = MutableStateFlow(SettingsUiState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    init {
        observeBluetoothState()
        observePermissions()
        loadInitialSettings()
    }

    private fun observeBluetoothState() {
        viewModelScope.launch {
            btStateManager.bluetoothState.collect { state ->
                _uiState.update { it.copy(btState = state) }
            }
        }
    }

    private fun observePermissions() {
        viewModelScope.launch {
            btStateManager.permissionsGranted.collect { granted ->
                _uiState.update { it.copy(allPermissionsGranted = granted) }
            }
        }
        viewModelScope.launch {
            btStateManager.hasLocationPermission.collect { loc ->
                _uiState.update { it.copy(hasLocation = loc) }
            }
        }
    }

    private fun loadInitialSettings() {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    serverUrl = authBackend.getServerUrl(),
                    hasBtScan = btStateManager.checkPermissions(),
                    hasBtConnect = true
                )
            }
        }
    }

    fun updateServerUrl(url: String) {
        viewModelScope.launch { authBackend.setServerUrl(url) }
    }

    fun generateDemoAuth() {
        val demoId = authBackend.generateDemoAuthId()
        _uiState.update { it.copy(demoAuthId = demoId) }
    }

    fun requestPermissions() {
        btStateManager.checkPermissions()
    }

    fun clearAuthorization() {
        viewModelScope.launch { authBackend.clearCachedAuthorization() }
    }

    fun clearAllData() {
        viewModelScope.launch { authBackend.clearCachedAuthorization() }
    }
}

data class SettingsUiState(
    val btState: BluetoothState = BluetoothState.UNAVAILABLE,
    val allPermissionsGranted: Boolean = false,
    val hasBtScan: Boolean = false,
    val hasBtConnect: Boolean = false,
    val hasLocation: Boolean = false,
    val serverUrl: String = "",
    val demoAuthId: String? = null
)
