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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.R
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
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.cd_navigate_back))
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Bluetooth Status Card
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(stringResource(R.string.settings_bt_status), style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                when (uiState.btState) {
                                    BluetoothState.ON -> Icons.Default.Bluetooth
                                    BluetoothState.OFF -> Icons.Default.BluetoothDisabled
                                    else -> Icons.Default.BluetoothSearching
                                },
                                contentDescription = stringResource(R.string.cd_bluetooth_status),
                                tint = when (uiState.btState) {
                                    BluetoothState.ON -> MaterialTheme.colorScheme.primary
                                    BluetoothState.OFF -> MaterialTheme.colorScheme.error
                                    else -> MaterialTheme.colorScheme.outline
                                }
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                when (uiState.btState) {
                                    BluetoothState.ON -> stringResource(R.string.settings_bt_enabled)
                                    BluetoothState.OFF -> stringResource(R.string.settings_bt_disabled)
                                    BluetoothState.TURNING_ON -> stringResource(R.string.settings_bt_turning_on)
                                    BluetoothState.TURNING_OFF -> stringResource(R.string.settings_bt_turning_off)
                                    BluetoothState.UNAVAILABLE -> stringResource(R.string.settings_bt_unavailable)
                                }
                            )
                        }

                        if (uiState.btState != BluetoothState.ON) {
                            Spacer(Modifier.height(8.dp))
                            Text(
                                stringResource(R.string.settings_bt_required),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }

            // Permissions Card
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(stringResource(R.string.settings_permissions), style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))

                        val perms = listOf(
                            stringResource(R.string.settings_perm_bt_scan) to uiState.hasBtScan,
                            stringResource(R.string.settings_perm_bt_connect) to uiState.hasBtConnect,
                            stringResource(R.string.settings_perm_location) to uiState.hasLocation,
                            stringResource(R.string.settings_perm_notifications) to true // Assume granted for settings
                        )
                        perms.forEach { (name, granted) ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(vertical = 4.dp)
                            ) {
                                Icon(
                                    if (granted) Icons.Default.CheckCircle else Icons.Default.Cancel,
                                    contentDescription = if (granted) stringResource(R.string.cd_permission_granted) else stringResource(R.string.cd_permission_denied),
                                    tint = if (granted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(Modifier.width(8.dp))
                                Text(name, modifier = Modifier.weight(1f))
                                Text(
                                    if (granted) stringResource(R.string.settings_perm_granted) else stringResource(R.string.settings_perm_denied),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (granted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                                )
                            }
                        }

                        if (!uiState.allPermissionsGranted) {
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(onClick = { viewModel.requestPermissions() }) {
                                Text(stringResource(R.string.settings_request_perms))
                            }
                        }
                    }
                }
            }

            // Authorization Card
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(stringResource(R.string.settings_auth_card), style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))

                        var serverUrl by remember { mutableStateOf(uiState.serverUrl) }
                        OutlinedTextField(
                            value = serverUrl,
                            onValueChange = { serverUrl = it },
                            label = { Text(stringResource(R.string.settings_server_url)) },
                            placeholder = { Text(stringResource(R.string.settings_server_url_placeholder)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                        Spacer(Modifier.height(8.dp))
                        FilledTonalButton(
                            onClick = { viewModel.updateServerUrl(serverUrl) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Save, contentDescription = stringResource(R.string.cd_save_settings))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.settings_save_server))
                        }

                        Spacer(Modifier.height(12.dp))
                        Divider()
                        Spacer(Modifier.height(12.dp))

                        Text(stringResource(R.string.settings_demo_mode), style = MaterialTheme.typography.titleSmall)
                        Text(
                            stringResource(R.string.settings_demo_desc),
                            style = MaterialTheme.typography.bodySmall
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = { viewModel.generateDemoAuth() },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.VpnKey, contentDescription = stringResource(R.string.cd_demo_authorization))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.settings_generate_demo))
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
                }
            }

            // Data Management Card
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(stringResource(R.string.settings_data_management), style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))

                        OutlinedButton(
                            onClick = { viewModel.clearAuthorization() },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Logout, contentDescription = stringResource(R.string.cd_sign_out))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.settings_clear_auth))
                        }
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = { viewModel.clearAllData() },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                        ) {
                            Icon(Icons.Default.DeleteForever, contentDescription = stringResource(R.string.cd_clear_data))
                            Spacer(Modifier.width(4.dp))
                            Text(stringResource(R.string.settings_clear_all))
                        }
                    }
                }
            }

            // About Card
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(stringResource(R.string.settings_about_card), style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))
                        Text(stringResource(R.string.settings_app_version, com.btsec.testtool.BuildConfig.VERSION_NAME), style = MaterialTheme.typography.bodyMedium)
                        Text(stringResource(R.string.settings_app_subtitle), style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            stringResource(R.string.settings_warning_notice),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
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
        viewModelScope.launch {
            btStateManager.bluetoothState.collect { state ->
                _uiState.update { it.copy(btState = state) }
            }
        }
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
