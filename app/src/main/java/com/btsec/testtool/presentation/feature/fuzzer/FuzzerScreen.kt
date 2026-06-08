/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.fuzzer

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.R
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.FuzzProgress
import com.btsec.testtool.domain.repository.FuzzingStatistics
import com.btsec.testtool.domain.usecase.FuzzingStartResult
import com.btsec.testtool.domain.usecase.FuzzingUseCase
import com.btsec.testtool.presentation.feature.scanner.EmptyView
import com.btsec.testtool.presentation.feature.scanner.ErrorView
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FuzzerScreen(
    authId: String,
    onBack: () -> Unit
) {
    val viewModel: FuzzerViewModel = androidx.hilt.navigation.compose.hiltViewModel()
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.fuzzer_bt_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.cd_navigate_up))
                    }
                }
            )
        }
    ) { padding ->
        when {
            uiState.error != null -> {
                Column(modifier = Modifier.padding(padding)) {
                    ErrorView(
                        error = uiState.error!!,
                        onRetry = { viewModel.clearError() }
                    )
                }
            }
            uiState.status == FuzzStatus.RUNNING && uiState.progress == null -> {
                Box(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(stringResource(R.string.fuzzer_starting), style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
            else -> {
                FuzzerContent(
                    padding = padding,
                    uiState = uiState,
                    onMethodChange = { viewModel.updateMethod(it) },
                    onPacketCountChange = { viewModel.updatePacketCount(it) },
                    onRateChange = { viewModel.updateRate(it) },
                    onStart = { viewModel.startFuzzing() },
                    onStop = { viewModel.stopFuzzing() },
                    onPause = { viewModel.pauseFuzzing() }
                )
            }
        }
    }
}

@Composable
private fun FuzzerContent(
    padding: PaddingValues,
    uiState: FuzzerUiState,
    onMethodChange: (FuzzMethod) -> Unit,
    onPacketCountChange: (Int) -> Unit,
    onRateChange: (Int) -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onPause: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Selected Device Info
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (uiState.selectedDeviceName != null)
                        MaterialTheme.colorScheme.primaryContainer
                    else
                        MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Bluetooth,
                        contentDescription = "Selected device",
                        tint = if (uiState.selectedDeviceName != null)
                            MaterialTheme.colorScheme.onPrimaryContainer
                        else
                            MaterialTheme.colorScheme.onErrorContainer
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = if (uiState.selectedDeviceName != null)
                            "Target: ${uiState.selectedDeviceName}"
                        else
                            "No device selected — go to Scanner to select a device",
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (uiState.selectedDeviceName != null)
                            MaterialTheme.colorScheme.onPrimaryContainer
                        else
                            MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }

        // Configuration Section
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(stringResource(R.string.fuzzer_config_title), style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(12.dp))

                    // Fuzz Method Selector
                    var methodExpanded by remember { mutableStateOf(false) }
                    ExposedDropdownMenuBox(expanded = methodExpanded, onExpandedChange = { methodExpanded = it }) {
                        OutlinedTextField(
                            value = uiState.selectedMethod.name,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text(stringResource(R.string.fuzzer_method_label)) },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = methodExpanded) },
                            modifier = Modifier.fillMaxWidth().menuAnchor()
                        )
                        ExposedDropdownMenu(expanded = methodExpanded, onDismissRequest = { methodExpanded = false }) {
                            FuzzMethod.entries.forEach { method ->
                                DropdownMenuItem(
                                    text = { Text(method.name.replace("_", " ")) },
                                    onClick = {
                                        onMethodChange(method)
                                        methodExpanded = false
                                    }
                                )
                            }
                        }
                    }

                    Spacer(Modifier.height(8.dp))

                    // Packet Count
                    Text(stringResource(R.string.fuzzer_packet_count_label, uiState.packetCount))
                    Slider(
                        value = uiState.packetCount.toFloat(),
                        onValueChange = { onPacketCountChange(it.toInt()) },
                        valueRange = 10f..10000f
                    )

                    Spacer(Modifier.height(8.dp))

                    // Rate
                    Text(stringResource(R.string.fuzzer_rate_label, uiState.packetsPerSecond))
                    Slider(
                        value = uiState.packetsPerSecond.toFloat(),
                        onValueChange = { onRateChange(it.toInt()) },
                        valueRange = 1f..100f
                    )

                    Spacer(Modifier.height(12.dp))

                    // Control Buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        when (uiState.status) {
                            FuzzStatus.PENDING, FuzzStatus.COMPLETED, FuzzStatus.STOPPED, FuzzStatus.ERROR -> {
                                FilledTonalButton(
                                    onClick = onStart,
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.Default.PlayArrow, contentDescription = "Start fuzzing")
                                    Spacer(Modifier.width(4.dp))
                                    Text("Start")
                                }
                            }
                            FuzzStatus.RUNNING -> {
                                FilledTonalButton(
                                    onClick = onPause,
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.Default.Pause, contentDescription = "Pause fuzzing")
                                    Spacer(Modifier.width(4.dp))
                                    Text("Pause")
                                }
                                OutlinedButton(
                                    onClick = onStop,
                                    modifier = Modifier.weight(1f),
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                                ) {
                                    Icon(Icons.Default.Stop, contentDescription = "Stop fuzzing")
                                    Spacer(Modifier.width(4.dp))
                                    Text("Stop")
                                }
                            }
                        }
                    }
                }
            }
        }

        // Progress Section
        if (uiState.status == FuzzStatus.RUNNING || uiState.progress != null) {
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Progress", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))

                        val progressPct = uiState.progress?.getProgressPercentage()?.toFloat() ?: 0f
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

                        Spacer(Modifier.height(8.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text("Sent: ${uiState.progress?.packetsSent ?: 0}", style = MaterialTheme.typography.bodySmall)
                            Text("Received: ${uiState.progress?.packetsReceived ?: 0}", style = MaterialTheme.typography.bodySmall)
                            Text("Errors: ${uiState.progress?.errors ?: 0}", style = MaterialTheme.typography.bodySmall)
                            Text("Findings: ${uiState.progress?.findings ?: 0}", style = MaterialTheme.typography.bodySmall)
                        }

                        Text(
                            "${(progressPct).toInt()}% complete",
                            style = MaterialTheme.typography.labelMedium,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                }
            }
        }

        // Findings Section
        if (uiState.findings.isEmpty() && uiState.status == FuzzStatus.COMPLETED) {
            item {
                EmptyView(
                    message = "No fuzzing findings. The target handled all packets without issues.",
                    icon = Icons.Default.CheckCircle
                )
            }
        } else if (uiState.findings.isNotEmpty()) {
            item {
                Text("Findings", style = MaterialTheme.typography.titleMedium)
            }
            items(uiState.findings, key = { "${it.timestamp}_${it.packetNumber}" }) { finding ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = when (finding.severity) {
                            VulnerabilitySeverity.CRITICAL -> Color(0xFFFFEBEE)
                            VulnerabilitySeverity.HIGH -> Color(0xFFFFF3E0)
                            VulnerabilitySeverity.MEDIUM -> Color(0xFFFFF8E1)
                            else -> Color(0xFFF1F8E9)
                        }
                    )
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Default.Warning,
                                contentDescription = "Finding severity: ${finding.severity.name}",
                                tint = when (finding.severity) {
                                    VulnerabilitySeverity.CRITICAL -> Color.Red
                                    VulnerabilitySeverity.HIGH -> Color(0xFFFF6D00)
                                    VulnerabilitySeverity.MEDIUM -> Color(0xFFFFAB00)
                                    else -> Color(0xFF4CAF50)
                                },
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                finding.severity.name,
                                style = MaterialTheme.typography.labelLarge
                            )
                        }
                        Text(finding.description, style = MaterialTheme.typography.bodyMedium)
                        Text(
                            "Category: ${finding.category.name.replace("_", " ")}",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }

        // Statistics Section
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Statistics", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    Text("Total Tests: ${uiState.statistics?.totalTests ?: 0}")
                    Text("Total Packets Sent: ${uiState.statistics?.totalPacketsSent ?: 0}")
                    Text("Avg Success Rate: ${"%.1f".format(uiState.statistics?.averageSuccessRate ?: 0.0)}%")
                }
            }
        }
    }
}

@HiltViewModel
class FuzzerViewModel @Inject constructor(
    private val fuzzingUseCase: FuzzingUseCase,
    private val scanningUseCase: com.btsec.testtool.domain.usecase.BluetoothScanningUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(FuzzerUiState())
    val uiState: StateFlow<FuzzerUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            fuzzingUseCase.getFuzzingStatus().collect { status ->
                _uiState.update { it.copy(status = status) }
            }
        }
        viewModelScope.launch {
            fuzzingUseCase.getFuzzingProgress().collect { progress ->
                _uiState.update { it.copy(progress = progress) }
            }
        }
        viewModelScope.launch {
            fuzzingUseCase.getFuzzingStatistics().collect { stats ->
                _uiState.update { it.copy(statistics = stats) }
            }
        }
        viewModelScope.launch {
            fuzzingUseCase.getCriticalFindings().collect { findings ->
                _uiState.update { it.copy(findings = findings) }
            }
        }
        viewModelScope.launch {
            scanningUseCase.getSelectedDeviceAddress().collect { address ->
                if (address != null) {
                    val device = scanningUseCase.getDevice(address)
                    _uiState.update { it.copy(selectedDeviceName = device?.name ?: address) }
                } else {
                    _uiState.update { it.copy(selectedDeviceName = null) }
                }
            }
        }
    }

    fun updateMethod(method: FuzzMethod) {
        _uiState.update { it.copy(selectedMethod = method) }
    }

    fun updatePacketCount(count: Int) {
        _uiState.update { it.copy(packetCount = count) }
    }

    fun updateRate(rate: Int) {
        _uiState.update { it.copy(packetsPerSecond = rate) }
    }

    fun startFuzzing() {
        viewModelScope.launch {
            val device = scanningUseCase.getSelectedDevice()
            if (device == null) {
                _uiState.update { it.copy(error = "No device selected. Please scan and select a device first.") }
                return@launch
            }
            val config = FuzzConfig(
                targetDevice = device,
                targetService = null,
                targetCharacteristic = null,
                fuzzMethod = _uiState.value.selectedMethod,
                packetCount = _uiState.value.packetCount,
                packetsPerSecond = _uiState.value.packetsPerSecond,
                randomSeed = null,
                dataPatterns = emptyList(),
                durationSeconds = null
            )
            fuzzingUseCase.startFuzzing(config)
        }
    }

    fun stopFuzzing() {
        viewModelScope.launch { fuzzingUseCase.stopFuzzing() }
    }

    fun pauseFuzzing() {
        viewModelScope.launch { fuzzingUseCase.pauseFuzzing() }
    }

    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }
}

data class FuzzerUiState(
    val selectedMethod: FuzzMethod = FuzzMethod.MUTATION,
    val packetCount: Int = 1000,
    val packetsPerSecond: Int = 50,
    val status: FuzzStatus = FuzzStatus.PENDING,
    val progress: FuzzProgress? = null,
    val findings: List<FuzzFinding> = emptyList(),
    val statistics: FuzzingStatistics? = null,
    val error: String? = null,
    val selectedDeviceName: String? = null
)
