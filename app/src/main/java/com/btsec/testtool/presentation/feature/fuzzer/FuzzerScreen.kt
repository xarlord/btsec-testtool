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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.FuzzProgress
import com.btsec.testtool.domain.repository.FuzzStatus
import com.btsec.testtool.domain.repository.FuzzingStatistics
import com.btsec.testtool.domain.usecase.FuzzingStartResult
import com.btsec.testtool.domain.usecase.FuzzingUseCase
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
                title = { Text("Bluetooth Fuzzer") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
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
            // Configuration Section
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Fuzzing Configuration", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(12.dp))

                        // Fuzz Method Selector
                        var methodExpanded by remember { mutableStateOf(false) }
                        ExposedDropdownMenuBox(expanded = methodExpanded, onExpandedChange = { methodExpanded = it }) {
                            OutlinedTextField(
                                value = uiState.selectedMethod.name,
                                onValueChange = {},
                                readOnly = true,
                                label = { Text("Fuzz Method") },
                                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = methodExpanded) },
                                modifier = Modifier.fillMaxWidth().menuAnchor()
                            )
                            ExposedDropdownMenu(expanded = methodExpanded, onDismissRequest = { methodExpanded = false }) {
                                FuzzMethod.entries.forEach { method ->
                                    DropdownMenuItem(
                                        text = { Text(method.name.replace("_", " ")) },
                                        onClick = {
                                            viewModel.updateMethod(method)
                                            methodExpanded = false
                                        }
                                    )
                                }
                            }
                        }

                        Spacer(Modifier.height(8.dp))

                        // Packet Count
                        Text("Packet Count: ${uiState.packetCount}")
                        Slider(
                            value = uiState.packetCount.toFloat(),
                            onValueChange = { viewModel.updatePacketCount(it.toInt()) },
                            valueRange = 10f..10000f
                        )

                        Spacer(Modifier.height(8.dp))

                        // Rate
                        Text("Rate: ${uiState.packetsPerSecond} pkt/sec")
                        Slider(
                            value = uiState.packetsPerSecond.toFloat(),
                            onValueChange = { viewModel.updateRate(it.toInt()) },
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
                                        onClick = { viewModel.startFuzzing() },
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Icon(Icons.Default.PlayArrow, contentDescription = null)
                                        Spacer(Modifier.width(4.dp))
                                        Text("Start")
                                    }
                                }
                                FuzzStatus.RUNNING -> {
                                    FilledTonalButton(
                                        onClick = { viewModel.pauseFuzzing() },
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Icon(Icons.Default.Pause, contentDescription = null)
                                        Spacer(Modifier.width(4.dp))
                                        Text("Pause")
                                    }
                                    OutlinedButton(
                                        onClick = { viewModel.stopFuzzing() },
                                        modifier = Modifier.weight(1f),
                                        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                                    ) {
                                        Icon(Icons.Default.Stop, contentDescription = null)
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
                            LinearProgressIndicator(
                                progress = { progressPct / 100f },
                                modifier = Modifier.fillMaxWidth()
                            )

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
            if (uiState.findings.isNotEmpty()) {
                item {
                    Text("Findings", style = MaterialTheme.typography.titleMedium)
                }
                items(uiState.findings) { finding ->
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
                                    contentDescription = null,
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
}

@HiltViewModel
class FuzzerViewModel @Inject constructor(
    private val fuzzingUseCase: FuzzingUseCase
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
            // Use a placeholder device — in production would come from scan results
            val placeholderDevice = BluetoothDevice(
                address = "00:00:00:00:00:00",
                name = "Select Device",
                type = BluetoothType.UNKNOWN,
                deviceClass = null,
                bondState = BondState.NONE,
                rssi = null,
                txPower = null,
                firstSeen = java.time.Instant.now(),
                lastSeen = java.time.Instant.now()
            )
            val config = FuzzConfig(
                targetDevice = placeholderDevice,
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
}

data class FuzzerUiState(
    val selectedMethod: FuzzMethod = FuzzMethod.MUTATION,
    val packetCount: Int = 1000,
    val packetsPerSecond: Int = 50,
    val status: FuzzStatus = FuzzStatus.PENDING,
    val progress: FuzzProgress? = null,
    val findings: List<FuzzFinding> = emptyList(),
    val statistics: FuzzingStatistics? = null
)
