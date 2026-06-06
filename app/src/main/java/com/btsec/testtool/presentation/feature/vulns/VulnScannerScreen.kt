/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.vulns

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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.ScanProgress
import com.btsec.testtool.domain.repository.ScanStatus
import com.btsec.testtool.domain.repository.VulnerabilityStatistics
import com.btsec.testtool.domain.repository.VulnerabilityTestResult
import com.btsec.testtool.domain.usecase.ScanStartResult
import com.btsec.testtool.domain.usecase.VulnerabilityScanningUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VulnScannerScreen(
    authId: String,
    onBack: () -> Unit
) {
    val viewModel: VulnScannerViewModel = androidx.hilt.navigation.compose.hiltViewModel()
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Vulnerability Scanner") },
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
            // Scan Controls
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Vulnerability Scan", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))

                        Text(
                            "Scan the connected device for known Bluetooth vulnerabilities including KNOB, BIAS, BLESA, BlueBorne, and more.",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Spacer(Modifier.height(12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            if (uiState.scanStatus != ScanStatus.RUNNING) {
                                FilledTonalButton(
                                    onClick = { viewModel.startScan() },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                                    Spacer(Modifier.width(4.dp))
                                    Text("Scan All")
                                }
                            } else {
                                OutlinedButton(
                                    onClick = { viewModel.stopScan() },
                                    modifier = Modifier.weight(1f),
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                                ) {
                                    Icon(Icons.Default.Stop, contentDescription = null)
                                    Spacer(Modifier.width(4.dp))
                                    Text("Stop Scan")
                                }
                            }
                        }
                    }
                }
            }

            // Scan Progress
            if (uiState.scanStatus == ScanStatus.RUNNING) {
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text("Scanning Progress", style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.height(8.dp))

                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

                            Spacer(Modifier.height(4.dp))

                            uiState.scanProgress?.let { progress ->
                                Text(
                                    "Checking: ${progress.vulnerabilitiesChecked}/${progress.totalVulnerabilities} • Found: ${progress.vulnerabilitiesFound}",
                                    style = MaterialTheme.typography.bodySmall
                                )
                                progress.currentVulnerability?.let { vuln ->
                                    Text(
                                        "Current: ${vuln.name}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // Known Vulnerability Definitions
            item {
                Text("Known Vulnerability Database", style = MaterialTheme.typography.titleMedium)
            }

            items(uiState.definitions, key = { it.cveId }) { def ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            SeverityBadge(def.severity)
                            Spacer(Modifier.width(8.dp))
                            Text(
                                def.cveId,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(def.name, style = MaterialTheme.typography.titleSmall)
                        Text(
                            def.description,
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 3
                        )
                        Spacer(Modifier.height(4.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text("CVSS: ${def.cvssScore}", style = MaterialTheme.typography.bodySmall)
                            Text("Year: ${def.yearDiscovered}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            // Discovered Vulnerabilities
            if (uiState.discoveredVulns.isNotEmpty()) {
                item {
                    Text(
                        "Discovered Vulnerabilities (${uiState.discoveredVulns.size})",
                        style = MaterialTheme.typography.titleMedium
                    )
                }
                items(uiState.discoveredVulns, key = { it.id }) { vuln ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = when (vuln.severity) {
                                VulnerabilitySeverity.CRITICAL -> Color(0xFFFFEBEE)
                                VulnerabilitySeverity.HIGH -> Color(0xFFFFF3E0)
                                VulnerabilitySeverity.MEDIUM -> Color(0xFFFFF8E1)
                                else -> MaterialTheme.colorScheme.surfaceVariant
                            }
                        )
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                SeverityBadge(vuln.severity)
                                Spacer(Modifier.width(8.dp))
                                Text(vuln.name, style = MaterialTheme.typography.titleSmall)
                            }
                            vuln.cveId?.let {
                                Text(it, style = MaterialTheme.typography.labelMedium)
                            }
                            Text(vuln.description, style = MaterialTheme.typography.bodySmall, maxLines = 2)
                            Spacer(Modifier.height(4.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                if (vuln.verified) {
                                    AssistChip(
                                        onClick = {},
                                        label = { Text("Verified") },
                                        leadingIcon = { Icon(Icons.Default.CheckCircle, null, modifier = Modifier.size(16.dp)) }
                                    )
                                }
                                AssistChip(
                                    onClick = { viewModel.verifyVulnerability(vuln.id) },
                                    label = { Text("Verify") },
                                    leadingIcon = { Icon(Icons.Default.FactCheck, null, modifier = Modifier.size(16.dp)) }
                                )
                            }
                        }
                    }
                }
            }

            // Statistics
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Statistics", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))
                        val stats = uiState.statistics
                        if (stats != null) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                                StatItem("Critical", stats.criticalCount, Color.Red)
                                StatItem("High", stats.highCount, Color(0xFFFF6D00))
                                StatItem("Medium", stats.mediumCount, Color(0xFFFFAB00))
                                StatItem("Low", stats.lowCount, Color(0xFF4CAF50))
                            }
                        } else {
                            Text("No scan data yet", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SeverityBadge(severity: VulnerabilitySeverity) {
    val color = when (severity) {
        VulnerabilitySeverity.CRITICAL -> Color.Red
        VulnerabilitySeverity.HIGH -> Color(0xFFFF6D00)
        VulnerabilitySeverity.MEDIUM -> Color(0xFFFFAB00)
        VulnerabilitySeverity.LOW -> Color(0xFF4CAF50)
        VulnerabilitySeverity.NONE -> Color.Gray
        VulnerabilitySeverity.INFORMATIONAL -> Color(0xFF2196F3)
    }
    Surface(
        shape = MaterialTheme.shapes.small,
        color = color.copy(alpha = 0.15f)
    ) {
        Text(
            severity.name,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun StatItem(label: String, count: Int, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text("$count", style = MaterialTheme.typography.titleLarge, color = color, fontWeight = FontWeight.Bold)
        Text(label, style = MaterialTheme.typography.labelSmall)
    }
}

@HiltViewModel
class VulnScannerViewModel @Inject constructor(
    private val vulnScanningUseCase: VulnerabilityScanningUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(VulnScannerUiState())
    val uiState: StateFlow<VulnScannerUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            vulnScanningUseCase.getScanStatus().collect { status ->
                _uiState.update { it.copy(scanStatus = status) }
            }
        }
        viewModelScope.launch {
            vulnScanningUseCase.getScanProgress().collect { progress ->
                _uiState.update { it.copy(scanProgress = progress) }
            }
        }
        viewModelScope.launch {
            vulnScanningUseCase.getAllVulnerabilityDefinitions().collect { defs ->
                _uiState.update { it.copy(definitions = defs) }
            }
        }
        viewModelScope.launch {
            vulnScanningUseCase.getAllDiscoveredVulnerabilities().collect { vulns ->
                _uiState.update { it.copy(discoveredVulns = vulns) }
            }
        }
        viewModelScope.launch {
            vulnScanningUseCase.getVulnerabilityStatistics().collect { stats ->
                _uiState.update { it.copy(statistics = stats) }
            }
        }
    }

    fun startScan() {
        viewModelScope.launch {
            val placeholderDevice = BluetoothDevice(
                address = "00:00:00:00:00:00",
                name = "Target Device",
                type = BluetoothType.BLE,
                deviceClass = null,
                bondState = BondState.NONE,
                rssi = null,
                txPower = null,
                firstSeen = java.time.Instant.now(),
                lastSeen = java.time.Instant.now()
            )
            vulnScanningUseCase.startVulnerabilityScan(placeholderDevice)
        }
    }

    fun stopScan() {
        viewModelScope.launch { vulnScanningUseCase.stopScan() }
    }

    fun verifyVulnerability(vulnId: String) {
        viewModelScope.launch {
            vulnScanningUseCase.updateVulnerabilityVerification(vulnId, true, "Manually verified")
        }
    }
}

data class VulnScannerUiState(
    val scanStatus: ScanStatus = ScanStatus.PENDING,
    val scanProgress: ScanProgress? = null,
    val definitions: List<VulnerabilityDefinition> = emptyList(),
    val discoveredVulns: List<Vulnerability> = emptyList(),
    val statistics: VulnerabilityStatistics? = null
)
