/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.R
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.ScanProgress
import com.btsec.testtool.domain.repository.ScanStatus
import com.btsec.testtool.domain.repository.VulnerabilityStatistics
import com.btsec.testtool.domain.repository.VulnerabilityTestResult
import com.btsec.testtool.domain.usecase.ScanStartResult
import com.btsec.testtool.domain.usecase.VulnerabilityScanningUseCase
import com.btsec.testtool.presentation.feature.scanner.EmptyView
import com.btsec.testtool.presentation.feature.scanner.ErrorView
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
                title = { Text(stringResource(R.string.vuln_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.cd_navigate_up))
                    }
                }
            )
        }
    ) { padding ->
        when {
            uiState.isLoading -> {
                Box(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = stringResource(R.string.vuln_loading),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }
            uiState.error != null -> {
                Column(modifier = Modifier.padding(padding)) {
                    ErrorView(
                        error = uiState.error!!,
                        onRetry = { viewModel.retry() }
                    )
                }
            }
            else -> {
                VulnScannerContent(
                    padding = padding,
                    uiState = uiState,
                    onStartScan = { viewModel.startScan() },
                    onStopScan = { viewModel.stopScan() },
                    onVerify = { viewModel.verifyVulnerability(it) }
                )
            }
        }
    }
}

@Composable
private fun VulnScannerContent(
    padding: PaddingValues,
    uiState: VulnScannerUiState,
    onStartScan: () -> Unit,
    onStopScan: () -> Unit,
    onVerify: (String) -> Unit
) {
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
                    Text(stringResource(R.string.vuln_scan_title), style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))

                    Text(
                        stringResource(R.string.vuln_scan_description),
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (uiState.scanStatus != ScanStatus.RUNNING) {
                            FilledTonalButton(
                                onClick = onStartScan,
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.PlayArrow, contentDescription = "Start vulnerability scan")
                                Spacer(Modifier.width(4.dp))
                                Text(stringResource(R.string.vuln_scan_all))
                            }
                        } else {
                            OutlinedButton(
                                onClick = onStopScan,
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                            ) {
                                Icon(Icons.Default.Stop, contentDescription = "Stop vulnerability scan")
                                Spacer(Modifier.width(4.dp))
                                Text(stringResource(R.string.scanner_stop))
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
                        Text(stringResource(R.string.vuln_scanning_progress), style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(8.dp))

                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

                        Spacer(Modifier.height(4.dp))

                        uiState.scanProgress?.let { progress ->
                            Text(
                                stringResource(R.string.vuln_checking_progress, progress.vulnerabilitiesChecked, progress.totalVulnerabilities, progress.vulnerabilitiesFound),
                                style = MaterialTheme.typography.bodySmall
                            )
                            progress.currentVulnerability?.let { vuln ->
                                Text(
                                    stringResource(R.string.vuln_current, vuln.name),
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
        if (uiState.definitions.isEmpty()) {
            item {
                EmptyView(
                    message = stringResource(R.string.vuln_no_definitions),
                    icon = Icons.Default.BugReport
                )
            }
        } else {
            item {
                Text(stringResource(R.string.vuln_known_database), style = MaterialTheme.typography.titleMedium)
            }

            items(uiState.definitions) { def ->
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
                            Text(stringResource(R.string.vuln_cvss_label, def.cvssScore.toString()), style = MaterialTheme.typography.bodySmall)
                            Text(stringResource(R.string.vuln_year_label, def.yearDiscovered), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }

        // Discovered Vulnerabilities
        if (uiState.discoveredVulns.isNotEmpty()) {
            item {
                Text(
                    stringResource(R.string.vuln_discovered_title, uiState.discoveredVulns.size),
                    style = MaterialTheme.typography.titleMedium
                )
            }
            items(uiState.discoveredVulns) { vuln ->
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
                                    leadingIcon = { Icon(Icons.Default.CheckCircle, contentDescription = "Verified vulnerability", modifier = Modifier.size(16.dp)) }
                                )
                            }
                            AssistChip(
                                onClick = { onVerify(vuln.id) },
                                label = { Text("Verify") },
                                leadingIcon = { Icon(Icons.Default.FactCheck, contentDescription = "Verify vulnerability", modifier = Modifier.size(16.dp)) }
                            )
                        }
                    }
                }
            }
        } else if (uiState.scanStatus == ScanStatus.COMPLETED) {
            item {
                EmptyView(
                    message = stringResource(R.string.vuln_none_discovered),
                    icon = Icons.Default.CheckCircle
                )
            }
        }

        // Statistics
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(stringResource(R.string.fuzzer_stats_title), style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    val stats = uiState.statistics
                    if (stats != null) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                            StatItem(stringResource(R.string.vuln_critical), stats.criticalCount, Color.Red)
                            StatItem(stringResource(R.string.vuln_high), stats.highCount, Color(0xFFFF6D00))
                            StatItem(stringResource(R.string.vuln_medium), stats.mediumCount, Color(0xFFFFAB00))
                            StatItem(stringResource(R.string.vuln_low), stats.lowCount, Color(0xFF4CAF50))
                        }
                    } else {
                        Text(stringResource(R.string.vuln_no_scan_data), style = MaterialTheme.typography.bodySmall)
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
    private val vulnScanningUseCase: VulnerabilityScanningUseCase,
    private val scanningUseCase: com.btsec.testtool.domain.usecase.BluetoothScanningUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(VulnScannerUiState())
    val uiState: StateFlow<VulnScannerUiState> = _uiState.asStateFlow()

    init {
        _uiState.update { it.copy(isLoading = true) }
        viewModelScope.launch {
            vulnScanningUseCase.getScanStatus().collect { status ->
                _uiState.update { it.copy(scanStatus = status, isLoading = false) }
            }
        }
        viewModelScope.launch {
            vulnScanningUseCase.getScanProgress().collect { progress ->
                _uiState.update { it.copy(scanProgress = progress) }
            }
        }
        viewModelScope.launch {
            try {
                vulnScanningUseCase.getAllVulnerabilityDefinitions().collect { defs ->
                    _uiState.update { it.copy(definitions = defs, isLoading = false) }
                }
            } catch (e: Exception) {
                _uiState.update { it.copy(error = e.message ?: "Failed to load definitions", isLoading = false) }
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
            val device = scanningUseCase.getSelectedDevice()
            if (device == null) {
                _uiState.update { it.copy(error = "No device selected. Please scan and select a device first.") }
                return@launch
            }
            vulnScanningUseCase.startVulnerabilityScan(device)
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

    fun retry() {
        _uiState.update { it.copy(error = null, isLoading = true) }
        // Re-trigger loading by re-collecting flows (they're already active via init)
        _uiState.update { it.copy(isLoading = false) }
    }
}

data class VulnScannerUiState(
    val isLoading: Boolean = false,
    val error: String? = null,
    val scanStatus: ScanStatus = ScanStatus.PENDING,
    val scanProgress: ScanProgress? = null,
    val definitions: List<VulnerabilityDefinition> = emptyList(),
    val discoveredVulns: List<Vulnerability> = emptyList(),
    val statistics: VulnerabilityStatistics? = null
)
