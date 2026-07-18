/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.reports

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.Assessment
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.ExportFormat
import com.btsec.testtool.domain.repository.ReportConfig
import com.btsec.testtool.domain.repository.ReportsSummary
import com.btsec.testtool.domain.usecase.ReportGenerationUseCase
import com.btsec.testtool.presentation.feature.scanner.ErrorView
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportsScreen(onBack: () -> Unit) {
    val viewModel: ReportsViewModel = androidx.hilt.navigation.compose.hiltViewModel()
    val uiState by viewModel.uiState.collectAsState()

    var showGenerateDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Reports") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Navigate back")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showGenerateDialog = true }) {
                Icon(Icons.Default.Add, contentDescription = "Generate new report")
            }
        },
    ) { padding ->
        when {
            uiState.isLoading -> {
                Box(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator()
                }
            }
            uiState.error != null -> {
                Column(modifier = Modifier.padding(padding)) {
                    ErrorView(
                        error = uiState.error!!,
                        onRetry = { viewModel.retry() },
                    )
                }
            }
            else -> {
                ReportsContent(
                    padding = padding,
                    uiState = uiState,
                    onExport = { reportId, format -> viewModel.exportReport(reportId, format) },
                    onDelete = { viewModel.deleteReport(it) },
                    onArchive = { viewModel.archiveReport(it) },
                    showGenerateDialog = showGenerateDialog,
                    onDismissDialog = { showGenerateDialog = false },
                    onGenerate = { title, includeVulns, includeFuzzing, includeKeys ->
                        viewModel.generateReport(title, includeVulns, includeFuzzing, includeKeys)
                        showGenerateDialog = false
                    },
                )
            }
        }
    }
}

@Composable
private fun ReportsContent(
    padding: PaddingValues,
    uiState: ReportsUiState,
    onExport: (String, ExportFormat) -> Unit,
    onDelete: (String) -> Unit,
    onArchive: (String) -> Unit,
    showGenerateDialog: Boolean,
    onDismissDialog: () -> Unit,
    onGenerate: (String, Boolean, Boolean, Boolean) -> Unit,
) {
    LazyColumn(
        modifier =
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // Summary Card
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Report Summary", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))

                    val summary = uiState.summary
                    if (summary != null) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceEvenly,
                        ) {
                            StatChip("Total", summary.totalReports, Icons.Default.Description, "Total reports")
                            StatChip("Draft", summary.draftReports, Icons.Default.Edit, "Draft reports")
                            StatChip("Final", summary.finalReports, Icons.Default.CheckCircle, "Final reports")
                        }
                        Spacer(Modifier.height(8.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceEvenly,
                        ) {
                            Text(
                                "Critical Vulns: ${summary.criticalVulnerabilitiesTotal}",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color.Red,
                            )
                            Text(
                                "High Vulns: ${summary.highVulnerabilitiesTotal}",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFFFF6D00),
                            )
                            Text(
                                "Pending: ${summary.pendingActions}",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    } else {
                        Text("No report data available", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        // Report List
        if (uiState.reports.isEmpty()) {
            item {
                Box(
                    modifier = Modifier.fillMaxWidth().padding(48.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Outlined.Assessment,
                            contentDescription = "No reports available",
                            modifier = Modifier.size(64.dp),
                            tint = MaterialTheme.colorScheme.outline,
                        )
                        Spacer(Modifier.height(16.dp))
                        Text("No reports yet", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Generate your first security assessment report",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Spacer(Modifier.height(16.dp))
                        FilledTonalButton(onClick = { onGenerate("Bluetooth Security Assessment", true, true, true) }) {
                            Icon(Icons.Default.Add, contentDescription = "Generate first report")
                            Spacer(Modifier.width(4.dp))
                            Text("Generate Report")
                        }
                    }
                }
            }
        } else {
            items(uiState.reports, key = { it.id }) { report ->
                ReportCard(
                    report = report,
                    onExport = { format -> onExport(report.id, format) },
                    onDelete = { onDelete(report.id) },
                    onArchive = { onArchive(report.id) },
                )
            }
        }
    }

    // Generate Report Dialog
    if (showGenerateDialog) {
        GenerateReportDialog(
            onDismiss = onDismissDialog,
            onGenerate = onGenerate,
        )
    }
}

@Composable
private fun StatChip(
    label: String,
    count: Int,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    description: String,
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(icon, contentDescription = description, modifier = Modifier.size(24.dp), tint = MaterialTheme.colorScheme.primary)
        Text("$count", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Text(label, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun ReportCard(
    report: SecurityReport,
    onExport: (ExportFormat) -> Unit,
    onDelete: () -> Unit,
    onArchive: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusBadge(report.status)
                Spacer(Modifier.width(8.dp))
                Text(report.title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "Generated: ${report.generatedAt}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Devices: ${report.targetDevices.size} • Vulns: ${report.vulnerabilities.size}",
                style = MaterialTheme.typography.bodySmall,
            )

            Spacer(Modifier.height(8.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                FilledTonalButton(onClick = { onExport(ExportFormat.JSON) }, contentPadding = PaddingValues(horizontal = 8.dp)) {
                    Text("JSON", style = MaterialTheme.typography.labelSmall)
                }
                OutlinedButton(onClick = { onExport(ExportFormat.HTML) }, contentPadding = PaddingValues(horizontal = 8.dp)) {
                    Text("HTML", style = MaterialTheme.typography.labelSmall)
                }
                OutlinedButton(onClick = { onExport(ExportFormat.PDF) }, contentPadding = PaddingValues(horizontal = 8.dp)) {
                    Text("PDF", style = MaterialTheme.typography.labelSmall)
                }
                IconButton(onClick = onArchive) {
                    Icon(Icons.Default.Archive, contentDescription = "Archive report", modifier = Modifier.size(18.dp))
                }
                IconButton(onClick = onDelete) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = "Delete report",
                        modifier = Modifier.size(18.dp),
                        tint = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

@Composable
private fun StatusBadge(status: ReportStatus) {
    val (color, text) =
        when (status) {
            ReportStatus.DRAFT -> Color(0xFF9E9E9E) to "Draft"
            ReportStatus.REVIEW -> Color(0xFF2196F3) to "Review"
            ReportStatus.FINAL -> Color(0xFF4CAF50) to "Final"
            ReportStatus.ARCHIVED -> Color(0xFF795548) to "Archived"
        }
    Surface(shape = MaterialTheme.shapes.small, color = color.copy(alpha = 0.15f)) {
        Text(
            text,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Bold,
        )
    }
}

@Composable
private fun GenerateReportDialog(
    onDismiss: () -> Unit,
    onGenerate: (String, Boolean, Boolean, Boolean) -> Unit,
) {
    var title by remember { mutableStateOf("Bluetooth Security Assessment") }
    var includeVulns by remember { mutableStateOf(true) }
    var includeFuzzing by remember { mutableStateOf(true) }
    var includeKeys by remember { mutableStateOf(true) }
    val focusManager = LocalFocusManager.current

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Generate Report") },
        text = {
            Column {
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                    keyboardActions =
                        KeyboardActions(onDone = {
                            focusManager.clearFocus()
                            onGenerate(title, includeVulns, includeFuzzing, includeKeys)
                        }),
                    label = { Text("Report Title") },
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = includeVulns, onCheckedChange = { includeVulns = it })
                    Spacer(Modifier.width(8.dp))
                    Text("Include Vulnerabilities")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = includeFuzzing, onCheckedChange = { includeFuzzing = it })
                    Spacer(Modifier.width(8.dp))
                    Text("Include Fuzzing Results")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = includeKeys, onCheckedChange = { includeKeys = it })
                    Spacer(Modifier.width(8.dp))
                    Text("Include Key Extraction")
                }
            }
        },
        confirmButton = {
            FilledTonalButton(onClick = { onGenerate(title, includeVulns, includeFuzzing, includeKeys) }) {
                Text("Generate")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@HiltViewModel
class ReportsViewModel
    @Inject
    constructor(
        @ApplicationContext private val context: android.content.Context,
        private val reportGenerationUseCase: ReportGenerationUseCase,
    ) : ViewModel() {
        private val _uiState = MutableStateFlow(ReportsUiState())
        val uiState: StateFlow<ReportsUiState> = _uiState.asStateFlow()

        init {
            _uiState.update { it.copy(isLoading = true) }
            viewModelScope.launch {
                reportGenerationUseCase.getAllReports().collect { reports ->
                    _uiState.update { it.copy(reports = reports, isLoading = false) }
                }
            }
            viewModelScope.launch {
                reportGenerationUseCase.getReportsSummary().collect { summary ->
                    _uiState.update { it.copy(summary = summary, isLoading = false) }
                }
            }
        }

        fun generateReport(
            title: String,
            includeVulns: Boolean,
            includeFuzzing: Boolean,
            includeKeys: Boolean,
        ) {
            viewModelScope.launch {
                val config =
                    ReportConfig(
                        title = title,
                        includeVulnerabilities = includeVulns,
                        includeFuzzingResults = includeFuzzing,
                        includeKeyExtraction = includeKeys,
                    )
                reportGenerationUseCase.generateReport(config)
            }
        }

        fun exportReport(
            reportId: String,
            format: ExportFormat,
        ) {
            viewModelScope.launch {
                val exportDir = context.cacheDir.resolve("exports").apply { mkdirs() }
                val outputPath = File(exportDir, "report_$reportId.${format.name.lowercase()}").absolutePath
                when (format) {
                    ExportFormat.JSON -> reportGenerationUseCase.exportToJson(reportId, outputPath)
                    ExportFormat.HTML -> reportGenerationUseCase.exportToHtml(reportId, outputPath)
                    ExportFormat.PDF -> reportGenerationUseCase.exportToPdf(reportId, outputPath)
                    ExportFormat.CSV -> reportGenerationUseCase.exportToCsv(reportId, outputPath)
                    ExportFormat.XML -> reportGenerationUseCase.exportToJson(reportId, outputPath)
                    ExportFormat.MARKDOWN -> reportGenerationUseCase.exportToJson(reportId, outputPath)
                }
            }
        }

        fun deleteReport(reportId: String) {
            viewModelScope.launch { reportGenerationUseCase.deleteReport(reportId) }
        }

        fun archiveReport(reportId: String) {
            viewModelScope.launch { reportGenerationUseCase.archiveReport(reportId) }
        }

        fun retry() {
            _uiState.update { it.copy(error = null, isLoading = true) }
        }
    }

data class ReportsUiState(
    val isLoading: Boolean = false,
    val error: String? = null,
    val reports: List<SecurityReport> = emptyList(),
    val summary: ReportsSummary? = null,
)
