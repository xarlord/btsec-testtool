/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.keys

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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import com.btsec.testtool.domain.usecase.KeyExtractionStartResult
import com.btsec.testtool.domain.usecase.KeyExtractionUseCase
import com.btsec.testtool.presentation.feature.scanner.EmptyView
import com.btsec.testtool.presentation.feature.scanner.ErrorView
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyExtractionScreen(
    authId: String,
    onBack: () -> Unit
) {
    val viewModel: KeyExtractionViewModel = androidx.hilt.navigation.compose.hiltViewModel()
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Key Extraction") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Navigate back")
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
            uiState.extractionStatus == ExtractionStatus.RUNNING && uiState.results.isEmpty() -> {
                // Show content with progress since extraction has config + progress
                KeyExtractionContent(
                    padding = padding,
                    uiState = uiState,
                    onUpdateKeyType = { viewModel.updateKeyType(it) },
                    onUpdateMethod = { viewModel.updateMethod(it) },
                    onStart = { viewModel.startExtraction() },
                    onCancel = { viewModel.cancelExtraction() }
                )
            }
            else -> {
                KeyExtractionContent(
                    padding = padding,
                    uiState = uiState,
                    onUpdateKeyType = { viewModel.updateKeyType(it) },
                    onUpdateMethod = { viewModel.updateMethod(it) },
                    onStart = { viewModel.startExtraction() },
                    onCancel = { viewModel.cancelExtraction() }
                )
            }
        }
    }
}

@Composable
private fun KeyExtractionContent(
    padding: PaddingValues,
    uiState: KeyExtractionUiState,
    onUpdateKeyType: (KeyType) -> Unit,
    onUpdateMethod: (ExtractionMethod) -> Unit,
    onStart: () -> Unit,
    onCancel: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Extraction Configuration
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Key Extraction Configuration", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(12.dp))

                    // Key Type Selector
                    var keyTypeExpanded by remember { mutableStateOf(false) }
                    ExposedDropdownMenuBox(expanded = keyTypeExpanded, onExpandedChange = { keyTypeExpanded = it }) {
                        OutlinedTextField(
                            value = uiState.selectedKeyType.name,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Key Type") },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = keyTypeExpanded) },
                            modifier = Modifier.fillMaxWidth().menuAnchor()
                        )
                        ExposedDropdownMenu(expanded = keyTypeExpanded, onDismissRequest = { keyTypeExpanded = false }) {
                            KeyType.entries.forEach { kt ->
                                DropdownMenuItem(
                                    text = { Text(kt.name) },
                                    onClick = { onUpdateKeyType(kt); keyTypeExpanded = false }
                                )
                            }
                        }
                    }

                    Spacer(Modifier.height(8.dp))

                    // Extraction Method Selector
                    var methodExpanded by remember { mutableStateOf(false) }
                    ExposedDropdownMenuBox(expanded = methodExpanded, onExpandedChange = { methodExpanded = it }) {
                        OutlinedTextField(
                            value = uiState.selectedMethod.name.replace("_", " "),
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Extraction Method") },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = methodExpanded) },
                            modifier = Modifier.fillMaxWidth().menuAnchor()
                        )
                        ExposedDropdownMenu(expanded = methodExpanded, onDismissRequest = { methodExpanded = false }) {
                            ExtractionMethod.entries.forEach { m ->
                                DropdownMenuItem(
                                    text = { Text(m.name.replace("_", " ")) },
                                    onClick = { onUpdateMethod(m); methodExpanded = false }
                                )
                            }
                        }
                    }

                    Spacer(Modifier.height(12.dp))

                    // Start/Cancel Buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (uiState.extractionStatus != ExtractionStatus.RUNNING) {
                            FilledTonalButton(
                                onClick = onStart,
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.VpnKey, contentDescription = "Start key extraction")
                                Spacer(Modifier.width(4.dp))
                                Text("Extract Key")
                            }
                        } else {
                            OutlinedButton(
                                onClick = onCancel,
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                            ) {
                                Icon(Icons.Default.Cancel, contentDescription = "Cancel key extraction")
                                Spacer(Modifier.width(4.dp))
                                Text("Cancel")
                            }
                        }
                    }
                }
            }
        }

        // Step Progress
        if (uiState.extractionStatus == ExtractionStatus.RUNNING) {
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Extraction Progress", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))

                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

                        Spacer(Modifier.height(8.dp))

                        ExtractionStep.entries.forEach { step ->
                            val isActive = step == uiState.currentStep
                            val isDone = step == ExtractionStep.COMPLETED && uiState.extractionStatus == ExtractionStatus.COMPLETED
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    when {
                                        isDone -> Icons.Default.CheckCircle
                                        isActive -> Icons.Default.Sync
                                        else -> Icons.Default.RadioButtonUnchecked
                                    },
                                    contentDescription = when {
                                        isDone -> "Step ${step.name} completed"
                                        isActive -> "Step ${step.name} in progress"
                                        else -> "Step ${step.name} pending"
                                    },
                                    tint = when {
                                        isDone -> Color(0xFF4CAF50)
                                        isActive -> MaterialTheme.colorScheme.primary
                                        else -> MaterialTheme.colorScheme.outline
                                    },
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    step.name.replace("_", " ").lowercase().replaceFirstChar { it.uppercase() },
                                    color = if (isActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                                )
                            }
                        }
                    }
                }
            }
        }

        // Encryption Analysis
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Encryption Analysis", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Encryption:")
                        Text(if (uiState.encryptionAnalysis?.encryptionEnabled == true) "Enabled" else "Disabled")
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Key Size:")
                        Text("${uiState.encryptionAnalysis?.encryptionKeySize ?: 128} bits")
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Secure Connections:")
                        Text(if (uiState.encryptionAnalysis?.supportsSecureConnections == true) "Yes" else "No")
                    }

                    if (uiState.encryptionAnalysis?.pairingMethod != null) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Pairing Method:")
                            Text(uiState.encryptionAnalysis!!.pairingMethod!!.name.replace("_", " "))
                        }
                    }
                }
            }
        }

        // Results
        if (uiState.results.isEmpty() && uiState.extractionStatus == ExtractionStatus.COMPLETED) {
            item {
                EmptyView(
                    message = "No keys were extracted. Try a different extraction method or key type.",
                    icon = Icons.Default.VpnKey
                )
            }
        } else if (uiState.results.isNotEmpty()) {
            item { Text("Extraction Results", style = MaterialTheme.typography.titleMedium) }
            items(uiState.results) { result ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            if (result.extracted) Icons.Default.CheckCircle else Icons.Default.Cancel,
                            contentDescription = if (result.extracted) "Key successfully extracted" else "Key extraction failed",
                            tint = if (result.extracted) Color(0xFF4CAF50) else MaterialTheme.colorScheme.outline
                        )
                        Spacer(Modifier.width(12.dp))
                        Column {
                            Text(result.keyType.name, style = MaterialTheme.typography.titleSmall)
                            Text(
                                "Method: ${result.method.name.replace("_", " ")}",
                                style = MaterialTheme.typography.bodySmall
                            )
                            Text(
                                "Confidence: ${result.confidence.name}",
                                style = MaterialTheme.typography.bodySmall
                            )
                            if (result.notes != null) {
                                Text(
                                    result.notes!!,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@HiltViewModel
class KeyExtractionViewModel @Inject constructor(
    private val keyExtractionUseCase: KeyExtractionUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(KeyExtractionUiState())
    val uiState: StateFlow<KeyExtractionUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            keyExtractionUseCase.getExtractionStatus().collect { status ->
                _uiState.update { it.copy(extractionStatus = status) }
            }
        }
        viewModelScope.launch {
            keyExtractionUseCase.getAllExtractionResults().collect { results ->
                _uiState.update { it.copy(results = results) }
            }
        }
    }

    fun updateKeyType(keyType: KeyType) {
        _uiState.update { it.copy(selectedKeyType = keyType) }
    }

    fun updateMethod(method: ExtractionMethod) {
        _uiState.update { it.copy(selectedMethod = method) }
    }

    fun startExtraction() {
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
            keyExtractionUseCase.extractKey(
                device = placeholderDevice,
                keyType = _uiState.value.selectedKeyType,
                method = _uiState.value.selectedMethod
            )

            // Load encryption analysis
            val analysis = keyExtractionUseCase.analyzeEncryptionStrength(placeholderDevice)
            _uiState.update { it.copy(encryptionAnalysis = analysis) }
        }
    }

    fun cancelExtraction() {
        viewModelScope.launch { keyExtractionUseCase.cancelExtraction() }
    }

    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }
}

data class KeyExtractionUiState(
    val selectedKeyType: KeyType = KeyType.LTK,
    val selectedMethod: ExtractionMethod = ExtractionMethod.PASSIVE_MONITORING,
    val extractionStatus: ExtractionStatus = ExtractionStatus.PENDING,
    val currentStep: ExtractionStep = ExtractionStep.INITIALIZING,
    val results: List<KeyExtractionResult> = emptyList(),
    val encryptionAnalysis: EncryptionAnalysis? = null,
    val error: String? = null
)
