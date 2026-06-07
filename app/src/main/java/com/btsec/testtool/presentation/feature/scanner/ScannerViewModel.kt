/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.scanner

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
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
 * ViewModel for the Scanner screen.
 *
 * Manages scanning state, discovered devices, and error handling.
 * All UI state survives process death via StateFlow.
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
                    _uiState.value = _uiState.value.copy(isScanning = true, error = null)
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
        _uiState.value = _uiState.value.copy(isScanning = false)
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
    val error: String? = null
)
