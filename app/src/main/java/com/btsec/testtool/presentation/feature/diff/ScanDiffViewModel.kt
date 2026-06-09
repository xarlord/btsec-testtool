/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.diff

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.DeviceDiff
import com.btsec.testtool.domain.model.DiffType
import com.btsec.testtool.domain.model.ScanDiffResult
import com.btsec.testtool.domain.usecase.BluetoothScanningUseCase
import com.btsec.testtool.domain.usecase.ScanDiffUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ViewModel for the Scan Diff screen.
 *
 * Manages scan session selection and delegates diff computation
 * to [ScanDiffUseCase]. All operations are for AUTHORIZED security testing only.
 */
@HiltViewModel
class ScanDiffViewModel @Inject constructor(
    private val scanDiffUseCase: ScanDiffUseCase,
    private val scanningUseCase: BluetoothScanningUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(ScanDiffUiState())
    val uiState: StateFlow<ScanDiffUiState> = _uiState.asStateFlow()

    init {
        loadScanSnapshots()
    }

    /**
     * Load available scan sessions for the dropdown selectors.
     */
    private fun loadScanSnapshots() {
        viewModelScope.launch {
            scanningUseCase.getScanResults().collect { devices ->
                _uiState.value = _uiState.value.copy(
                    availableDevices = devices
                )
            }
        }
    }

    /**
     * Run the diff computation using the selected baseline and comparison devices.
     */
    fun computeDiff(
        baselineDevices: List<BluetoothDevice>,
        comparisonDevices: List<BluetoothDevice>
    ) {
        val result = scanDiffUseCase.diffScans(
            baseline = baselineDevices,
            comparison = comparisonDevices,
            baselineScanId = "session-baseline",
            comparisonScanId = "session-comparison"
        )
        _uiState.value = _uiState.value.copy(
            diffResult = result,
            filteredDevices = filterDevices(result, _uiState.value.selectedFilter)
        )
    }

    /**
     * Change the active filter and re-apply to current results.
     */
    fun setFilter(filter: DiffTypeFilter) {
        val current = _uiState.value
        val filtered = current.diffResult?.let { filterDevices(it, filter) } ?: emptyList()
        _uiState.value = current.copy(
            selectedFilter = filter,
            filteredDevices = filtered
        )
    }

    /**
     * Reset state for a new comparison.
     */
    fun reset() {
        _uiState.value = ScanDiffUiState()
    }

    private fun filterDevices(
        result: ScanDiffResult,
        filter: DiffTypeFilter
    ): List<DeviceDiff> {
        return when (filter) {
            DiffTypeFilter.ALL -> result.added + result.removed + result.modified + result.unchanged
            DiffTypeFilter.ADDED -> result.added
            DiffTypeFilter.REMOVED -> result.removed
            DiffTypeFilter.MODIFIED -> result.modified
        }
    }
}

/**
 * Filter options for the diff list.
 */
enum class DiffTypeFilter {
    ALL, ADDED, REMOVED, MODIFIED
}

/**
 * UI state for the Scan Diff screen.
 */
data class ScanDiffUiState(
    val availableDevices: List<BluetoothDevice> = emptyList(),
    val diffResult: ScanDiffResult? = null,
    val filteredDevices: List<DeviceDiff> = emptyList(),
    val selectedFilter: DiffTypeFilter = DiffTypeFilter.ALL,
    val isLoading: Boolean = false,
    val error: String? = null
)
