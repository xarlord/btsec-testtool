/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.hexdump

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.btsec.testtool.domain.model.HexDumpEntry
import com.btsec.testtool.domain.model.HexDumpResult
import com.btsec.testtool.domain.model.HexDumpViewMode
import com.btsec.testtool.domain.usecase.HexDumpUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Sealed class representing the UI state for the Hex Dump screen.
 */
sealed class HexDumpUiState {
    /** Initial loading state. */
    data object Loading : HexDumpUiState()

    /** Successfully loaded hex dump data. */
    data class Success(
        val result: HexDumpResult,
        val displayEntries: List<HexDumpEntry>,
        val viewMode: HexDumpViewMode = HexDumpViewMode.HEX,
        val searchQuery: String = "",
        val copiedToClipboard: Boolean = false,
    ) : HexDumpUiState()

    /** Error state. */
    data class Error(
        val message: String,
    ) : HexDumpUiState()
}

/**
 * ViewModel for the Hex Dump Viewer screen.
 *
 * Manages hex dump generation, view mode toggling, search, and clipboard operations.
 * All operations are performed within the context of AUTHORIZED security testing.
 */
@HiltViewModel
class HexDumpViewModel
    @Inject
    constructor(
        private val hexDumpUseCase: HexDumpUseCase,
    ) : ViewModel() {
        private val _uiState = MutableStateFlow<HexDumpUiState>(HexDumpUiState.Loading)
        val uiState: StateFlow<HexDumpUiState> = _uiState.asStateFlow()

        private var currentResult: HexDumpResult? = null

        /**
         * Load characteristic data and generate hex dump.
         *
         * @param data Raw bytes from the characteristic value
         * @param characteristicUuid UUID of the characteristic
         * @param serviceUuid UUID of the service
         */
        fun loadCharacteristicData(
            data: ByteArray,
            characteristicUuid: String,
            serviceUuid: String,
        ) {
            viewModelScope.launch {
                try {
                    val result =
                        hexDumpUseCase.generateHexDump(
                            data = data,
                            characteristicUuid = characteristicUuid,
                            serviceUuid = serviceUuid,
                        )
                    currentResult = result
                    _uiState.value =
                        HexDumpUiState.Success(
                            result = result,
                            displayEntries = result.entries,
                        )
                } catch (e: Exception) {
                    _uiState.value =
                        HexDumpUiState.Error(
                            message = e.message ?: "Failed to generate hex dump",
                        )
                }
            }
        }

        /**
         * Set the view mode (Hex, Text, Binary).
         */
        fun setViewMode(mode: HexDumpViewMode) {
            val currentState = _uiState.value
            if (currentState is HexDumpUiState.Success) {
                _uiState.value = currentState.copy(viewMode = mode)
            }
        }

        /**
         * Search within the hex dump.
         */
        fun search(query: String) {
            val currentState = _uiState.value
            if (currentState is HexDumpUiState.Success) {
                val result = currentResult ?: return
                val filtered =
                    if (query.isBlank()) {
                        result.entries
                    } else {
                        hexDumpUseCase.searchInDump(result.entries, query)
                    }
                _uiState.value =
                    currentState.copy(
                        searchQuery = query,
                        displayEntries = filtered,
                    )
            }
        }

        /**
         * Get the full dump as a formatted string for clipboard copy.
         */
        fun getFullDumpForCopy(): String {
            val result = currentResult ?: return ""
            return hexDumpUseCase.formatFullDump(result)
        }

        /**
         * Get the raw hex string for clipboard copy.
         */
        fun getRawHexForCopy(): String {
            val result = currentResult ?: return ""
            return hexDumpUseCase.formatAsRawHex(result.value)
        }

        /**
         * Get binary representation for display/copy.
         */
        fun getBinaryRepresentation(): String {
            val result = currentResult ?: return ""
            return hexDumpUseCase.formatAsBinary(result.value)
        }

        /**
         * Get text representation for display/copy.
         */
        fun getTextRepresentation(): String {
            val result = currentResult ?: return ""
            return hexDumpUseCase.formatAsText(result.value)
        }

        /**
         * Mark that content has been copied to clipboard.
         */
        fun onCopiedToClipboard() {
            val currentState = _uiState.value
            if (currentState is HexDumpUiState.Success) {
                _uiState.value = currentState.copy(copiedToClipboard = true)
            }
        }

        /**
         * Reset the copied state.
         */
        fun resetCopiedState() {
            val currentState = _uiState.value
            if (currentState is HexDumpUiState.Success) {
                _uiState.value = currentState.copy(copiedToClipboard = false)
            }
        }
    }
