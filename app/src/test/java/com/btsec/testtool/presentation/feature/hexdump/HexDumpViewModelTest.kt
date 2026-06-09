/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.hexdump

import com.btsec.testtool.domain.model.HexDumpViewMode
import com.btsec.testtool.domain.usecase.HexDumpUseCase
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Tests for [HexDumpViewModel].
 *
 * Validates state management, view mode switching, search, and copy operations.
 * All testing is conducted under AUTHORIZED security testing conditions.
 */
class HexDumpViewModelTest {

    private lateinit var viewModel: HexDumpViewModel
    private lateinit var useCase: HexDumpUseCase

    @BeforeEach
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        useCase = HexDumpUseCase()
        viewModel = HexDumpViewModel(useCase)
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Nested
    @DisplayName("loadCharacteristicData")
    inner class LoadCharacteristicData {

        @Test
        @DisplayName("should transition from Loading to Success")
        fun loadingToSuccess() = runTest {
            val data = "Hello".toByteArray()

            viewModel.loadCharacteristicData(
                data = data,
                characteristicUuid = "test-uuid",
                serviceUuid = "svc-uuid"
            )

            val state = viewModel.uiState.value
            assertThat(state).isInstanceOf(HexDumpUiState.Success::class.java)
        }

        @Test
        @DisplayName("should populate entries in success state")
        fun populatesEntries() = runTest {
            val data = "Hello World!".toByteArray()

            viewModel.loadCharacteristicData(
                data = data,
                characteristicUuid = "char-uuid",
                serviceUuid = "svc-uuid"
            )

            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.result.entries).isNotEmpty()
            assertThat(state.result.size).isEqualTo(12)
            assertThat(state.displayEntries).isEqualTo(state.result.entries)
        }

        @Test
        @DisplayName("should handle empty data")
        fun emptyData() = runTest {
            viewModel.loadCharacteristicData(
                data = byteArrayOf(),
                characteristicUuid = "char-uuid",
                serviceUuid = "svc-uuid"
            )

            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.result.entries).isEmpty()
            assertThat(state.result.size).isEqualTo(0)
        }
    }

    @Nested
    @DisplayName("setViewMode")
    inner class SetViewMode {

        @BeforeEach
        fun loadData() = runTest {
            viewModel.loadCharacteristicData(
                data = "test".toByteArray(),
                characteristicUuid = "uuid",
                serviceUuid = "svc"
            )
        }

        @Test
        @DisplayName("should default to HEX view mode")
        fun defaultHex() {
            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.viewMode).isEqualTo(HexDumpViewMode.HEX)
        }

        @Test
        @DisplayName("should switch to TEXT view mode")
        fun switchToText() {
            viewModel.setViewMode(HexDumpViewMode.TEXT)

            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.viewMode).isEqualTo(HexDumpViewMode.TEXT)
        }

        @Test
        @DisplayName("should switch to BINARY view mode")
        fun switchToBinary() {
            viewModel.setViewMode(HexDumpViewMode.BINARY)

            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.viewMode).isEqualTo(HexDumpViewMode.BINARY)
        }

        @Test
        @DisplayName("should switch back to HEX")
        fun switchBackToHex() {
            viewModel.setViewMode(HexDumpViewMode.TEXT)
            viewModel.setViewMode(HexDumpViewMode.HEX)

            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.viewMode).isEqualTo(HexDumpViewMode.HEX)
        }
    }

    @Nested
    @DisplayName("search")
    inner class Search {

        @BeforeEach
        fun loadData() = runTest {
            // 32 bytes = 2 lines of 16
            val data = ByteArray(32) { (it + 0x41).toByte() }
            viewModel.loadCharacteristicData(
                data = data,
                characteristicUuid = "uuid",
                serviceUuid = "svc"
            )
        }

        @Test
        @DisplayName("should filter entries by search query")
        fun filterEntries() {
            viewModel.search("41")

            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.displayEntries.size).isAtMost(2)
            assertThat(state.searchQuery).isEqualTo("41")
        }

        @Test
        @DisplayName("should return all entries for blank query")
        fun blankQuery() {
            viewModel.search("41")
            viewModel.search("")

            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.displayEntries).hasSize(2)
        }

        @Test
        @DisplayName("should update search query in state")
        fun updateQuery() {
            viewModel.search("test query")

            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.searchQuery).isEqualTo("test query")
        }
    }

    @Nested
    @DisplayName("clipboard operations")
    inner class ClipboardOperations {

        @BeforeEach
        fun loadData() = runTest {
            viewModel.loadCharacteristicData(
                data = "Hello".toByteArray(),
                characteristicUuid = "uuid",
                serviceUuid = "svc"
            )
        }

        @Test
        @DisplayName("should generate full dump for copy")
        fun fullDumpCopy() {
            val dump = viewModel.getFullDumpForCopy()

            assertThat(dump).contains("Characteristic: uuid")
            assertThat(dump).contains("Size: 5 bytes")
        }

        @Test
        @DisplayName("should generate raw hex for copy")
        fun rawHexCopy() {
            val hex = viewModel.getRawHexForCopy()

            assertThat(hex).isEqualTo("48656c6c6f")
        }

        @Test
        @DisplayName("should track copied state")
        fun copiedState() {
            viewModel.onCopiedToClipboard()

            val state = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(state.copiedToClipboard).isTrue()

            viewModel.resetCopiedState()

            val stateAfter = viewModel.uiState.value as HexDumpUiState.Success
            assertThat(stateAfter.copiedToClipboard).isFalse()
        }
    }

    @Nested
    @DisplayName("format helpers")
    inner class FormatHelpers {

        @BeforeEach
        fun loadData() = runTest {
            viewModel.loadCharacteristicData(
                data = byteArrayOf(0x0F, 0xFF.toByte()),
                characteristicUuid = "uuid",
                serviceUuid = "svc"
            )
        }

        @Test
        @DisplayName("should generate binary representation")
        fun binaryRepresentation() {
            val binary = viewModel.getBinaryRepresentation()

            assertThat(binary).isEqualTo("00001111 11111111")
        }

        @Test
        @DisplayName("should generate text representation")
        fun textRepresentation() = runTest {
            viewModel.loadCharacteristicData(
                data = "AB".toByteArray(),
                characteristicUuid = "uuid",
                serviceUuid = "svc"
            )

            val text = viewModel.getTextRepresentation()

            assertThat(text).isEqualTo("AB")
        }
    }
}
