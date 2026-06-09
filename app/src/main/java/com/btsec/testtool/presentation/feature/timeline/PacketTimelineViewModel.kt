/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.timeline

import androidx.lifecycle.ViewModel
import com.btsec.testtool.domain.model.CapturedPacket
import com.btsec.testtool.domain.model.PacketDirection
import com.btsec.testtool.domain.model.PacketFilter
import com.btsec.testtool.domain.model.PacketStats
import com.btsec.testtool.domain.model.PacketType
import com.btsec.testtool.domain.usecase.PacketCaptureUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import javax.inject.Inject

/**
 * UI state for the Packet Timeline screen.
 * Used in AUTHORIZED security testing visualization.
 */
data class PacketTimelineUiState(
    val packets: List<CapturedPacket> = emptyList(),
    val filteredPackets: List<CapturedPacket> = emptyList(),
    val selectedPacketId: String? = null,
    val filter: PacketFilter = PacketFilter(),
    val stats: PacketStats = PacketStats(
        totalPackets = 0,
        sentCount = 0,
        receivedCount = 0,
        typeDistribution = emptyMap(),
        averageSize = 0.0,
        durationMs = 0L
    )
)

/**
 * ViewModel for the BLE Packet Timeline Visualization screen.
 *
 * Manages sample packet data, filtering, selection, and statistics
 * for AUTHORIZED security testing packet analysis.
 */
@HiltViewModel
class PacketTimelineViewModel @Inject constructor(
    private val packetCaptureUseCase: PacketCaptureUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(PacketTimelineUiState())
    val uiState: StateFlow<PacketTimelineUiState> = _uiState.asStateFlow()

    init {
        loadPackets()
    }

    /**
     * Load sample packets for demonstration.
     * In production, this would receive packets from a capture engine.
     */
    fun loadPackets() {
        val samplePackets = generateSamplePackets()
        val stats = packetCaptureUseCase.computeStats(samplePackets)
        _uiState.update { state ->
            state.copy(
                packets = samplePackets,
                filteredPackets = samplePackets,
                stats = stats,
                filter = PacketFilter(),
                selectedPacketId = null
            )
        }
    }

    /**
     * Select a packet to view its details.
     */
    fun selectPacket(packetId: String?) {
        _uiState.update { it.copy(selectedPacketId = packetId) }
    }

    /**
     * Clear the current packet selection.
     */
    fun clearSelection() {
        _uiState.update { it.copy(selectedPacketId = null) }
    }

    /**
     * Apply a filter to the packet list.
     */
    fun applyFilter(filter: PacketFilter) {
        _uiState.update { state ->
            val filtered = packetCaptureUseCase.filterPackets(state.packets, filter)
            state.copy(
                filter = filter,
                filteredPackets = filtered,
                selectedPacketId = null
            )
        }
    }

    /**
     * Update the type filter while preserving other filter values.
     */
    fun updateTypeFilter(type: PacketType?) {
        val current = _uiState.value.filter
        applyFilter(current.copy(type = type))
    }

    /**
     * Update the direction filter while preserving other filter values.
     */
    fun updateDirectionFilter(direction: PacketDirection?) {
        val current = _uiState.value.filter
        applyFilter(current.copy(direction = direction))
    }

    /**
     * Update the search query while preserving other filter values.
     */
    fun updateSearchQuery(query: String?) {
        val current = _uiState.value.filter
        applyFilter(current.copy(searchQuery = query))
    }

    private fun generateSamplePackets(): List<CapturedPacket> {
        val baseTime = System.currentTimeMillis()
        val packets = mutableListOf<CapturedPacket>()

        val sampleData = listOf(
            Triple(PacketType.ATT, PacketDirection.SENT, byteArrayOf(0x02, 0x00, 0x0A, 0x00)),
            Triple(PacketType.ATT, PacketDirection.RECEIVED, byteArrayOf(0x01, 0x0A, 0x00, 0x0B, 0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F)),
            Triple(PacketType.L2CAP, PacketDirection.SENT, byteArrayOf(0x01, 0x04, 0x00, 0x00, 0x01, 0x00)),
            Triple(PacketType.L2CAP, PacketDirection.RECEIVED, byteArrayOf(0x02, 0x04, 0x00, 0x00, 0x01, 0x00)),
            Triple(PacketType.SMP, PacketDirection.SENT, byteArrayOf(0x01, 0x04)),
            Triple(PacketType.SMP, PacketDirection.RECEIVED, byteArrayOf(0x02, 0x00)),
            Triple(PacketType.HCI, PacketDirection.SENT, byteArrayOf(0x01, 0x06, 0x04)),
            Triple(PacketType.HCI, PacketDirection.RECEIVED, byteArrayOf(0x04, 0x0E, 0x04, 0x01, 0x06, 0x04, 0x00)),
            Triple(PacketType.ATT, PacketDirection.SENT, byteArrayOf(0x12, 0x01, 0x00, 0x0A, 0x00, 0x54, 0x65, 0x73, 0x74)),
            Triple(PacketType.ATT, PacketDirection.RECEIVED, byteArrayOf(0x13, 0x00)),
            Triple(PacketType.L2CAP, PacketDirection.SENT, byteArrayOf(0x06, 0x01, 0x0A, 0x00, 0x14, 0x00, 0x41, 0x42)),
            Triple(PacketType.L2CAP, PacketDirection.RECEIVED, byteArrayOf(0x06, 0x02, 0x0A, 0x00, 0x14, 0x00)),
            Triple(PacketType.SMP, PacketDirection.SENT, byteArrayOf(0x03)),
            Triple(PacketType.SMP, PacketDirection.RECEIVED, byteArrayOf(0x04, 0x00, 0x01, 0x02, 0x03, 0x04)),
            Triple(PacketType.ATT, PacketDirection.SENT, byteArrayOf(0x52, 0x0B, 0x00, 0xFF.toByte())),
            Triple(PacketType.ATT, PacketDirection.RECEIVED, byteArrayOf(0x53, 0x0B, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06)),
            Triple(PacketType.HCI, PacketDirection.SENT, byteArrayOf(0x01, 0x0C, 0x04, 0x01)),
            Triple(PacketType.HCI, PacketDirection.RECEIVED, byteArrayOf(0x04, 0x0E, 0x04, 0x01, 0x0C, 0x04, 0x00))
        )

        sampleData.forEachIndexed { index, (type, direction, data) ->
            packets.add(
                CapturedPacket(
                    id = "sample-${index}",
                    timestamp = baseTime + (index * 150L),
                    type = type,
                    direction = direction,
                    data = data,
                    size = data.size,
                    source = if (direction == PacketDirection.SENT) "Local" else "Remote",
                    destination = if (direction == PacketDirection.SENT) "Remote" else "Local"
                )
            )
        }

        return packets
    }
}
