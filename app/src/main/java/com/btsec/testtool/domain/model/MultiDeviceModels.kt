/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

enum class DeviceScanState {
    QUEUED, CONNECTING, CONNECTED, SCANNING, TESTING, COMPLETED, FAILED, CANCELLED
}

data class ParallelScanTarget(
    val deviceAddress: String,
    val deviceName: String?,
    val priority: ScanPriority,
    val state: DeviceScanState = DeviceScanState.QUEUED,
    val progress: Float = 0f, // 0.0-1.0
    val assignedSlot: Int = -1, // Connection slot (0 to maxConnections-1)
    val error: String? = null,
    val startTime: Long? = null,
    val endTime: Long? = null
)

enum class ScanPriority { LOW, NORMAL, HIGH, CRITICAL }

data class ParallelScanConfig(
    val maxConcurrentConnections: Int = 4,
    val scanTimeoutMs: Long = 30000,
    val testTimeoutMs: Long = 60000,
    val retryCount: Int = 2,
    val retryDelayMs: Long = 5000,
    val stopOnFirstCritical: Boolean = false,
    val includeServiceDiscovery: Boolean = true,
    val includeFuzzing: Boolean = false,
    val maxConnectionsPerSlot: Int = 10 // Rotate devices through slots
)

data class ParallelScanResult(
    val target: ParallelScanTarget,
    val scanDurationMs: Long,
    val servicesFound: Int,
    val vulnerabilitiesFound: Int,
    val criticalFindings: Int,
    val highFindings: Int,
    val testData: String? = null // JSON blob of results
)

data class ParallelScanSession(
    val id: String,
    val config: ParallelScanConfig,
    val targets: List<ParallelScanTarget>,
    val results: List<ParallelScanResult>,
    val activeSlots: List<String>, // device addresses currently in slots
    val totalDurationMs: Long,
    val completedCount: Int,
    val failedCount: Int,
    val cancelledCount: Int
)

data class ConnectionPoolStatus(
    val totalSlots: Int,
    val activeSlots: Int,
    val queuedDevices: Int,
    val completedDevices: Int,
    val slotDetails: List<ConnectionSlot>
)

data class ConnectionSlot(
    val slotIndex: Int,
    val deviceAddress: String?,
    val state: DeviceScanState,
    val connectedAt: Long?,
    val devicesProcessed: Int
)
