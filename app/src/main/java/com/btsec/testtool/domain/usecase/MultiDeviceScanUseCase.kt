/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.ConnectionPoolStatus
import com.btsec.testtool.domain.model.ConnectionSlot
import com.btsec.testtool.domain.model.DeviceScanState
import com.btsec.testtool.domain.model.ParallelScanConfig
import com.btsec.testtool.domain.model.ParallelScanResult
import com.btsec.testtool.domain.model.ParallelScanSession
import com.btsec.testtool.domain.model.ParallelScanTarget
import com.btsec.testtool.domain.model.ScanPriority
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for managing multi-device parallel BLE scanning.
 *
 * Manages a connection pool of up to [ParallelScanConfig.maxConcurrentConnections]
 * concurrent GATT connections, scheduling scan targets across available slots
 * and tracking progress.
 *
 * All scanning operations require valid AUTHORIZATION and consent.
 */
@Singleton
class MultiDeviceScanUseCase @Inject constructor() {

    /**
     * Create a new parallel scan session from the given targets and configuration.
     * Targets are sorted by priority and assigned to available connection slots.
     */
    fun createSession(
        targets: List<ParallelScanTarget>,
        config: ParallelScanConfig
    ): ParallelScanSession {
        val sorted = sortTargetsByPriority(targets)
        val assigned = assignSlots(sorted, config.maxConcurrentConnections)
        val activeSlots = assigned
            .filter { it.assignedSlot >= 0 }
            .map { it.deviceAddress }

        return ParallelScanSession(
            id = UUID.randomUUID().toString(),
            config = config,
            targets = assigned,
            results = emptyList(),
            activeSlots = activeSlots,
            totalDurationMs = 0L,
            completedCount = 0,
            failedCount = 0,
            cancelledCount = 0
        )
    }

    /**
     * Assign slot indices 0..maxSlots-1 to the first N targets.
     * Remaining targets stay QUEUED with slot -1.
     * Targets should already be sorted by priority before calling this.
     */
    fun assignSlots(
        targets: List<ParallelScanTarget>,
        maxSlots: Int
    ): List<ParallelScanTarget> {
        return targets.mapIndexed { index, target ->
            if (index < maxSlots) {
                target.copy(assignedSlot = index)
            } else {
                target
            }
        }
    }

    /**
     * Find the next QUEUED target in the session and assign it to the freed slot.
     * Returns null if no queued targets remain.
     */
    fun getNextTarget(
        session: ParallelScanSession,
        freedSlot: Int
    ): ParallelScanTarget? {
        return session.targets
            .firstOrNull { it.state == DeviceScanState.QUEUED && it.assignedSlot < 0 }
            ?.copy(assignedSlot = freedSlot)
    }

    /**
     * Return a copy of the target with an updated state.
     */
    fun updateTargetState(
        target: ParallelScanTarget,
        newState: DeviceScanState
    ): ParallelScanTarget {
        return target.copy(state = newState)
    }

    /**
     * Compute overall progress as a fraction (0.0 to 1.0).
     * Progress is the ratio of terminal states (COMPLETED, FAILED, CANCELLED)
     * to total targets.
     */
    fun computeProgress(session: ParallelScanSession): Float {
        if (session.targets.isEmpty()) return 0f
        val terminal = session.targets.count {
            it.state == DeviceScanState.COMPLETED ||
                it.state == DeviceScanState.FAILED ||
                it.state == DeviceScanState.CANCELLED
        }
        return terminal.toFloat() / session.targets.size
    }

    /**
     * Compute the current connection pool status from the session state.
     */
    fun computePoolStatus(session: ParallelScanSession): ConnectionPoolStatus {
        val maxSlots = session.config.maxConcurrentConnections
        val slotDetails = (0 until maxSlots).map { slotIndex ->
            val target = session.targets.firstOrNull { it.assignedSlot == slotIndex }
            ConnectionSlot(
                slotIndex = slotIndex,
                deviceAddress = target?.deviceAddress,
                state = target?.state ?: DeviceScanState.QUEUED,
                connectedAt = if (target?.state == DeviceScanState.CONNECTED ||
                    target?.state == DeviceScanState.SCANNING ||
                    target?.state == DeviceScanState.TESTING
                ) {
                    target.startTime
                } else {
                    null
                },
                devicesProcessed = session.results.count {
                    it.target.deviceAddress == target?.deviceAddress
                }
            )
        }

        val activeSlots = slotDetails.count {
            it.state == DeviceScanState.CONNECTING ||
                it.state == DeviceScanState.CONNECTED ||
                it.state == DeviceScanState.SCANNING ||
                it.state == DeviceScanState.TESTING
        }
        val queuedDevices = session.targets.count {
            it.state == DeviceScanState.QUEUED
        }
        val completedDevices = session.targets.count {
            it.state == DeviceScanState.COMPLETED ||
                it.state == DeviceScanState.FAILED ||
                it.state == DeviceScanState.CANCELLED
        }

        return ConnectionPoolStatus(
            totalSlots = maxSlots,
            activeSlots = activeSlots,
            queuedDevices = queuedDevices,
            completedDevices = completedDevices,
            slotDetails = slotDetails
        )
    }

    /**
     * Determine whether the session should be stopped.
     * Stops if [ParallelScanConfig.stopOnFirstCritical] is enabled and any result
     * has critical findings, or if all targets have reached a terminal state.
     */
    fun shouldStopSession(
        session: ParallelScanSession,
        config: ParallelScanConfig
    ): Boolean {
        // Stop if stopOnFirstCritical and any result has critical findings
        if (config.stopOnFirstCritical) {
            val hasCritical = session.results.any { it.criticalFindings > 0 }
            if (hasCritical) return true
        }

        // Stop if all targets are in terminal states
        val allTerminal = session.targets.all {
            it.state == DeviceScanState.COMPLETED ||
                it.state == DeviceScanState.FAILED ||
                it.state == DeviceScanState.CANCELLED
        }
        return allTerminal
    }

    /**
     * Generate a human-readable summary report of the session.
     */
    fun generateSessionReport(session: ParallelScanSession): String {
        val totalDevices = session.targets.size
        val completed = session.targets.count { it.state == DeviceScanState.COMPLETED }
        val failed = session.targets.count { it.state == DeviceScanState.FAILED }
        val cancelled = session.targets.count { it.state == DeviceScanState.CANCELLED }
        val totalVulns = session.results.sumOf { it.vulnerabilitiesFound }
        val totalCritical = session.results.sumOf { it.criticalFindings }
        val totalHigh = session.results.sumOf { it.highFindings }
        val totalServices = session.results.sumOf { it.servicesFound }
        val durationSec = session.totalDurationMs / 1000.0

        return buildString {
            appendLine("=== Multi-Device Scan Report ===")
            appendLine("Session ID: ${session.id}")
            appendLine("Total Duration: ${"%.1f".format(durationSec)}s")
            appendLine("Devices: $totalDevices total, $completed completed, $failed failed, $cancelled cancelled")
            appendLine("Services Discovered: $totalServices")
            appendLine("Vulnerabilities: $totalVulns ($totalCritical critical, $totalHigh high)")
            appendLine("================================")
        }
    }

    /**
     * Sort targets by priority: CRITICAL first, then HIGH, NORMAL, LOW.
     * Targets with the same priority preserve their original relative order.
     */
    fun sortTargetsByPriority(targets: List<ParallelScanTarget>): List<ParallelScanTarget> {
        val priorityOrder = mapOf(
            ScanPriority.CRITICAL to 0,
            ScanPriority.HIGH to 1,
            ScanPriority.NORMAL to 2,
            ScanPriority.LOW to 3
        )
        return targets.sortedBy { priorityOrder[it.priority] ?: Int.MAX_VALUE }
    }
}
