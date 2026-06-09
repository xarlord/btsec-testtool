/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.DeviceDiff
import com.btsec.testtool.domain.model.DiffType
import com.btsec.testtool.domain.model.ScanDiffResult
import com.btsec.testtool.domain.model.ScanDiffSummary
import javax.inject.Inject

/**
 * Use case for comparing two Bluetooth scan sessions.
 *
 * Matches devices by MAC address and categorises every device as
 * ADDED, REMOVED, MODIFIED, or UNCHANGED. For modified devices the
 * specific fields that changed are reported in [DeviceDiff.changedFields].
 *
 * All comparisons are designed for AUTHORIZED security testing purposes only.
 */
class ScanDiffUseCase @Inject constructor() {

    /**
     * Compare a [baseline] scan against a [comparison] scan.
     *
     * @param baseline The earlier / reference scan session devices.
     * @param comparison The newer scan session devices to compare.
     * @param baselineScanId Optional identifier for the baseline session.
     * @param comparisonScanId Optional identifier for the comparison session.
     * @return A [ScanDiffResult] categorising every device.
     */
    fun diffScans(
        baseline: List<BluetoothDevice>,
        comparison: List<BluetoothDevice>,
        baselineScanId: String = "baseline",
        comparisonScanId: String = "comparison"
    ): ScanDiffResult {
        val baselineMap = baseline.associateBy { it.address }
        val comparisonMap = comparison.associateBy { it.address }

        val baselineAddresses = baselineMap.keys
        val comparisonAddresses = comparisonMap.keys

        val addedAddresses = comparisonAddresses - baselineAddresses
        val removedAddresses = baselineAddresses - comparisonAddresses
        val commonAddresses = baselineAddresses.intersect(comparisonAddresses)

        val added = addedAddresses.map { addr ->
            val device = comparisonMap[addr]!!
            DeviceDiff(
                device = device,
                diffType = DiffType.ADDED,
                previousRssi = null,
                currentRssi = device.rssi,
                previousName = null,
                currentName = device.name,
                changedFields = emptyList()
            )
        }

        val removed = removedAddresses.map { addr ->
            val device = baselineMap[addr]!!
            DeviceDiff(
                device = device,
                diffType = DiffType.REMOVED,
                previousRssi = device.rssi,
                currentRssi = null,
                previousName = device.name,
                currentName = null,
                changedFields = emptyList()
            )
        }

        val modified = mutableListOf<DeviceDiff>()
        val unchanged = mutableListOf<DeviceDiff>()

        for (addr in commonAddresses) {
            val prev = baselineMap[addr]!!
            val curr = comparisonMap[addr]!!
            val changedFields = detectChanges(prev, curr)

            if (changedFields.isEmpty()) {
                unchanged += DeviceDiff(
                    device = curr,
                    diffType = DiffType.UNCHANGED,
                    previousRssi = prev.rssi,
                    currentRssi = curr.rssi,
                    previousName = prev.name,
                    currentName = curr.name,
                    changedFields = emptyList()
                )
            } else {
                modified += DeviceDiff(
                    device = curr,
                    diffType = DiffType.MODIFIED,
                    previousRssi = prev.rssi,
                    currentRssi = curr.rssi,
                    previousName = prev.name,
                    currentName = curr.name,
                    changedFields = changedFields
                )
            }
        }

        val summary = ScanDiffSummary(
            totalBaseline = baseline.size,
            totalComparison = comparison.size,
            addedCount = added.size,
            removedCount = removed.size,
            modifiedCount = modified.size,
            unchangedCount = unchanged.size
        )

        return ScanDiffResult(
            baselineScanId = baselineScanId,
            comparisonScanId = comparisonScanId,
            added = added,
            removed = removed,
            modified = modified,
            unchanged = unchanged,
            summary = summary
        )
    }

    /**
     * Detect which fields changed between two device snapshots.
     *
     * Compares: name, rssi, services, bondState, deviceClass, txPower, type.
     */
    private fun detectChanges(
        previous: BluetoothDevice,
        current: BluetoothDevice
    ): List<String> {
        val changes = mutableListOf<String>()

        if (previous.name != current.name) changes += "name"
        if (previous.rssi != current.rssi) changes += "rssi"
        if (previous.services != current.services) changes += "services"
        if (previous.bondState != current.bondState) changes += "bondState"
        if (previous.deviceClass != current.deviceClass) changes += "deviceClass"
        if (previous.txPower != current.txPower) changes += "txPower"
        if (previous.type != current.type) changes += "type"

        return changes
    }
}
