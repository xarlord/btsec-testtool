/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

/**
 * Type of difference detected between two scan sessions.
 */
enum class DiffType {
    ADDED,
    REMOVED,
    MODIFIED,
    UNCHANGED
}

/**
 * Represents the diff for a single device between two scan sessions.
 *
 * @property device The device from the comparison scan (or baseline if removed).
 * @property diffType Category of change.
 * @property previousRssi RSSI value in the baseline scan (null if device was added).
 * @property currentRssi RSSI value in the comparison scan (null if device was removed).
 * @property previousName Device name in the baseline scan.
 * @property currentName Device name in the comparison scan.
 * @property changedFields List of field names that changed (e.g. ["rssi", "name", "services"]).
 */
data class DeviceDiff(
    val device: BluetoothDevice,
    val diffType: DiffType,
    val previousRssi: Int?,
    val currentRssi: Int?,
    val previousName: String?,
    val currentName: String?,
    val changedFields: List<String>
)

/**
 * Aggregated result of comparing two scan sessions.
 *
 * @property baselineScanId Identifier for the baseline scan session.
 * @property comparisonScanId Identifier for the comparison scan session.
 * @property added Devices present only in the comparison scan.
 * @property removed Devices present only in the baseline scan.
 * @property modified Devices present in both scans with attribute changes.
 * @property unchanged Devices identical in both scans.
 * @property summary Summary counts.
 */
data class ScanDiffResult(
    val baselineScanId: String,
    val comparisonScanId: String,
    val added: List<DeviceDiff>,
    val removed: List<DeviceDiff>,
    val modified: List<DeviceDiff>,
    val unchanged: List<DeviceDiff>,
    val summary: ScanDiffSummary
)

/**
 * Summary statistics for a scan diff.
 */
data class ScanDiffSummary(
    val totalBaseline: Int,
    val totalComparison: Int,
    val addedCount: Int,
    val removedCount: Int,
    val modifiedCount: Int,
    val unchangedCount: Int
)
