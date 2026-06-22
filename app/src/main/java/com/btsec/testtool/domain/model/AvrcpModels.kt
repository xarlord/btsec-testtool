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
 * AVRCP (Audio/Video Remote Control Profile) security testing models.
 *
 * These models support testing for unauthorized media control and
 * directory traversal vulnerabilities in Bluetooth AVRCP implementations.
 *
 * All testing must be performed on AUTHORIZED devices only.
 */

/** Categories of AVRCP security tests. */
enum class AvrcpTestCategory {
    MEDIA_CONTROL, // Play/pause/skip without auth
    BROWSING, // Browse media library without auth
    PATH_TRAVERSAL, // Navigate outside media directories
    METADATA_EXTRACTION, // Extract media item metadata
    NOTIFICATION_INJECTION, // Register for event notifications
    VENDOR_COMMAND_FUZZ, // Fuzz vendor-specific AVRCP commands
    VOLUME_MANIPULATION, // Change volume without auth
}

/** Represents a media item discovered via AVRCP browsing. */
data class AvrcpMediaItem(
    val uid: Long,
    val title: String?,
    val artist: String?,
    val album: String?,
    val genre: String?,
    val trackNumber: Int?,
    val duration: Int?,
    val type: MediaItemType,
    val path: String?,
)

/** Type of media item found via browsing. */
enum class MediaItemType { TRACK, FOLDER, UNKNOWN }

/** Result of a single AVRCP security test. */
data class AvrcpTestResult(
    val category: AvrcpTestCategory,
    val testName: String,
    val command: String,
    val response: String?,
    val vulnerable: Boolean,
    val confidence: Double,
    val evidence: String,
    val severity: AvrcpSeverity,
    val recommendation: String,
)

/** Severity levels for AVRCP test findings. */
enum class AvrcpSeverity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

/** Result of an AVRCP browsing/directory traversal test. */
data class AvrcpBrowseResult(
    val path: String,
    val depth: Int,
    val itemsFound: Int,
    val traversalSuccessful: Boolean,
    val sensitivePaths: List<String>,
)

/** Overall report for an AVRCP security test session. */
data class AvrcpTestReport(
    val targetDevice: String,
    val results: List<AvrcpTestResult>,
    val browseResults: List<AvrcpBrowseResult>,
    val mediaItemsExtracted: Int,
    val criticalCount: Int,
    val highCount: Int,
    val testDurationMs: Long,
)
