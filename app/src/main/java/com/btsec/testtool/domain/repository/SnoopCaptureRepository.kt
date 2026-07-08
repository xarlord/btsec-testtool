/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.SnoopCaptureSession
import com.btsec.testtool.domain.model.SnoopRecord
import kotlinx.coroutines.flow.Flow

/**
 * Repository for HCI Snoop log capture operations.
 *
 * Provides capabilities for monitoring the HCI snoop log file,
 * parsing new packets, and managing capture sessions.
 *
 * Supports multiple capture strategies via [SnoopCaptureStrategy]:
 * - Direct file read (requires root)
 * - Shizuku shell (root-free, requires Shizuku)
 * - Bugreport zip extraction (root-free, post-capture)
 *
 * All operations require prior AUTHORIZATION.
 */
interface SnoopCaptureRepository {
    /**
     * Start monitoring the HCI snoop log for new packets.
     *
     * @return Flow of newly captured snoop records.
     */
    fun startCapture(): Flow<SnoopRecord>

    /**
     * Stop monitoring the HCI snoop log.
     */
    suspend fun stopCapture()

    /**
     * Get the current capture session info.
     *
     * @return Flow of the active capture session, or null if not capturing.
     */
    fun getCaptureSession(): Flow<SnoopCaptureSession?>

    /**
     * Check whether snoop capture is active.
     *
     * @return Flow of capture state.
     */
    fun isCapturing(): Flow<Boolean>

    /**
     * Save a capture session for later analysis.
     *
     * @param session The capture session to save.
     */
    suspend fun saveCaptureSession(session: SnoopCaptureSession)

    /**
     * Get saved capture sessions.
     *
     * @return Flow of all saved sessions.
     */
    fun getSavedSessions(): Flow<List<SnoopCaptureSession>>

    /**
     * Get a list of all registered capture strategies and their availability.
     *
     * Each entry contains the strategy name and whether it is currently available
     * on this device. This is useful for UI that lets the user pick a strategy.
     *
     * @return List of [StrategyInfo] describing each strategy.
     */
    fun getAvailableStrategies(): List<StrategyInfo>

    /**
     * Get the name of the currently active (selected) capture strategy.
     *
     * @return The strategy name, or null if no strategy is active.
     */
    fun getActiveStrategyName(): String?

    /**
     * Force selection of a specific capture strategy by name.
     *
     * If the named strategy is available and can read the snoop log, it becomes
     * the active strategy. Otherwise, the call fails silently and the current
     * strategy remains.
     *
     * @param name The exact name returned by [SnoopCaptureStrategy.getName].
     */
    fun selectStrategy(name: String)

    /**
     * Descriptor for a capture strategy's availability.
     */
    data class StrategyInfo(
        val name: String,
        val isAvailable: Boolean,
        val canRead: Boolean,
    )
}
