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
}
