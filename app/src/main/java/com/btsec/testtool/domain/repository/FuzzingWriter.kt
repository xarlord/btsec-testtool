/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.Flow

/**
 * Write/mutation interface for fuzzing operations.
 *
 * Provides methods to start/stop/pause/resume fuzzing tests, save/delete
 * results, manage custom patterns, and write audit logs.
 *
 * This interface follows the Interface Segregation Principle (ISP) by
 * exposing only mutation/action operations, allowing components that only
 * need to trigger or control fuzzing tests to depend on a narrow contract.
 */
interface FuzzingWriter {

    /**
     * Start a fuzzing test with the given configuration.
     *
     * @param config Fuzzing configuration
     * @return Flow of fuzzing progress updates
     */
    fun startFuzzing(config: FuzzConfig): Flow<FuzzProgress>

    /**
     * Stop the currently running fuzzing test.
     */
    suspend fun stopFuzzing(): Result<Unit>

    /**
     * Pause the current fuzzing test.
     */
    suspend fun pauseFuzzing(): Result<Unit>

    /**
     * Resume a paused fuzzing test.
     */
    suspend fun resumeFuzzing(): Result<Unit>

    /**
     * Save a fuzzing result.
     */
    suspend fun saveFuzzingResult(result: FuzzResult): Result<Unit>

    /**
     * Delete a fuzzing result.
     */
    suspend fun deleteFuzzingResult(id: String): Result<Unit>

    /**
     * Add a custom fuzzing pattern.
     */
    suspend fun addPattern(pattern: FuzzDataPattern): Result<Unit>

    /**
     * Remove a fuzzing pattern.
     */
    suspend fun removePattern(patternName: String): Result<Unit>

    /**
     * Log a fuzzing operation for audit purposes.
     */
    suspend fun logFuzzingOperation(operation: FuzzingOperation)
}
