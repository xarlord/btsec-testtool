/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject

/**
 * Use case for Bluetooth fuzzing operations.
 *
 * Fuzzing sends malformed/mutated packets to discover vulnerabilities.
 * All fuzzing operations require authorization and user consent.
 */
class FuzzingUseCase @Inject constructor(
    private val fuzzingRepository: FuzzingRepository,
    private val bluetoothRepository: BluetoothRepository,
    private val authorizationUseCase: AuthorizationUseCase,
    private val consentRepository: ConsentRepository
) {

    /**
     * Start a fuzzing test.
     *
     * @param config Fuzzing configuration
     * @return Result of fuzzing start
     */
    suspend fun startFuzzing(config: FuzzConfig): FuzzingStartResult {
        // Verify authorization for fuzzing
        val authResult = authorizationUseCase.requestActionAuthorization(
            TestAction.START_FUZZING,
            getDeviceInfo()
        )

        when (authResult) {
            is ActionAuthorizationResult.Authorized -> {
                // Check rate limit
                val maxRate = authorizationUseCase.getCurrentScope().first()?.maxPacketsPerSecond
                    ?: 100

                if (config.packetsPerSecond > maxRate) {
                    return FuzzingStartResult.RateLimitExceeded(maxRate)
                }

                // Check device in scope
                if (!authorizationUseCase.isTargetInScope(config.targetDevice.address)) {
                    return FuzzingStartResult.DeviceNotInScope
                }

                // Start fuzzing
                fuzzingRepository.startFuzzing(config)
                return FuzzingStartResult.Started
            }
            is ActionAuthorizationResult.ConsentDenied -> {
                return FuzzingStartResult.ConsentRequired
            }
            else -> {
                return FuzzingStartResult.NotAuthorized
            }
        }
    }

    /**
     * Stop the current fuzzing test.
     */
    suspend fun stopFuzzing(): Result<Unit> {
        return fuzzingRepository.stopFuzzing()
    }

    /**
     * Pause the current fuzzing test.
     */
    suspend fun pauseFuzzing(): Result<Unit> {
        return fuzzingRepository.pauseFuzzing()
    }

    /**
     * Resume a paused fuzzing test.
     */
    suspend fun resumeFuzzing(): Result<Unit> {
        return fuzzingRepository.resumeFuzzing()
    }

    /**
     * Get current fuzzing status.
     */
    fun getFuzzingStatus(): Flow<FuzzStatus> {
        return fuzzingRepository.getFuzzingStatus()
    }

    /**
     * Get current fuzzing progress.
     */
    fun getFuzzingProgress(): Flow<FuzzProgress?> {
        return fuzzingRepository.getFuzzingProgress()
    }

    /**
     * Get all fuzzing results.
     */
    fun getAllFuzzingResults(): Flow<List<FuzzResult>> {
        return fuzzingRepository.getAllFuzzingResults()
    }

    /**
     * Get fuzzing results for a specific device.
     */
    fun getFuzzingResultsForDevice(deviceAddress: String): Flow<List<FuzzResult>> {
        return fuzzingRepository.getFuzzingResultsForDevice(deviceAddress)
    }

    /**
     * Get findings from a fuzzing test.
     */
    fun getFindingsForResult(resultId: String): Flow<List<FuzzFinding>> {
        return fuzzingRepository.getFindingsForResult(resultId)
    }

    /**
     * Get critical findings from all fuzzing tests.
     */
    fun getCriticalFindings(): Flow<List<FuzzFinding>> {
        return fuzzingRepository.getFindingsBySeverity(VulnerabilitySeverity.CRITICAL)
    }

    /**
     * Get fuzzing statistics.
     */
    fun getFuzzingStatistics(): Flow<FuzzingStatistics> {
        return fuzzingRepository.getFuzzingStatistics()
    }

    /**
     * Get available fuzzing patterns.
     */
    fun getAvailablePatterns(): Flow<List<FuzzDataPattern>> {
        return fuzzingRepository.getAvailablePatterns()
    }

    /**
     * Get fuzzing patterns for a specific category.
     */
    suspend fun getPatternsForType(type: PatternType): List<FuzzDataPattern> {
        return fuzzingRepository.getPatternsForType(type)
    }

    /**
     * Get known exploit patterns from CVE database.
     */
    suspend fun getKnownExploitPatterns(): List<FuzzDataPattern> {
        return fuzzingRepository.getKnownExploitPatterns()
    }

    /**
     * Create a recommended fuzzing configuration for a device.
     *
     * @param device Target device
     * @return Recommended configuration
     */
    suspend fun createRecommendedConfig(device: BluetoothDevice): FuzzConfig {
        val maxRate = authorizationUseCase.getCurrentScope().first()?.maxPacketsPerSecond
            ?: 100

        return FuzzConfig(
            targetDevice = device,
            targetService = null,
            targetCharacteristic = null,
            fuzzMethod = FuzzMethod.MUTATION,
            packetCount = 1000,
            packetsPerSecond = maxRate.coerceAtMost(50),
            randomSeed = null,
            dataPatterns = getDefaultPatterns(),
            durationSeconds = 300,
            stopOnError = true,
            stopOnDisconnect = true,
            capturePackets = true,
            captureNotifications = true
        )
    }

    /**
     * Create an aggressive fuzzing configuration.
     * Use with caution - may cause device crashes.
     */
    suspend fun createAggressiveConfig(device: BluetoothDevice): FuzzConfig {
        val maxRate = authorizationUseCase.getCurrentScope().first()?.maxPacketsPerSecond
            ?: 100

        return FuzzConfig(
            targetDevice = device,
            targetService = null,
            targetCharacteristic = null,
            fuzzMethod = FuzzMethod.RANDOM,
            packetCount = 10000,
            packetsPerSecond = maxRate,
            randomSeed = null,
            dataPatterns = getAggressivePatterns(),
            durationSeconds = 1800,
            stopOnError = false,
            stopOnDisconnect = false,
            capturePackets = true,
            captureNotifications = true
        )
    }

    /**
     * Get default fuzzing patterns.
     */
    private suspend fun getDefaultPatterns(): List<FuzzDataPattern> {
        return listOf(
            FuzzDataPattern(
                name = "Buffer Overflow",
                description = "Long data to test buffer overflow",
                patternType = PatternType.OVERLONG,
                data = ByteArray(512) { 0x41 }  // 'A' * 512
            ),
            FuzzDataPattern(
                name = "Null Bytes",
                description = "Data with null bytes",
                patternType = PatternType.NULL_BYTES,
                data = byteArrayOf(0x00, 0x00, 0x00, 0x00)
            ),
            FuzzDataPattern(
                name = "Format String",
                description = "Format string patterns",
                patternType = PatternType.FORMAT_STRING,
                data = "%s%s%s%s%n%n%n".toByteArray()
            )
        )
    }

    /**
     * Get aggressive fuzzing patterns.
     * These are more likely to cause crashes.
     */
    private suspend fun getAggressivePatterns(): List<FuzzDataPattern> {
        return listOf(
            FuzzDataPattern(
                name = "Huge Buffer",
                description = "Very large buffer",
                patternType = PatternType.OVERLONG,
                data = ByteArray(4096) { 0x42 }
            ),
            FuzzDataPattern(
                name = "Bit Flip",
                description = "Flip all bits",
                patternType = PatternType.RANDOM,
                data = ByteArray(256) { it.toByte() }
            ),
            FuzzDataPattern(
                name = "Boundary Values",
                description = "Test boundary conditions",
                patternType = PatternType.EDGE_CASE,
                data = byteArrayOf(0x00, 0x01, 0x7F, 0x80, 0xFF.toByte())
            )
        )
    }

    private fun getDeviceInfo(): DeviceInfo {
        return DeviceInfo(
            platform = android.os.Build.MANUFACTURER,
            model = android.os.Build.MODEL,
            androidVersion = android.os.Build.VERSION.RELEASE,
            appVersion = "1.0.0",
            bluetoothAddress = "TESTING"
        )
    }
}

/**
 * Result of fuzzing start request.
 */
sealed class FuzzingStartResult {
    data object Started : FuzzingStartResult()
    data object ConsentRequired : FuzzingStartResult()
    data object NotAuthorized : FuzzingStartResult()
    data object DeviceNotInScope : FuzzingStartResult()
    data class RateLimitExceeded(val maxRate: Int) : FuzzingStartResult()
    data class Error(val message: String) : FuzzingStartResult()
}
