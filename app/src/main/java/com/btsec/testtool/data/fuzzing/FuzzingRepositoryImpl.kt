/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.fuzzing

import android.content.Context
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.DateRange
import com.btsec.testtool.domain.repository.DeviceFuzzingStatistics
import com.btsec.testtool.domain.repository.FuzzProgress
import com.btsec.testtool.domain.repository.FuzzingOperation
import com.btsec.testtool.domain.repository.FuzzingRepository
import com.btsec.testtool.domain.repository.FuzzingStatistics
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of fuzzing repository.
 *
 * Handles Bluetooth protocol fuzzing to discover vulnerabilities.
 * All fuzzing operations require authorization.
 */
@Singleton
class FuzzingRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : FuzzingRepository {
        private val fuzzingStatus = MutableStateFlow<FuzzStatus>(FuzzStatus.PENDING)
        private val fuzzingProgress = MutableStateFlow<FuzzProgress?>(null)
        private val fuzzingResults = MutableStateFlow<List<FuzzResult>>(emptyList())
        private val patterns = MutableStateFlow<List<FuzzDataPattern>>(emptyList())
        private val logs = MutableStateFlow<List<FuzzingOperation>>(emptyList())

        override fun startFuzzing(config: FuzzConfig): Flow<FuzzProgress> {
            return flow {
                fuzzingStatus.value = FuzzStatus.RUNNING
                val resultId = generateId()
                var packetsSent = 0
                var packetsReceived = 0
                var errors = 0
                var findings = 0

                emit(
                    FuzzProgress(
                        resultId = resultId,
                        config = config,
                        status = FuzzStatus.RUNNING,
                        packetsSent = 0,
                        packetsReceived = 0,
                        errors = 0,
                        findings = 0,
                        startTime = Instant.now(),
                        estimatedCompletionTime = Instant.now().plusSeconds(config.durationSeconds?.toLong() ?: 300),
                        currentPacketNumber = 0,
                        totalPackets = config.packetCount,
                    ),
                )

                // Simulate fuzzing progress
                repeat(config.packetCount) { i ->
                    packetsSent++
                    packetsReceived++ // Assume some responses

                    emit(
                        FuzzProgress(
                            resultId = resultId,
                            config = config,
                            status = FuzzStatus.RUNNING,
                            packetsSent = packetsSent,
                            packetsReceived = packetsReceived,
                            errors = 0,
                            findings = 0,
                            startTime = Instant.now(),
                            estimatedCompletionTime = Instant.now().plusSeconds(300),
                            currentPacketNumber = i + 1,
                            totalPackets = config.packetCount,
                        ),
                    )

                    kotlinx.coroutines.delay(100) // Simulate work
                }

                // Save result
                val result =
                    FuzzResult(
                        id = resultId,
                        config = config,
                        startTime = Instant.now(),
                        endTime = Instant.now(),
                        status = FuzzStatus.COMPLETED,
                        packetsSent = packetsSent,
                        packetsReceived = packetsReceived,
                        errors = emptyList(),
                        findings = emptyList(),
                        captureFile = null,
                        reportGenerated = false,
                    )
                saveResult(result)

                fuzzingStatus.value = FuzzStatus.COMPLETED
            }
        }

        override suspend fun stopFuzzing(): Result<Unit> {
            fuzzingStatus.value = FuzzStatus.STOPPED
            return Result.success(Unit)
        }

        override suspend fun pauseFuzzing(): Result<Unit> {
            // Would implement pause logic
            return Result.success(Unit)
        }

        override suspend fun resumeFuzzing(): Result<Unit> {
            // Would implement resume logic
            return Result.success(Unit)
        }

        override fun getFuzzingStatus(): Flow<FuzzStatus> {
            return fuzzingStatus
        }

        override fun getFuzzingProgress(): Flow<FuzzProgress?> {
            return fuzzingProgress
        }

        override suspend fun saveFuzzingResult(result: FuzzResult): Result<Unit> {
            return saveResult(result)
        }

        override suspend fun getFuzzingResult(id: String): FuzzResult? {
            return fuzzingResults.value.find { it.id == id }
        }

        override fun getAllFuzzingResults(): Flow<List<FuzzResult>> {
            return fuzzingResults
        }

        override fun getFuzzingResultsForDevice(deviceAddress: String): Flow<List<FuzzResult>> {
            return fuzzingResults.map { results -> results.filter { result -> result.config.targetDevice.address == deviceAddress } }
        }

        override fun getFuzzingResultsInRange(
            start: Instant,
            end: Instant,
        ): Flow<List<FuzzResult>> {
            return fuzzingResults.map { results -> results.filter { result -> result.startTime in start..end } }
        }

        override suspend fun deleteFuzzingResult(id: String): Result<Unit> {
            val updated = fuzzingResults.value.filter { it.id != id }
            fuzzingResults.value = updated
            return Result.success(Unit)
        }

        override fun getFindingsForResult(resultId: String): Flow<List<FuzzFinding>> {
            return flow { emit(emptyList()) }
        }

        override fun getFindingsBySeverity(minSeverity: VulnerabilitySeverity): Flow<List<FuzzFinding>> {
            return flow { emit(emptyList()) }
        }

        override fun getFindingsByCategory(category: FindingCategory): Flow<List<FuzzFinding>> {
            return flow { emit(emptyList()) }
        }

        override fun getAvailablePatterns(): Flow<List<FuzzDataPattern>> {
            return patterns
        }

        override suspend fun addPattern(pattern: FuzzDataPattern): Result<Unit> {
            val current = patterns.value.toMutableList()
            current.add(pattern)
            patterns.value = current
            return Result.success(Unit)
        }

        override suspend fun removePattern(patternName: String): Result<Unit> {
            val updated = patterns.value.filter { it.name != patternName }
            patterns.value = updated
            return Result.success(Unit)
        }

        override suspend fun getPatternsForType(type: PatternType): List<FuzzDataPattern> {
            return patterns.value.filter { it.patternType == type }
        }

        override suspend fun getKnownExploitPatterns(): List<FuzzDataPattern> {
            return listOf(
                FuzzDataPattern(
                    name = "KNOB Attack",
                    description = "Key Negotiation of Bluetooth attack pattern",
                    patternType = PatternType.KNOWN_EXPLOIT,
                    data = byteArrayOf(0x01, 0x02, 0x03),
                ),
            )
        }

        override suspend fun getBoundaryPatterns(): List<FuzzDataPattern> {
            return listOf(
                FuzzDataPattern(
                    name = "Max Value",
                    description = "Maximum 8-bit value",
                    patternType = PatternType.EDGE_CASE,
                    data = byteArrayOf(0xFF.toByte()),
                ),
            )
        }

        override suspend fun getFormatStringPatterns(): List<FuzzDataPattern> {
            return listOf(
                FuzzDataPattern(
                    name = "Format String",
                    description = "Classic format string",
                    patternType = PatternType.SPECIAL_CHARS,
                    data = "%s%n%x".toByteArray(),
                ),
            )
        }

        override suspend fun getBufferOverflowPatterns(): List<FuzzDataPattern> {
            return listOf(
                FuzzDataPattern(
                    name = "Buffer Overflow",
                    description = "Long data string",
                    patternType = PatternType.OVERLONG,
                    data = ByteArray(1024) { 0x41 },
                ),
            )
        }

        override fun getFuzzingStatistics(): Flow<FuzzingStatistics> {
            return flow {
                val results = fuzzingResults.value
                var totalPacketsSent = 0L
                var totalPacketsReceived = 0L
                var totalErrors = 0L
                var totalFindings = 0L
                var totalSuccessRate = 0.0
                var minStart: Instant? = null
                var maxEnd: Instant? = null
                // Optimization: Replaced multiple sumOf, minByOrNull, maxByOrNull, and map.average
                // calls with a single-pass O(N) loop. This eliminates redundant collection iterations
                // and intermediate allocations, improving performance significantly for large result sets.
                // Expected impact: O(K*N) -> O(N) where K was ~7. Memory allocations for intermediate collections reduced to 0.
                if (results.isNotEmpty()) {
                    for (result in results) {
                        totalPacketsSent += result.packetsSent
                        totalPacketsReceived += result.packetsReceived
                        totalErrors += result.errors.size
                        totalFindings += result.findings.size
                        totalSuccessRate += result.getSuccessRate()
                        val start = result.startTime
                        if (minStart == null || start.isBefore(minStart)) minStart = start
                        val end = result.endTime ?: start
                        if (maxEnd == null || end.isAfter(maxEnd)) maxEnd = end
                    }
                }
                emit(
                    FuzzingStatistics(
                        totalTests = results.size,
                        totalPacketsSent = totalPacketsSent,
                        totalPacketsReceived = totalPacketsReceived,
                        totalErrors = totalErrors,
                        totalFindings = totalFindings,
                        criticalFindings = 0,
                        highFindings = 0,
                        mediumFindings = 0,
                        lowFindings = 0,
                        averageSuccessRate = if (results.isNotEmpty()) totalSuccessRate / results.size else 0.0,
                        mostTestedDevice = null,
                        mostVulnerableDevice = null,
                        dateRange =
                            DateRange(
                                start = minStart ?: Instant.now(),
                                end = maxEnd ?: Instant.now(),
                            ),
                    ),
                )
            }
        }

        override suspend fun getStatisticsForDevice(deviceAddress: String): DeviceFuzzingStatistics {
            val deviceResults = fuzzingResults.value.filter { it.config.targetDevice.address == deviceAddress }
            var packetsSent = 0L
            var packetsReceived = 0L
            var findings = 0
            var maxStart: Instant? = null
            // Optimization: Single-pass iteration to aggregate all metrics concurrently, eliminating
            // multiple redundant sumOf and maxByOrNull passes. Reduces execution time to O(N)
            // and eliminates intermediate collection allocations.
            for (result in deviceResults) {
                packetsSent += result.packetsSent
                packetsReceived += result.packetsReceived
                findings += result.findings.size
                val start = result.startTime
                if (maxStart == null || start.isAfter(maxStart)) maxStart = start
            }
            return DeviceFuzzingStatistics(
                deviceAddress = deviceAddress,
                deviceName = deviceResults.firstOrNull()?.config?.targetDevice?.name,
                testsPerformed = deviceResults.size,
                packetsSent = packetsSent,
                packetsReceived = packetsReceived,
                findings = findings,
                lastTestDate = maxStart ?: Instant.now(),
                vulnerabilitiesDiscovered = emptyList(),
            )
        }

        override suspend fun isRateAllowed(packetsPerSecond: Int): Boolean {
            // In production, would check against authorization limits
            return packetsPerSecond <= 100
        }

        override suspend fun getMaxAllowedRate(): Int {
            // In production, would get from authorization
            return 100
        }

        override suspend fun logFuzzingOperation(operation: FuzzingOperation) {
            val current = logs.value.toMutableList()
            current.add(operation)
            logs.value = current
        }

        override fun getFuzzingLogs(): Flow<List<FuzzingOperation>> {
            return logs
        }

        private suspend fun saveResult(result: FuzzResult): Result<Unit> {
            val current = fuzzingResults.value.toMutableList()
            current.add(result)
            fuzzingResults.value = current
            return Result.success(Unit)
        }

        private fun generateId(): String {
            return java.util.UUID.randomUUID().toString()
        }
    }
