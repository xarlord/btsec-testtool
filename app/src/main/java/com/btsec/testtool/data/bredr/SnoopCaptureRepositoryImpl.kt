/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import android.content.Context
import com.btsec.testtool.data.bredr.strategy.DirectFileSnoopStrategy
import com.btsec.testtool.domain.model.HciPacketType
import com.btsec.testtool.domain.model.SnoopCaptureSession
import com.btsec.testtool.domain.model.SnoopDirection
import com.btsec.testtool.domain.model.SnoopRecord
import com.btsec.testtool.domain.repository.SnoopCaptureRepository
import com.btsec.testtool.domain.repository.SnoopCaptureStrategy
import com.btsec.testtool.domain.usecase.SnoopCaptureUseCase
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber
import java.io.File
import java.io.InputStream
import java.io.RandomAccessFile
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [SnoopCaptureRepository].
 *
 * Uses the strategy pattern to support multiple HCI snoop log capture methods:
 * - **Direct file read** (requires root) — the original approach
 * - **Shizuku shell** (root-free) — placeholder, to be wired when Shizuku lib is added
 * - **Bugreport zip extraction** (root-free, post-capture)
 *
 * Strategies are injected via Hilt as a [List] of [SnoopCaptureStrategy]. The
 * repository auto-selects the first available strategy that [canReadSnoopLog].
 * The user can override via [selectStrategy].
 *
 * For live monitoring (file-tail polling), the repository falls back to direct
 * [File] I/O using [DirectFileSnoopStrategy.SNOOP_LOG_PATH] — this is the only
 * strategy that supports incremental polling. Other strategies provide one-shot
 * reads via [SnoopCaptureStrategy.readSnoopLog].
 *
 * Delegates packet parsing to [SnoopCaptureUseCase].
 *
 * Issues: #375 (root-free snoop capture), #412 (strategy pattern refactor)
 */
@Singleton
class SnoopCaptureRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        private val snoopCaptureUseCase: SnoopCaptureUseCase,
        private val strategies: Set<@JvmSuppressWildcards SnoopCaptureStrategy>,
    ) : SnoopCaptureRepository {
        private val isCapturing = MutableStateFlow(false)
        private val captureSession = MutableStateFlow<SnoopCaptureSession?>(null)
        private val savedSessions = MutableStateFlow<List<SnoopCaptureSession>>(emptyList())

        private var monitorJob: kotlinx.coroutines.Job? = null
        private var lastFileSize = 0L
        private var sessionStartTime = 0L

        /** The currently selected strategy (or null if none selected yet). */
        private var activeStrategy: SnoopCaptureStrategy? = null

        /** Mutex to prevent concurrent strategy auto-selection. */
        private val strategyMutex = Mutex()

        override fun startCapture(): Flow<SnoopRecord> {
            return kotlinx.coroutines.flow.callbackFlow {
                isCapturing.value = true
                sessionStartTime = System.currentTimeMillis()

                var sentPackets = 0
                var receivedPackets = 0
                var aclPackets = 0
                var scoPackets = 0
                var hciCommands = 0
                var hciEvents = 0

                // Launch as a child of the ProducerScope (callbackFlow) so the
                // monitoring coroutine is cancelled automatically when the flow
                // collector is cancelled — fixing the raw CoroutineScope leak (#380).
                monitorJob =
                    launch(kotlinx.coroutines.Dispatchers.IO) {
                        val snoopFile = File(DirectFileSnoopStrategy.SNOOP_LOG_PATH)

                        while (isActive) {
                            try {
                                if (snoopFile.exists() && snoopFile.length() > lastFileSize) {
                                    val newRecords = readNewRecords(snoopFile)
                                    for (record in newRecords) {
                                        sentPackets += if (record.direction == SnoopDirection.SENT) 1 else 0
                                        receivedPackets += if (record.direction == SnoopDirection.RECEIVED) 1 else 0
                                        when (record.packetType) {
                                            HciPacketType.ACL_DATA -> aclPackets++
                                            HciPacketType.SCO_DATA -> scoPackets++
                                            HciPacketType.COMMAND -> hciCommands++
                                            HciPacketType.EVENT -> hciEvents++
                                            else -> {}
                                        }
                                        trySend(record)
                                    }

                                    captureSession.value =
                                        SnoopCaptureSession(
                                            id = java.util.UUID.randomUUID().toString(),
                                            startTime = sessionStartTime,
                                            endTime = System.currentTimeMillis(),
                                            totalPackets = sentPackets + receivedPackets,
                                            sentPackets = sentPackets,
                                            receivedPackets = receivedPackets,
                                            aclPackets = aclPackets,
                                            scoPackets = scoPackets,
                                            hciCommands = hciCommands,
                                            hciEvents = hciEvents,
                                            fileSizeBytes = snoopFile.length(),
                                        )
                                }
                            } catch (e: Exception) {
                                Timber.w(e, "Error reading snoop log")
                            }

                            lastFileSize = snoopFile.length()
                            delay(SNOOP_POLL_INTERVAL_MS)
                        }
                    }

                awaitClose {
                    monitorJob?.cancel()
                    monitorJob = null
                    isCapturing.value = false
                }
            }
        }

        override suspend fun stopCapture() {
            monitorJob?.cancel()
            monitorJob = null
            isCapturing.value = false

            captureSession.value?.let { session ->
                val updated = savedSessions.value.toMutableList()
                updated.add(session.copy(endTime = System.currentTimeMillis()))
                savedSessions.value = updated
            }
        }

        override fun getCaptureSession(): Flow<SnoopCaptureSession?> = captureSession

        override fun isCapturing(): Flow<Boolean> = isCapturing

        override suspend fun saveCaptureSession(session: SnoopCaptureSession) {
            val updated = savedSessions.value.toMutableList()
            updated.add(session)
            savedSessions.value = updated
        }

        override fun getSavedSessions(): Flow<List<SnoopCaptureSession>> = savedSessions

        // ── Strategy selection ──

        override fun getAvailableStrategies(): List<SnoopCaptureRepository.StrategyInfo> {
            return strategies.map { strategy ->
                SnoopCaptureRepository.StrategyInfo(
                    name = strategy.getName(),
                    isAvailable = strategy.isAvailable(),
                    canRead = strategy.isAvailable() && strategy.canReadSnoopLog(),
                )
            }
        }

        override fun getActiveStrategyName(): String? = activeStrategy?.getName()

        override fun selectStrategy(name: String) {
            val strategy = strategies.find { it.getName() == name }
            if (strategy != null && strategy.isAvailable()) {
                activeStrategy = strategy
                Timber.i("Snoop capture strategy selected: %s", name)
            } else {
                Timber.w("Cannot select strategy '%s': not found or not available", name)
            }
        }

        /**
         * Auto-select the first available strategy that can read the snoop log.
         *
         * @return the selected strategy, or null if none can read.
         */
        private suspend fun autoSelectStrategy(): SnoopCaptureStrategy? {
            return strategyMutex.withLock {
                // Check the currently active strategy first
                activeStrategy?.let { strategy ->
                    if (strategy.isAvailable() && strategy.canReadSnoopLog()) {
                        return strategy
                    }
                }
                // Otherwise scan all strategies
                for (strategy in strategies) {
                    try {
                        if (strategy.isAvailable() && strategy.canReadSnoopLog()) {
                            activeStrategy = strategy
                            Timber.i("Auto-selected snoop capture strategy: %s", strategy.getName())
                            return strategy
                        }
                    } catch (e: Exception) {
                        Timber.w(e, "Strategy %s check failed", strategy.getName())
                    }
                }
                Timber.w("No snoop capture strategy is available")
                null
            }
        }

        /**
         * Convenience method to read snoop log via the best available strategy.
         *
         * For strategies that support streaming (DirectFile), the existing
         * file-tail polling in [startCapture] is preferred. This method is
         * intended for one-shot reads (e.g., from bugreport zips).
         *
         * @return the snoop log input stream, or null if no strategy can read.
         */
        suspend fun readViaStrategy(): InputStream? {
            val strategy = autoSelectStrategy() ?: return null
            return strategy.readSnoopLog().getOrNull()
        }

        // ── Private helpers ──

        private suspend fun delay(ms: Long) {
            kotlinx.coroutines.delay(ms)
        }

        private fun readNewRecords(file: File): List<SnoopRecord> {
            val records = mutableListOf<SnoopRecord>()
            try {
                // Use .use { } so the file handle is always closed even if a read
                // throws mid-record (EOFException on truncated data, etc.) — fixes #379.
                val raf = RandomAccessFile(file, "r")
                raf.use {
                    // If first read, skip snoop header (16 bytes)
                    if (lastFileSize == 0L) {
                        it.seek(16)
                    } else {
                        it.seek(lastFileSize)
                    }

                    while (it.filePointer < it.length() - 24) { // Each record header is 24 bytes
                        val originalLength = it.readInt().toUnsigned()
                        val includedLength = it.readInt().toUnsigned()
                        val flags = it.readInt()
                        val drops = it.readInt()
                        val timestampMicros = it.readLong()

                        if (includedLength <= 0 || includedLength > 1_000_000) break

                        val data = ByteArray(includedLength)
                        it.readFully(data)

                        val direction = if ((flags and 0x01) == 0) SnoopDirection.SENT else SnoopDirection.RECEIVED
                        val packetType =
                            when ((flags shr 1) and 0x07) {
                                1 -> HciPacketType.COMMAND
                                2 -> HciPacketType.ACL_DATA
                                3 -> HciPacketType.SCO_DATA
                                4 -> HciPacketType.EVENT
                                else -> HciPacketType.UNKNOWN
                            }

                        records.add(
                            SnoopRecord(
                                originalLength = originalLength,
                                includedLength = includedLength,
                                flags = flags,
                                drops = drops,
                                timestampMicros = timestampMicros,
                                data = data,
                                packetType = packetType,
                                direction = direction,
                            ),
                        )
                    }

                    lastFileSize = it.filePointer
                }
            } catch (e: Exception) {
                Timber.w(e, "Failed to read snoop records")
            }
            return records
        }

        private fun Int.toUnsigned(): Int = if (this < 0) this + (1L shl 32).toInt() else this

        companion object {
            private const val SNOOP_POLL_INTERVAL_MS = 500L
        }
    }
