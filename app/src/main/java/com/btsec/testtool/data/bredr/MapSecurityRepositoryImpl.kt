/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.Context
import com.btsec.testtool.domain.model.MapAccessResult
import com.btsec.testtool.domain.model.MapFolder
import com.btsec.testtool.domain.model.MessageEntry
import com.btsec.testtool.domain.model.MessageType
import com.btsec.testtool.domain.model.PbmapTestReport
import com.btsec.testtool.domain.repository.MapSecurityRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import timber.log.Timber
import java.io.IOException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [MapSecurityRepository].
 *
 * Connects to MAP via OBEX/RFCOMM for message access testing.
 * Uses [ObexClient] for proper OBEX protocol framing to access
 * SMS/MMS/email folders on target devices.
 */
@Singleton
class MapSecurityRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : MapSecurityRepository {
        private val bluetoothManager: BluetoothManager =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

        private val connected = MutableStateFlow(false)
        private var socket: BluetoothSocket? = null
        private var obexClient: ObexClient? = null
        private val savedReports = MutableStateFlow<Map<String, List<PbmapTestReport>>>(emptyMap())

        @SuppressLint("MissingPermission")
        override suspend fun connect(deviceAddress: String): Result<Unit> {
            return try {
                disconnect()
                val device =
                    bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                        ?: return Result.failure(Exception("Device not found: $deviceAddress"))

                val mapSocket = device.createRfcommSocketToServiceRecord(MAP_MSE_UUID)
                mapSocket.connect()

                socket = mapSocket

                // Perform OBEX CONNECT with MAP target UUID
                val client = ObexClient(mapSocket.inputStream, mapSocket.outputStream)
                val response = client.connect(ObexClient.MAP_TARGET_UUID)

                if (response != null && response.isOk) {
                    obexClient = client
                    connected.value = true
                    Timber.i("MAP connected to $deviceAddress via OBEX")
                    Result.success(Unit)
                } else {
                    val code = response?.responseCode
                    mapSocket.close()
                    socket = null
                    Timber.w("MAP OBEX CONNECT failed: response code=0x${code?.toString(16) ?: "null"}")
                    Result.failure(Exception("OBEX connect failed: 0x${code?.toString(16) ?: "no response"}"))
                }
            } catch (e: SecurityException) {
                Timber.e(e, "Missing Bluetooth permissions")
                Result.failure(e)
            } catch (e: IOException) {
                Timber.e(e, "MAP connection failed")
                Result.failure(e)
            }
        }

        override suspend fun disconnect() {
            try {
                obexClient?.disconnect()
                socket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing MAP socket")
            }
            socket = null
            obexClient = null
            connected.value = false
        }

        override suspend fun accessFolder(folder: MapFolder): MapAccessResult {
            val startTime = System.currentTimeMillis()
            val client = obexClient

            if (client == null || !client.isConnected()) {
                return MapAccessResult(
                    folder = folder,
                    accessible = false,
                    messageCount = 0,
                    messages = emptyList(),
                    requiredAuth = true,
                    testDurationMs = System.currentTimeMillis() - startTime,
                )
            }

            // Navigate to the correct virtual folder
            val folderPath = folderToPath(folder)
            val setPathResponse = client.setPath(folderPath)

            val duration = System.currentTimeMillis() - startTime

            if (setPathResponse == null || !setPathResponse.isSuccess) {
                Timber.w("MAP: SET_PATH failed for $folder (code=0x${setPathResponse?.responseCode?.toString(16) ?: "null"})")
                return MapAccessResult(
                    folder = folder,
                    accessible = false,
                    messageCount = 0,
                    messages = emptyList(),
                    requiredAuth = true,
                    testDurationMs = duration,
                )
            }

            // MAP GET to list messages in the folder
            // Application parameters for listing:
            //   Tag 0x01: MaxListCount (2 bytes) — 0x0000 = list all
            //   Tag 0x02: ListStartOffset (2 bytes) — 0x0000
            //   Tag 0x03: ParameterMask (8 bytes) — bitmask of fields to return
            val appParams = buildMapListParams()

            val response = client.get(folderPath, appParams)
            val totalDuration = System.currentTimeMillis() - startTime

            return if (response != null) {
                when {
                    response.isUnauthorized -> {
                        Timber.i("MAP: folder access unauthorized for $folder")
                        MapAccessResult(
                            folder = folder,
                            accessible = false,
                            messageCount = 0,
                            messages = emptyList(),
                            requiredAuth = true,
                            testDurationMs = totalDuration,
                        )
                    }
                    response.isOk && response.body != null -> {
                        val messages = parseMapMessages(response.body!!, folder)
                        Timber.i("MAP: retrieved ${messages.size} messages for $folder")
                        MapAccessResult(
                            folder = folder,
                            accessible = true,
                            messageCount = messages.size,
                            messages = messages,
                            requiredAuth = false,
                            testDurationMs = totalDuration,
                        )
                    }
                    response.isOk -> {
                        // OK but no body — folder might be empty
                        MapAccessResult(
                            folder = folder,
                            accessible = true,
                            messageCount = 0,
                            messages = emptyList(),
                            requiredAuth = false,
                            testDurationMs = totalDuration,
                        )
                    }
                    else -> {
                        Timber.w("MAP: unexpected response 0x${response.responseCode.toString(16)} for $folder")
                        MapAccessResult(
                            folder = folder,
                            accessible = false,
                            messageCount = 0,
                            messages = emptyList(),
                            requiredAuth = true,
                            testDurationMs = totalDuration,
                        )
                    }
                }
            } else {
                Timber.w("MAP: no response for $folder")
                MapAccessResult(
                    folder = folder,
                    accessible = false,
                    messageCount = 0,
                    messages = emptyList(),
                    requiredAuth = true,
                    testDurationMs = totalDuration,
                )
            }
        }

        override fun isMapConnected(): Flow<Boolean> = connected

        override suspend fun saveTestReport(report: PbmapTestReport) {
            val updated = savedReports.value.toMutableMap()
            val list = (updated[report.targetDevice] ?: emptyList()).toMutableList()
            list.add(report)
            updated[report.targetDevice] = list
            savedReports.value = updated
        }

        override fun getTestReports(deviceAddress: String): Flow<List<PbmapTestReport>> {
            return savedReports.map { it[deviceAddress] ?: emptyList() }
        }

        // ── Private helpers ──

        /**
         * Maps a MapFolder to its MAP virtual filesystem path.
         */
        private fun folderToPath(folder: MapFolder): String =
            when (folder) {
                MapFolder.INBOX -> "inbox"
                MapFolder.OUTBOX -> "outbox"
                MapFolder.SENT -> "sent"
                MapFolder.DELETED -> "deleted"
                MapFolder.DRAFT -> "draft"
                MapFolder.UNREAD -> "unread"
            }

        /**
         * Builds MAP listing application parameters.
         *
         * Tag 0x01: MaxListCount (2 bytes) — 0xFFFF = max
         * Tag 0x02: ListStartOffset (2 bytes) — 0x0000
         * Tag 0x03: ParameterMask (8 bytes) — request subject, sender, datetime, type
         */
        private fun buildMapListParams(): ByteArray {
            return byteArrayOf(
                // Tag: MaxListCount
                0x01,
                // Length: 2 bytes
                0x02,
                0xFF.toByte(),
                0xFF.toByte(),
                // List all messages
                0x02,
                // Tag: ListStartOffset
                // Length: 2 bytes
                0x02,
                0x00,
                0x00,
                // Start at 0
                0x03,
                // Tag: ParameterMask
                // Length: 8 bytes
                0x08,
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x03.toByte(),
                // Subject | Sender | DateTime | Type bits
                0xD0.toByte(),
                0x00.toByte(),
            )
        }

        /**
         * Parses MAP message listing response (bMessage format).
         */
        private fun parseMapMessages(
            data: ByteArray,
            folder: MapFolder,
        ): List<MessageEntry> {
            val content = String(data, Charsets.UTF_8)
            val messages = mutableListOf<MessageEntry>()
            val entries = content.split("BEGIN:BMSG").filter { it.contains("END:BMSG") }

            for (entry in entries) {
                val message = parseBmessage(entry, folder)
                if (message.sender != null || message.body != null) {
                    messages.add(message)
                }
            }
            return messages
        }

        /**
         * Parses a single bMessage entry.
         */
        private fun parseBmessage(
            entry: String,
            folder: MapFolder,
        ): MessageEntry {
            val lines = entry.lines().map { it.trim() }.filter { it.isNotEmpty() }
            var sender: String? = null
            var subject: String? = null
            var body: String? = null
            var timestamp: Long? = null
            var type = MessageType.UNKNOWN
            var read = false

            for (line in lines) {
                when {
                    line.startsWith("X-MESSAGE-TYPE:") -> {
                        val value = line.substringAfter(":").trim()
                        type =
                            when (value.uppercase()) {
                                "SMS_GSM", "SMS_CDMA" -> MessageType.SMS
                                "MMS" -> MessageType.MMS
                                "EMAIL" -> MessageType.EMAIL
                                else -> MessageType.UNKNOWN
                            }
                    }
                    line.startsWith("X-ORIGINATOR:") -> {
                        sender = line.substringAfter(":").trim().ifBlank { null }
                    }
                    line.startsWith("X-SUBJECT:") -> {
                        subject = line.substringAfter(":").trim().ifBlank { null }
                    }
                    line.startsWith("X-TIMESTAMP:") -> {
                        try {
                            timestamp = parseMapTimestamp(line.substringAfter(":").trim())
                        } catch (_: Exception) {
                            // Ignore parse failures
                        }
                    }
                    line.startsWith("X-READ:") -> {
                        read = line.substringAfter(":").trim() == "1"
                    }
                    line.startsWith("BEGIN:BBODY") -> {
                        // Message body follows
                        val bodyIdx = lines.indexOf(line)
                        val bodyLines = mutableListOf<String>()
                        for (i in bodyIdx + 1 until lines.size) {
                            val l = lines[i]
                            if (l.startsWith("END:BBODY")) break
                            if (l.startsWith("X-BODY;CHARSET=UTF-8:") || l.startsWith("X-BODY:")) {
                                bodyLines.add(l.substringAfter(":").trim())
                            }
                        }
                        body = bodyLines.joinToString("\n").ifBlank { null }
                    }
                }
            }

            return MessageEntry(
                type = type,
                sender = sender,
                subject = subject,
                body = body,
                timestamp = timestamp,
                folder = folder,
                read = read,
            )
        }

        /**
         * Parses MAP timestamp format (e.g., "20260107T120000").
         */
        private fun parseMapTimestamp(value: String): Long {
            if (value.length < 15) return 0L
            val pattern = Regex("(\\d{4})(\\d{2})(\\d{2})T(\\d{2})(\\d{2})(\\d{2})")
            val match = pattern.find(value) ?: return 0L
            val (year, month, day, hour, min, sec) = match.destructured
            // Simple epoch calculation
            return try {
                java.text.SimpleDateFormat("yyyyMMdd'T'HHmmss", java.util.Locale.US)
                    .parse(value)?.time ?: 0L
            } catch (_: Exception) {
                0L
            }
        }

        companion object {
            private val MAP_MSE_UUID: UUID = UUID.fromString("00001132-0000-1000-8000-00805F9B34FB")
        }
    }
