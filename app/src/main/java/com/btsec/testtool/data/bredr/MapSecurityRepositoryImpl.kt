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
 * MAP uses the OBEX protocol to access SMS/MMS/email folders.
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
        private var obexConnectionId = 0
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
                connected.value = true

                // Perform OBEX CONNECT handshake to establish MAP session
                try {
                    val result =
                        ObexProtocol.sendConnect(
                            mapSocket.outputStream,
                            mapSocket.inputStream,
                            maxPacketLength = 0x2000,
                        )
                    obexConnectionId = result.connectionId
                    Timber.i("MAP connected to $deviceAddress (OBEX: ${result.responseCode}, connId=${result.connectionId})")
                } catch (e: Exception) {
                    Timber.w(e, "OBEX CONNECT failed - RFCOMM established but OBEX session not initialized")
                }

                Result.success(Unit)
            } catch (e: SecurityException) {
                Timber.e(e, "Missing Bluetooth permissions")
                Result.failure(e)
            } catch (e: IOException) {
                Timber.e(e, "MAP connection failed")
                Result.failure(e)
            }
        }

        override suspend fun disconnect() {
            socket?.let { sock ->
                try {
                    if (obexConnectionId != 0) {
                        ObexProtocol.sendDisconnect(sock.outputStream, sock.inputStream, obexConnectionId)
                    }
                } catch (e: IOException) {
                    Timber.w(e, "Error sending OBEX DISCONNECT")
                }
            }
            try {
                socket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing MAP socket")
            }
            socket = null
            obexConnectionId = 0
            connected.value = false
        }

        override suspend fun accessFolder(folder: MapFolder): MapAccessResult {
            val startTime = System.currentTimeMillis()
            val sock = socket
            if (sock == null) {
                Timber.w("accessFolder: not connected")
                return MapAccessResult(
                    folder = folder,
                    accessible = false,
                    messageCount = 0,
                    messages = emptyList(),
                    requiredAuth = true,
                    testDurationMs = System.currentTimeMillis() - startTime,
                )
            }

            // Map MapFolder to the MAP virtual folder path + OBEX type
            val (folderPath, obexType) = mapFolderPathForType(folder)

            return try {
                val result =
                    ObexProtocol.sendGet(
                        output = sock.outputStream,
                        input = sock.inputStream,
                        type = obexType,
                        name = folderPath,
                        connectionId = obexConnectionId,
                    )

                val accessible = result.success && result.body.isNotEmpty()
                val messages = if (accessible) parseBMessageEntries(result.body, folder) else emptyList()

                if (accessible) {
                    Timber.i("MAP: Retrieved ${messages.size} messages from $folder (no auth required!)")
                } else {
                    Timber.i("MAP: Folder $folder not accessible (OBEX response: ${result.responseCode})")
                }

                MapAccessResult(
                    folder = folder,
                    accessible = accessible,
                    messageCount = messages.size,
                    messages = messages,
                    requiredAuth = !accessible,
                    testDurationMs = System.currentTimeMillis() - startTime,
                )
            } catch (e: Exception) {
                Timber.w(e, "MAP accessFolder failed for $folder")
                MapAccessResult(
                    folder = folder,
                    accessible = false,
                    messageCount = 0,
                    messages = emptyList(),
                    requiredAuth = true,
                    testDurationMs = System.currentTimeMillis() - startTime,
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

        /**
         * Maps a [MapFolder] to the MAP virtual folder path and OBEX type string.
         * MAP spec defines these folders under telecom/msg/.
         */
        private fun mapFolderPathForType(folder: MapFolder): Pair<String, String> {
            val path =
                when (folder) {
                    MapFolder.INBOX -> "telecom/msg/inbox"
                    MapFolder.OUTBOX -> "telecom/msg/outbox"
                    MapFolder.SENT -> "telecom/msg/sent"
                    MapFolder.DELETED -> "telecom/msg/deleted"
                    MapFolder.DRAFT -> "telecom/msg/draft"
                    MapFolder.UNREAD -> "telecom/msg/inbox" // Unread is typically filtered from inbox
                }
            return path to "x-bt/MAP-msg-listing"
        }

        /**
         * Parses bMessage-format message entries from the OBEX response body.
         * Extracts sender, subject, body, and type from bmsg envelopes.
         */
        private fun parseBMessageEntries(
            body: ByteArray,
            folder: MapFolder,
        ): List<MessageEntry> {
            val text = String(body, Charsets.UTF_8)
            val messages = mutableListOf<MessageEntry>()

            // Split on BEGIN:BMSG
            val bmsgs =
                text.split(Regex("(?i)BEGIN:BMSG"))
                    .drop(1)
                    .mapNotNull { block ->
                        val endMatch = Regex("(?i)END:BMSG").find(block)
                        if (endMatch != null) block.substring(0, endMatch.range.first) else null
                    }

            for (bmsg in bmsgs) {
                var sender: String? = null
                var subject: String? = null
                var bodyText: String? = null
                var type = MessageType.UNKNOWN

                for (line in bmsg.lines()) {
                    val trimmed = line.trim()
                    when {
                        trimmed.startsWith("TYPE:", ignoreCase = true) -> {
                            type =
                                when (trimmed.substringAfter(":").trim().uppercase()) {
                                    "SMS_GSM", "SMS_CDMA", "SMS" -> MessageType.SMS
                                    "MMS" -> MessageType.MMS
                                    "EMAIL" -> MessageType.EMAIL
                                    else -> MessageType.UNKNOWN
                                }
                        }
                        trimmed.startsWith("SUBJECT:", ignoreCase = true) -> {
                            subject = trimmed.substringAfter(":").trim()
                        }
                        trimmed.contains("TEL:", ignoreCase = true) ||
                            trimmed.contains("PARTICIPANT", ignoreCase = true) -> {
                            if (sender == null) sender = trimmed.substringAfter(":").trim().take(50)
                        }
                        trimmed.startsWith("BEGIN:BBODY", ignoreCase = true) -> {
                            // Extract body text until END:BBODY
                            val bodyStart = bmsg.indexOf(trimmed) + trimmed.length
                            val endBodyMatch = Regex("(?i)END:BBODY").find(bmsg, bodyStart)
                            val bodyEnd = endBodyMatch?.range?.first ?: -1
                            if (bodyEnd > bodyStart) {
                                bodyText = bmsg.substring(bodyStart, bodyEnd).trim().take(500)
                            }
                        }
                    }
                }

                messages.add(
                    MessageEntry(
                        type = type,
                        sender = sender,
                        subject = subject,
                        body = bodyText,
                        timestamp = null,
                        folder = folder,
                        read = false,
                    ),
                )
            }

            return messages
        }

        companion object {
            private val MAP_MSE_UUID: UUID = UUID.fromString("00001132-0000-1000-8000-00805F9B34FB")
        }
    }
