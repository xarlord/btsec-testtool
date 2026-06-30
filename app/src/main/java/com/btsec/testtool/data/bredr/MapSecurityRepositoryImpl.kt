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
import com.btsec.testtool.data.bredr.ObexClient
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
                Timber.i("MAP connected to $deviceAddress")
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
            try {
                socket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing MAP socket")
            }
            socket = null
            connected.value = false
        }

        override suspend fun accessFolder(folder: MapFolder): MapAccessResult {
            val startTime = System.currentTimeMillis()
            Timber.d("accessFolder: $folder")

            val sock = socket ?: return MapAccessResult(
                folder = folder,
                accessible = false,
                messageCount = 0,
                messages = emptyList(),
                requiredAuth = true,
                testDurationMs = System.currentTimeMillis() - startTime,
            )

            return try {
                val obex = ObexClient(sock.inputStream, sock.outputStream)

                // Connect to MAP service
                if (!obex.connect(UUID_MAP)) {
                    Timber.w("MAP OBEX connect failed")
                    return MapAccessResult(
                        folder = folder,
                        accessible = false,
                        messageCount = 0,
                        messages = emptyList(),
                        requiredAuth = true,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                }

                // Build MAP path (MAS folder format)
                val mapPath = when (folder) {
                    MapFolder.INBOX -> "telecom/msg/inbox"
                    MapFolder.SENT -> "telecom/msg/sent"
                    MapFolder.DRAFT -> "telecom/msg/drafts"
                    MapFolder.UNREAD -> "telecom/msg/unread"
                    MapFolder.DELETED -> "telecom/msg/deleted"
                    MapFolder.OUTBOX -> "telecom/msg/outbox"
                }

                // Build application parameters
                // Tag 0x0D = FolderListingSize (0 = all)
                val appParams = byteArrayOf(
                    0x0D, 0x02, 0x00, 0x00, // FolderListingSize = 0 (all)
                )

                // Pull message listing via GET
                val listingData = obex.get(mapPath, appParams)

                if (listingData != null) {
                    // Parse MAP message listing (XML or plain text)
                    val messages = parseMapListing(listingData)

                    obex.disconnect()

                    MapAccessResult(
                        folder = folder,
                        accessible = true,
                        messageCount = messages.size,
                        messages = messages,
                        requiredAuth = false,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                } else {
                    obex.disconnect()
                    MapAccessResult(
                        folder = folder,
                        accessible = false,
                        messageCount = 0,
                        messages = emptyList(),
                        requiredAuth = true,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                }
            } catch (e: Exception) {
                Timber.e(e, "MAP folder access failed")
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

        // ── Private helpers ──

        private fun parseMapListing(listingData: ByteArray): List<MessageEntry> {
            val messages = mutableListOf<MessageEntry>()
            val listing = String(listingData, Charsets.UTF_8)

            // MAP listing can be XML or plain text
            // Try XML format first
            val xmlPattern = """<msg>(.*?)</msg>""".toRegex(RegexOption.DOT_MATCHES_ALL)
            val xmlMatches = xmlPattern.findAll(listing)

            if (xmlMatches.iterator().hasNext()) {
                // XML format
                for (match in xmlMatches) {
                    val msgContent = match.value
                    val sender = msgContent
                        .lines()
                        .find { it.contains("<sender") }
                        ?.let { extractXmlTag(it, "sender") }

                    val subject = msgContent
                        .lines()
                        .find { it.contains("<subject") }
                        ?.let { extractXmlTag(it, "subject") }

                    val timestamp = msgContent
                        .lines()
                        .find { it.contains("<timestamp") }
                        ?.let { extractXmlTag(it, "timestamp") }
                        ?.toLongOrNull()

                    // Determine message type from content
                    val type = when {
                        msgContent.contains("type=\"sms\"", ignoreCase = true) -> MessageType.SMS
                        msgContent.contains("type=\"mms\"", ignoreCase = true) -> MessageType.MMS
                        msgContent.contains("type=\"email\"", ignoreCase = true) -> MessageType.EMAIL
                        else -> MessageType.UNKNOWN
                    }

                    messages.add(MessageEntry(
                        type = type,
                        sender = sender,
                        subject = subject,
                        body = null, // Folder listing doesn't include body
                        timestamp = timestamp,
                        folder = MapFolder.INBOX, // Will be updated by caller
                        read = false,
                    ))
                }
            } else {
                // Plain text format (one message per line)
                val lines = listing.lines()
                for (line in lines) {
                    if (line.isNotBlank()) {
                        val parts = line.split("|")
                        val sender = if (parts.size > 0) parts[0].trim() else null
                        val subject = if (parts.size > 1) parts[1].trim() else null
                        val timestampStr = if (parts.size > 2) parts[2].trim() else null
                        
                        messages.add(MessageEntry(
                            type = MessageType.UNKNOWN,
                            sender = sender,
                            subject = subject,
                            body = null,
                            timestamp = timestampStr?.toLongOrNull(),
                            folder = MapFolder.INBOX,
                            read = false,
                        ))
                    }
                }
            }

            return messages
        }

        private fun extractXmlTag(line: String, tag: String): String {
            val start = line.indexOf(">") + 1
            val end = line.lastIndexOf("<")
            return if (start > 0 && end > start) {
                line.substring(start, end).trim()
            } else {
                ""
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

        companion object {
            private val MAP_MSE_UUID: UUID = UUID.fromString("00001132-0000-1000-8000-00805F9B34FB")
            private const val UUID_MAP = "00001132-0000-1000-8000-00805f9b34fb"
        }
    }
