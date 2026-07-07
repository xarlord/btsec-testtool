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
import com.btsec.testtool.domain.model.AvrcpMediaItem
import com.btsec.testtool.domain.model.AvrcpTestReport
import com.btsec.testtool.domain.model.MediaItemType
import com.btsec.testtool.domain.repository.AvrcpSecurityRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withTimeoutOrNull
import timber.log.Timber
import java.io.IOException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [AvrcpSecurityRepository].
 *
 * Connects to AVRCP for media browsing and control testing.
 * AVRCP uses a control channel (AVRCP CT via RFCOMM) and a
 * browsing channel (BIP via OBEX/RFCOMM).
 *
 * Control commands use AV/C framing over the control socket.
 * Media browsing uses OBEX protocol over the browse socket.
 */
@Singleton
class AvrcpSecurityRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : AvrcpSecurityRepository {
        private val bluetoothManager: BluetoothManager =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

        private val connected = MutableStateFlow(false)
        private var controlSocket: BluetoothSocket? = null
        private var browseSocket: BluetoothSocket? = null
        private var obexClient: ObexClient? = null
        private val savedReports = MutableStateFlow<Map<String, List<AvrcpTestReport>>>(emptyMap())

        @SuppressLint("MissingPermission")
        override suspend fun connect(deviceAddress: String): Result<Unit> {
            return try {
                disconnect()
                val device =
                    bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                        ?: return Result.failure(Exception("Device not found: $deviceAddress"))

                // Connect control channel
                val ctrl = device.createRfcommSocketToServiceRecord(AVRCP_CT_UUID)
                ctrl.connect()
                controlSocket = ctrl
                connected.value = true

                // Attempt to connect browse channel (non-fatal if unavailable)
                try {
                    val browse = device.createRfcommSocketToServiceRecord(AVRCP_BROWSE_UUID)
                    browse.connect()
                    browseSocket = browse

                    // OBEX CONNECT for browsing
                    val client = ObexClient(browse.inputStream, browse.outputStream)
                    val response = client.connect(ObexClient.AVRCP_BROWSING_TARGET_UUID)
                    if (response != null && response.isOk) {
                        obexClient = client
                        Timber.i("AVRCP browse channel connected to $deviceAddress")
                    } else {
                        browse.close()
                        browseSocket = null
                        Timber.w("AVRCP browse OBEX CONNECT failed for $deviceAddress")
                    }
                } catch (e: IOException) {
                    // Browse channel is optional per AVRCP 1.5 spec
                    Timber.d("AVRCP browse channel not available: ${e.message}")
                }

                Timber.i("AVRCP connected to $deviceAddress")
                Result.success(Unit)
            } catch (e: SecurityException) {
                Timber.e(e, "Missing Bluetooth permissions")
                Result.failure(e)
            } catch (e: IOException) {
                Timber.e(e, "AVRCP connection failed")
                Result.failure(e)
            }
        }

        override suspend fun disconnect() {
            try {
                obexClient?.disconnect()
                controlSocket?.close()
                browseSocket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing AVRCP socket")
            }
            controlSocket = null
            browseSocket = null
            obexClient = null
            connected.value = false
        }

        override suspend fun browseMedia(
            path: String,
            depth: Int,
        ): List<AvrcpMediaItem> {
            val client = obexClient
            if (client == null || !client.isConnected()) {
                Timber.d("browseMedia: browse channel not connected (path=$path depth=$depth)")
                return emptyList()
            }

            return try {
                // OBEX BROWSE uses GET with virtual folder path
                // AVRCP browsing: "/" for root, "/VirtualFileSystem" for filesystem
                val browsePath = if (path == "/") "VirtualFileSystem" else path.removePrefix("/")
                val response = client.get(browsePath)

                if (response != null && response.isOk && response.body != null) {
                    val items = parseAvrcpBrowseResponse(response.body!!)
                    Timber.i("AVRCP browse: found ${items.size} items at $browsePath")
                    items
                } else {
                    Timber.d("AVRCP browse: no data for $browsePath (code=0x${response?.responseCode?.toString(16) ?: "null"})")
                    emptyList()
                }
            } catch (e: Exception) {
                Timber.w(e, "AVRCP browseMedia failed for path=$path")
                emptyList()
            }
        }

        override suspend fun sendMediaCommand(command: String): Result<Unit> {
            val sock = controlSocket ?: return Result.failure(Exception("Not connected"))
            return try {
                val output = sock.outputStream

                // Build AV/C command frame
                // AV/C format: [ctype(1)] [subunit_type|subunit_id(1)] [opcode(1)] [operands]
                val avcFrame = buildAvcFrame(command)
                output.write(avcFrame)
                output.flush()

                // Read AV/C response
                val input = sock.inputStream
                val buffer = ByteArray(64)
                val read = withTimeoutOrNull(500L) {
                    input.read(buffer)
                }
                if (read != null && read > 0) {
                    val responseCode = buffer[0].toInt() and 0x0F
                    Timber.d("AVRCP command response: ctype=0x${responseCode.toString(16)}")
                }

                Timber.d("AVRCP sendMediaCommand: $command (${avcFrame.size} bytes)")
                Result.success(Unit)
            } catch (e: IOException) {
                Timber.w(e, "AVRCP command failed")
                Result.failure(e)
            }
        }

        override fun isAvrcpConnected(): Flow<Boolean> = connected

        override suspend fun saveTestReport(report: AvrcpTestReport) {
            val updated = savedReports.value.toMutableMap()
            val list = (updated[report.targetDevice] ?: emptyList()).toMutableList()
            list.add(report)
            updated[report.targetDevice] = list
            savedReports.value = updated
        }

        override fun getTestReports(deviceAddress: String): Flow<List<AvrcpTestReport>> {
            return savedReports.map { it[deviceAddress] ?: emptyList() }
        }

        // ── Private helpers ──

        /**
         * Builds an AV/C command frame for common media commands.
         *
         * AV/C frame format (AVRCP over L2CAP/RFCOMM):
         * - Byte 0: CType (Command Type) | Address
         * - Byte 1: Subunit type (0x09 for PANEL) | Subunit ID (0x00)
         * - Byte 2: Opcode
         * - Remaining: Operand(s)
         */
        private fun buildAvcFrame(command: String): ByteArray {
            val opcode: Byte
            val operands: ByteArray

            when (command.lowercase()) {
                "play" -> {
                    opcode = 0x7C // VENDOR DEPENDENT
                    operands = byteArrayOf(
                        0x00, 0x00, // Company ID (minimum 3 bytes for vendor)
                        0x09, 0x00, // Play opcode (AVRCP Play)
                    )
                }
                "pause" -> {
                    opcode = 0x7C // VENDOR DEPENDENT
                    operands = byteArrayOf(
                        0x00, 0x00,
                        0x09, 0x00, // Pause opcode (AVRCP Pause)
                    )
                }
                "stop" -> {
                    opcode = 0x7E // VENDOR DEPENDENT
                    operands = byteArrayOf(
                        0x00, 0x00,
                        0x09, 0x00, // Stop opcode
                    )
                }
                "next" -> {
                    opcode = 0x7C
                    operands = byteArrayOf(
                        0x00, 0x00,
                        0x09, 0x00, // Next Track
                    )
                }
                "previous" -> {
                    opcode = 0x7C
                    operands = byteArrayOf(
                        0x00, 0x00,
                        0x09, 0x00, // Previous Track
                    )
                }
                "volume_up" -> {
                    opcode = 0x7C
                    operands = byteArrayOf(
                        0x00, 0x00,
                        0x09, 0x00, // Volume Up
                    )
                }
                "volume_down" -> {
                    opcode = 0x7C
                    operands = byteArrayOf(
                        0x00, 0x00,
                        0x09, 0x00, // Volume Down
                    )
                }
                else -> {
                    // Generic pass-through for unrecognized commands
                    opcode = 0x7C
                    operands = byteArrayOf(
                        0x00, 0x00,
                        0x00, command.toByteArray(Charsets.UTF_8).firstOrNull()?.toByte() ?: 0x00,
                    )
                }
            }

            return byteArrayOf(
                0x00, // CType: CONTROL (0x00)
                0x09, // Subunit type: PANEL (0x09) | ID: 0x00
                opcode,
                *operands,
            )
        }

        /**
         * Parses AVRCP browsing response (media element tree items).
         *
         * Each item in the browse response has the format:
         * [ItemType(1)] [Length(2)] [UID(8)] [Attributes...]
         */
        private fun parseAvrcpBrowseResponse(data: ByteArray): List<AvrcpMediaItem> {
            val items = mutableListOf<AvrcpMediaItem>()
            var offset = 0

            while (offset + 3 < data.size) {
                val itemType = data[offset].toInt() and 0xFF
                offset++
                val itemLen = ((data[offset].toInt() and 0xFF) shl 8) or
                    (data[offset + 1].toInt() and 0xFF)
                offset += 2

                if (offset + itemLen > data.size) break
                if (itemLen < 8) {
                    offset += itemLen
                    continue
                }

                // Extract UID (8 bytes, big-endian)
                var uid = 0L
                for (i in 0 until 8) {
                    uid = (uid shl 8) or (data[offset + i].toInt() and 0xFF)
                }
                offset += 8

                // Parse attributes (type-length-value triples)
                var attrOffset = offset
                val remainingLen = itemLen - 8
                val attrs = mutableMapOf<Int, String>()

                while (attrOffset + 4 <= offset + remainingLen) {
                    val attrId = data[attrOffset].toInt() and 0xFF
                    attrOffset++
                    val charSetId = data[attrOffset].toInt() and 0xFF
                    attrOffset++
                    val attrLen = ((data[attrOffset].toInt() and 0xFF) shl 16) or
                        ((data[attrOffset + 1].toInt() and 0xFF) shl 8) or
                        (data[attrOffset + 2].toInt() and 0xFF)
                    attrOffset += 3

                    if (attrLen > 0 && attrOffset + attrLen <= offset + remainingLen) {
                        val attrValue = String(data, attrOffset, attrLen, Charsets.UTF_16BE)
                            .trimEnd('\u0000')
                        attrs[attrId] = attrValue
                        attrOffset += attrLen
                    }
                }

                val mediaType = when (itemType) {
                    0x01 -> MediaItemType.FOLDER
                    0x02 -> MediaItemType.TRACK
                    else -> MediaItemType.UNKNOWN
                }

                items.add(
                    AvrcpMediaItem(
                        uid = uid,
                        title = attrs[0x01], // Media Attribute ID: Title
                        artist = attrs[0x02], // Artist
                        album = attrs[0x03], // Album
                        genre = attrs[0x04], // Genre
                        trackNumber = attrs[0x05]?.toIntOrNull(),
                        duration = attrs[0x06]?.toIntOrNull(),
                        type = mediaType,
                        path = attrs[0x07], // Folder path
                    ),
                )

                offset += remainingLen
            }

            return items
        }

        companion object {
            private val AVRCP_CT_UUID: UUID = UUID.fromString("0000110E-0000-1000-8000-00805F9B34FB")
            private val AVRCP_BROWSE_UUID: UUID = UUID.fromString("0000110B-0000-1000-8000-00805F9B34FB")
        }
    }
