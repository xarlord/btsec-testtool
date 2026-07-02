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
import com.btsec.testtool.domain.repository.AvrcpSecurityRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import timber.log.Timber
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [AvrcpSecurityRepository].
 *
 * Connects to AVRCP for media browsing and control testing.
 * AVRCP uses both control (CT/TG) and browsing (BIP) channels.
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
        private val savedReports = MutableStateFlow<Map<String, List<AvrcpTestReport>>>(emptyMap())

        @SuppressLint("MissingPermission")
        override suspend fun connect(deviceAddress: String): Result<Unit> {
            return try {
                disconnect()
                val device =
                    bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                        ?: return Result.failure(Exception("Device not found: $deviceAddress"))

                val ctrl = device.createRfcommSocketToServiceRecord(AVRCP_CT_UUID)
                ctrl.connect()
                controlSocket = ctrl

                // Also connect to browsing channel if available
                try {
                    val browse = device.createRfcommSocketToServiceRecord(AVRCP_BROWSE_UUID)
                    browse.connect()
                    browseSocket = browse
                    Timber.i("AVRCP browsing channel connected")
                } catch (e: IOException) {
                    Timber.w("AVRCP browsing channel not available: ${e.message}")
                }

                connected.value = true

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
                controlSocket?.close()
                browseSocket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing AVRCP socket")
            }
            controlSocket = null
            browseSocket = null
            connected.value = false
        }

        override suspend fun browseMedia(
            path: String,
            depth: Int,
        ): List<AvrcpMediaItem> {
            val sock = browseSocket
            if (sock == null) {
                Timber.w("AVRCP browsing socket not connected")
                return emptyList()
            }

            return try {
                // AVRCP Browsing (BIP) uses OBEX-like protocol over dedicated channel
                val obexClient = ObexClient(sock.inputStream, sock.outputStream)
                val connected = obexClient.connect(AVRCP_BROWSE_UUID.toString())

                if (!connected) {
                    Timber.w("AVRCP OBEX browsing connection failed")
                    return emptyList()
                }

                // Build AVRCP browsing GET request
                // Path format: /Item=VirtualFilesystem (root), /Item=Folder_UUID
                val browsePath = if (path.isEmpty() || path == "/") "/Item=VirtualFilesystem" else path
                val appParams = buildBrowseAppParams(depth)

                val data = obexClient.get(browsePath, appParams)
                obexClient.disconnect()

                if (data != null) {
                    val items = parseBrowsingData(data, browsePath)
                    Timber.d("AVRCP browse: found ${items.size} items at $browsePath")
                    items
                } else {
                    Timber.w("AVRCP browse: no data returned")
                    emptyList()
                }
            } catch (e: Exception) {
                Timber.w(e, "AVRCP browsing failed")
                emptyList()
            }
        }

        /**
         * Build AVRCP browsing application parameters.
         * Format: [Tag-Length-Value] tuples for depth, folder UID, etc.
         */
        private fun buildBrowseAppParams(depth: Int): ByteArray {
            val params = ByteArrayOutputStream()
            // Depth parameter (Tag 0x01, Length 0x01, Value)
            params.write(0x01) // Tag: Depth
            params.write(0x01) // Length: 1 byte
            params.write(depth.coerceIn(0, 255).toByte())
            return params.toByteArray()
        }

        /**
         * Parse AVRCP browsing response data.
         * Extracts media item metadata from OBEX response.
         */
        private fun parseBrowsingData(data: ByteArray, parentPath: String): List<AvrcpMediaItem> {
            val items = mutableListOf<AvrcpMediaItem>()
            val content = String(data, Charsets.UTF_8)

            // Parse AVRCP browsing folder listing format
            // Each item: uid=xxx,name=xxx,type=xxx
            val lines = content.split("\n")
            for (line in lines) {
                if (line.trim().isEmpty() || line.startsWith("#")) continue

                val item = parseBrowsingLine(line, parentPath)
                if (item != null) {
                    items.add(item)
                }
            }

            return items
        }

        /**
         * Parse a single browsing line into an AvrcpMediaItem.
         * Format: uid=123,name=My Folder,type=folder/item
         */
        private fun parseBrowsingLine(line: String, parentPath: String): AvrcpMediaItem? {
            val parts = line.split(",").map { it.trim() }
            var uid: String? = null
            var name: String? = null
            var type: String? = null

            for (part in parts) {
                val keyValue = part.split("=")
                if (keyValue.size == 2) {
                    when (keyValue[0].lowercase()) {
                        "uid" -> uid = keyValue[1]
                        "name" -> name = keyValue[1]
                        "type" -> type = keyValue[1]
                    }
                }
            }

            return if (uid != null && name != null && type != null) {
                AvrcpMediaItem(
                    uid = uid,
                    name = name,
                    type = type,
                    path = "$parentPath/$uid",
                    playable = type == "item",
                )
            } else {
                null
            }
        }

        override suspend fun sendMediaCommand(command: String): Result<Unit> {
            val sock = controlSocket ?: return Result.failure(Exception("Not connected"))
            return try {
                val output = sock.outputStream
                // AVRCP commands are binary packets (AV/C protocol)
                // This is a simplified interface; real AVRCP uses AV/C frames
                Timber.d("sendMediaCommand: $command")
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

        companion object {
            private val AVRCP_CT_UUID: UUID = UUID.fromString("0000110E-0000-1000-8000-00805F9B34FB")
            private val AVRCP_BROWSE_UUID: UUID = UUID.fromString("0000110F-0000-1000-8000-00805F9B34FB")
        }
    }
