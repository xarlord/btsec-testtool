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

            val sock = socket
            if (sock == null || !connected.value) {
                return MapAccessResult(
                    folder = folder,
                    accessible = false,
                    messageCount = 0,
                    messages = emptyList(),
                    requiredAuth = true,
                    testDurationMs = System.currentTimeMillis() - startTime,
                )
            }

            return try {
                val obexClient = ObexClient(sock.inputStream, sock.outputStream)
                val connected = obexClient.connect(ObexClient.UUID_MAP)
                
                if (!connected) {
                    return MapAccessResult(
                        folder = folder,
                        accessible = false,
                        messageCount = 0,
                        messages = emptyList(),
                        requiredAuth = true,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                }

                // Map folder type to OBEX path
                val path = when (folder) {
                    MapFolder.INBOX -> "inbox"
                    MapFolder.SENT -> "sent"
                    MapFolder.DRAFTS -> "drafts"
                    MapFolder.DELETED -> "deleted"
                    MapFolder.TEMPLATE -> "template"
                    MapFolder.OUTBOX -> "outbox"
                }

                // MAP application parameters for GetFolderListing
                val appParams = byteArrayOf(0x02, 0x00, 0x02, 0x00, 0x00) // MaxListCount = 0 (all)
                val data = obexClient.get(path, appParams)

                obexClient.disconnect()

                if (data != null) {
                    // Parse message listing (simplified)
                    val messageEntries = parseMessageListing(data)
                    MapAccessResult(
                        folder = folder,
                        accessible = true,
                        messageCount = messageEntries.size,
                        messages = messageEntries,
                        requiredAuth = false,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                } else {
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
                Timber.w(e, "MAP access failed")
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

        private fun parseMessageListing(data: ByteArray): List<String> {
            val entries = mutableListOf<String>()
            val content = String(data, Charsets.UTF_8)
            // Parse simple text-based MAP listing (one entry per line)
            val lines = content.split("\n")
            for (line in lines) {
                val trimmed = line.trim()
                if (trimmed.isNotEmpty()) {
                    entries.add(trimmed)
                }
            }
            return entries
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
        }
    }
