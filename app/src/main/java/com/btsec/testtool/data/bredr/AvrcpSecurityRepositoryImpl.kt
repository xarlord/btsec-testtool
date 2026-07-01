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
            // AVRCP browsing uses a separate BIP channel.
            // Full implementation requires OBEX browsing protocol.
            // This skeleton returns empty list; actual browsing is protocol-level.
            Timber.d("browseMedia: path=$path depth=$depth (stub)")
            return emptyList()
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
