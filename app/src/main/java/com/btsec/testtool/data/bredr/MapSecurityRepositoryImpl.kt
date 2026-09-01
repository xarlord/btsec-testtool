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
            Timber.d("accessFolder: $folder (OBEX framing required)")

            return MapAccessResult(
                folder = folder,
                accessible = false,
                messageCount = 0,
                messages = emptyList(),
                requiredAuth = null,
                testDurationMs = System.currentTimeMillis() - startTime,
                outcome = com.btsec.testtool.domain.model.EvidenceOutcome.UNSUPPORTED,
                evidenceSource = com.btsec.testtool.domain.model.EvidenceSource.UNAVAILABLE,
                limitation = "MAP OBEX CONNECT/GET is not implemented in this build",
                capabilityBoundary = "Requires an authorized target and a native OBEX/RFCOMM implementation",
            )
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
