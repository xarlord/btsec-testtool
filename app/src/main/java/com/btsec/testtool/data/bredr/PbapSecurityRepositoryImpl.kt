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
import com.btsec.testtool.domain.model.PbapAccessResult
import com.btsec.testtool.domain.model.PbmapTestReport
import com.btsec.testtool.domain.model.PhonebookType
import com.btsec.testtool.domain.repository.PbapSecurityRepository
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
 * Implementation of [PbapSecurityRepository].
 *
 * Connects to PBAP via OBEX/RFCOMM for phonebook access testing.
 * PBAP uses the OBEX protocol over RFCOMM to access phonebook data.
 */
@Singleton
class PbapSecurityRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : PbapSecurityRepository {
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

                val pbapSocket = device.createRfcommSocketToServiceRecord(PBAP_UUID)
                pbapSocket.connect()

                socket = pbapSocket
                connected.value = true
                Timber.i("PBAP connected to $deviceAddress")
                Result.success(Unit)
            } catch (e: SecurityException) {
                Timber.e(e, "Missing Bluetooth permissions")
                Result.failure(e)
            } catch (e: IOException) {
                Timber.e(e, "PBAP connection failed")
                Result.failure(e)
            }
        }

        override suspend fun disconnect() {
            try {
                socket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing PBAP socket")
            }
            socket = null
            connected.value = false
        }

        override suspend fun accessPhonebook(phonebookType: PhonebookType): PbapAccessResult {
            // PBAP access requires OBEX protocol framing.
            // Full implementation needs OBEX CONNECT + PULL operations.
            val startTime = System.currentTimeMillis()
            Timber.d("accessPhonebook: $phonebookType (OBEX framing required)")

            return PbapAccessResult(
                phonebookType = phonebookType,
                accessible = false,
                entryCount = 0,
                entries = emptyList(),
                requiredAuth = null,
                testDurationMs = System.currentTimeMillis() - startTime,
                outcome = com.btsec.testtool.domain.model.EvidenceOutcome.UNSUPPORTED,
                evidenceSource = com.btsec.testtool.domain.model.EvidenceSource.UNAVAILABLE,
                limitation = "PBAP OBEX CONNECT/PULL is not implemented in this build",
                capabilityBoundary = "Requires an authorized target and a native OBEX/RFCOMM implementation",
            )
        }

        override fun isPbapConnected(): Flow<Boolean> = connected

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
            private val PBAP_UUID: UUID = UUID.fromString("0000112F-0000-1000-8000-00805F9B34FB")
        }
    }
