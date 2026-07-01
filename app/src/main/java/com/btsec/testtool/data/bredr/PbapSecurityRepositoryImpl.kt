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
            val startTime = System.currentTimeMillis()
            Timber.d("accessPhonebook: $phonebookType")

            val sock = socket
            if (sock == null || !connected.value) {
                return PbapAccessResult(
                    phonebookType = phonebookType,
                    accessible = false,
                    entryCount = 0,
                    entries = emptyList(),
                    requiredAuth = true,
                    testDurationMs = System.currentTimeMillis() - startTime,
                )
            }

            return try {
                val obexClient = ObexClient(sock.inputStream, sock.outputStream)
                val connected = obexClient.connect(ObexClient.UUID_PBAP)
                
                if (!connected) {
                    return PbapAccessResult(
                        phonebookType = phonebookType,
                        accessible = false,
                        entryCount = 0,
                        entries = emptyList(),
                        requiredAuth = true,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                }

                // Map phonebook type to OBEX path
                val path = when (phonebookType) {
                    PhonebookType.INTERNAL -> "telecom/pb.vcf"
                    PhonebookType.SIM -> "telecom/pb.vcf"
                    PhonebookType.FAVORITES -> "telecom/fav.vcf"
                    PhonebookType.MISSED_CALLS -> "telecom/mch.vcf"
                    PhonebookType.INCOMING_CALLS -> "telecom/ich.vcf"
                    PhonebookType.OUTGOING_CALLS -> "telecom/och.vcf"
                    PhonebookType.COMBINED -> "telecom/cch.vcf"
                }

                // PBAP application parameters for GetPhonebook
                val appParams = byteArrayOf(0x01, 0x00, 0x02, 0x00, 0x00) // MaxCount = 0 (all)
                val data = obexClient.get(path, appParams)

                obexClient.disconnect()

                if (data != null) {
                    // Parse vCard entries (simplified)
                    val vcardEntries = parseVCardEntries(data)
                    PbapAccessResult(
                        phonebookType = phonebookType,
                        accessible = true,
                        entryCount = vcardEntries.size,
                        entries = vcardEntries,
                        requiredAuth = false,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                } else {
                    PbapAccessResult(
                        phonebookType = phonebookType,
                        accessible = false,
                        entryCount = 0,
                        entries = emptyList(),
                        requiredAuth = true,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                }
            } catch (e: Exception) {
                Timber.w(e, "PBAP access failed")
                PbapAccessResult(
                    phonebookType = phonebookType,
                    accessible = false,
                    entryCount = 0,
                    entries = emptyList(),
                    requiredAuth = true,
                    testDurationMs = System.currentTimeMillis() - startTime,
                )
            }
        }

        private fun parseVCardEntries(data: ByteArray): List<String> {
            val entries = mutableListOf<String>()
            val content = String(data, Charsets.UTF_8)
            val vcards = content.split("BEGIN:VCARD")
            for (vcard in vcards) {
                if (vcard.contains("END:VCARD")) {
                    entries.add("BEGIN:VCARD$vcard")
                }
            }
            return entries
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
