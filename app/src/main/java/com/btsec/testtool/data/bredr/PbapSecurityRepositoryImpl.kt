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
import com.btsec.testtool.domain.model.PhonebookEntry
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
        private var obexConnectionId = 0
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

                // Perform OBEX CONNECT handshake to establish PBAP session
                try {
                    val result =
                        ObexProtocol.sendConnect(
                            pbapSocket.outputStream,
                            pbapSocket.inputStream,
                            maxPacketLength = 0x2000,
                        )
                    obexConnectionId = result.connectionId
                    Timber.i("PBAP connected to $deviceAddress (OBEX: ${result.responseCode}, connId=${result.connectionId})")
                } catch (e: Exception) {
                    Timber.w(e, "OBEX CONNECT failed - RFCOMM established but OBEX session not initialized")
                    // RFCOMM connection itself succeeded; OBEX ops may still fail gracefully
                }

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
            // Send OBEX DISCONNECT before closing the socket
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
                Timber.w(e, "Error closing PBAP socket")
            }
            socket = null
            obexConnectionId = 0
            connected.value = false
        }

        override suspend fun accessPhonebook(phonebookType: PhonebookType): PbapAccessResult {
            val startTime = System.currentTimeMillis()
            val sock = socket
            if (sock == null) {
                Timber.w("accessPhonebook: not connected")
                return PbapAccessResult(
                    phonebookType = phonebookType,
                    accessible = false,
                    entryCount = 0,
                    entries = emptyList(),
                    requiredAuth = true,
                    testDurationMs = System.currentTimeMillis() - startTime,
                )
            }

            // Map PhonebookType to the PBAP virtual folder path + OBEX type
            val (folderPath, obexType) = phonebookPathForType(phonebookType)

            return try {
                // Send OBEX GET request for the phonebook object
                val result =
                    ObexProtocol.sendGet(
                        output = sock.outputStream,
                        input = sock.inputStream,
                        type = obexType,
                        name = folderPath,
                        connectionId = obexConnectionId,
                    )

                val accessible = result.success && result.body.isNotEmpty()
                val entries = if (accessible) parseVCardEntries(result.body) else emptyList()

                if (accessible) {
                    Timber.i("PBAP: Retrieved ${entries.size} entries from $phonebookType (no auth required!)")
                } else {
                    Timber.i("PBAP: Phonebook $phonebookType not accessible (OBEX response: ${result.responseCode})")
                }

                PbapAccessResult(
                    phonebookType = phonebookType,
                    accessible = accessible,
                    entryCount = entries.size,
                    entries = entries,
                    // If we got data without being challenged, auth was NOT required
                    requiredAuth = !accessible,
                    testDurationMs = System.currentTimeMillis() - startTime,
                )
            } catch (e: Exception) {
                Timber.w(e, "PBAP accessPhonebook failed for $phonebookType")
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

        /**
         * Maps a [PhonebookType] to the PBAP virtual folder path and OBEX type string.
         * PBAP spec defines these paths under the telecom/ virtual folder.
         */
        private fun phonebookPathForType(type: PhonebookType): Pair<String, String> {
            val path =
                when (type) {
                    PhonebookType.MAIN_CONTACTS -> "telecom/pb.vcf"
                    PhonebookType.INCOMING_CALLS -> "telecom/ich.vcf"
                    PhonebookType.OUTGOING_CALLS -> "telecom/och.vcf"
                    PhonebookType.MISSED_CALLS -> "telecom/mch.vcf"
                    PhonebookType.COMBINED_CALLS -> "telecom/cch.vcf"
                    PhonebookType.SPEED_DIAL -> "telecom/spd.vcf"
                    PhonebookType.FAVORITES -> "telecom/fav.vcf"
                }
            return path to "x-bt/phonebook"
        }

        /**
         * Parses vCard (VCF) entries from the OBEX response body.
         * Extracts name and phone number from BEGIN:VCARD ... END:VCARD blocks.
         */
        private fun parseVCardEntries(body: ByteArray): List<PhonebookEntry> {
            val text = String(body, Charsets.US_ASCII)
            val entries = mutableListOf<PhonebookEntry>()

            // Split on BEGIN:VCARD
            val vcards =
                text.split(Regex("(?i)BEGIN:VCARD"))
                    .drop(1) // Skip content before first VCARD
                    .mapNotNull { block ->
                        val endMatch = Regex("(?i)END:VCARD").find(block)
                        if (endMatch != null) block.substring(0, endMatch.range.first) else null
                    }

            for (vcard in vcards) {
                var name: String? = null
                val phones = mutableListOf<String>()
                val emails = mutableListOf<String>()

                for (line in vcard.lines()) {
                    val trimmed = line.trim()
                    when {
                        trimmed.startsWith("FN:", ignoreCase = true) ||
                            trimmed.startsWith("N:", ignoreCase = true) -> {
                            if (name == null) name = trimmed.substringAfter(":").replace(";", " ").trim()
                        }
                        trimmed.startsWith("TEL", ignoreCase = true) -> {
                            val number = trimmed.substringAfter(":").trim()
                            if (number.isNotEmpty()) phones.add(number)
                        }
                        trimmed.startsWith("EMAIL", ignoreCase = true) -> {
                            val email = trimmed.substringAfter(":").trim()
                            if (email.isNotEmpty()) emails.add(email)
                        }
                    }
                }

                if (name != null || phones.isNotEmpty()) {
                    entries.add(PhonebookEntry(name = name ?: "Unknown", phoneNumbers = phones, emails = emails))
                }
            }

            return entries
        }

        companion object {
            private val PBAP_UUID: UUID = UUID.fromString("0000112F-0000-1000-8000-00805F9B34FB")
        }
    }
