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
 * Uses [ObexClient] for proper OBEX protocol framing.
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
        private var obexClient: ObexClient? = null
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

                // Perform OBEX CONNECT with PBAP target UUID
                val client = ObexClient(pbapSocket.inputStream, pbapSocket.outputStream)
                val response = client.connect(ObexClient.PBAP_TARGET_UUID)

                if (response != null && response.isOk) {
                    obexClient = client
                    connected.value = true
                    Timber.i("PBAP connected to $deviceAddress via OBEX")
                    Result.success(Unit)
                } else {
                    val code = response?.responseCode
                    pbapSocket.close()
                    socket = null
                    Timber.w("PBAP OBEX CONNECT failed: response code=0x${code?.toString(16) ?: "null"}")
                    Result.failure(Exception("OBEX connect failed: 0x${code?.toString(16) ?: "no response"}"))
                }
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
                obexClient?.disconnect()
                socket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing PBAP socket")
            }
            socket = null
            obexClient = null
            connected.value = false
        }

        override suspend fun accessPhonebook(phonebookType: PhonebookType): PbapAccessResult {
            val startTime = System.currentTimeMillis()
            val client = obexClient

            if (client == null || !client.isConnected()) {
                return PbapAccessResult(
                    phonebookType = phonebookType,
                    accessible = false,
                    entryCount = 0,
                    entries = emptyList(),
                    requiredAuth = true,
                    testDurationMs = System.currentTimeMillis() - startTime,
                )
            }

            val path = phonebookToPath(phonebookType)

            // Build PBAP application parameters: vCard 3.0 filter
            // Filter format: <Filter> (4 bytes) + optional <Format> (1 byte)
            val appParams = buildAppParams(phonebookType)

            val response = client.get(path, appParams)
            val duration = System.currentTimeMillis() - startTime

            return if (response != null) {
                when {
                    response.isUnauthorized -> {
                        Timber.i("PBAP: phonebook access unauthorized for $phonebookType")
                        PbapAccessResult(
                            phonebookType = phonebookType,
                            accessible = false,
                            entryCount = 0,
                            entries = emptyList(),
                            requiredAuth = true,
                            testDurationMs = duration,
                        )
                    }
                    response.isOk && response.body != null -> {
                        val entries = parseVcardEntries(response.body!!, phonebookType)
                        Timber.i("PBAP: retrieved ${entries.size} entries for $phonebookType")
                        PbapAccessResult(
                            phonebookType = phonebookType,
                            accessible = true,
                            entryCount = entries.size,
                            entries = entries,
                            requiredAuth = false,
                            testDurationMs = duration,
                        )
                    }
                    response.isOk -> {
                        // OK but no body — phonebook might be empty
                        PbapAccessResult(
                            phonebookType = phonebookType,
                            accessible = true,
                            entryCount = 0,
                            entries = emptyList(),
                            requiredAuth = false,
                            testDurationMs = duration,
                        )
                    }
                    else -> {
                        Timber.w("PBAP: unexpected response 0x${response.responseCode.toString(16)} for $phonebookType")
                        PbapAccessResult(
                            phonebookType = phonebookType,
                            accessible = false,
                            entryCount = 0,
                            entries = emptyList(),
                            requiredAuth = true,
                            testDurationMs = duration,
                        )
                    }
                }
            } else {
                Timber.w("PBAP: no response for $phonebookType")
                PbapAccessResult(
                    phonebookType = phonebookType,
                    accessible = false,
                    entryCount = 0,
                    entries = emptyList(),
                    requiredAuth = true,
                    testDurationMs = duration,
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

        // ── Private helpers ──

        /**
         * Maps a PhonebookType to its PBAP virtual filesystem path.
         */
        private fun phonebookToPath(type: PhonebookType): String =
            when (type) {
                PhonebookType.MAIN_CONTACTS -> "telecom/pb.vcf"
                PhonebookType.INCOMING_CALLS -> "telecom/ich.vcf"
                PhonebookType.OUTGOING_CALLS -> "telecom/och.vcf"
                PhonebookType.MISSED_CALLS -> "telecom/mch.vcf"
                PhonebookType.COMBINED_CALLS -> "telecom/cch.vcf"
                PhonebookType.SPEED_DIAL -> "telecom/spd.vcf"
                PhonebookType.FAVORITES -> "telecom/fav.vcf"
            }

        /**
         * Builds PBAP application parameters for the GET request.
         *
         * Format: Tag(1) + Length(1) + Value
         * Tag 0x01 = PropertySelector (4 bytes, bitmask of vCard fields)
         * Tag 0x02 = Format (1 byte: 0x00=vCard 2.1, 0x01=vCard 3.0)
         */
        private fun buildAppParams(type: PhonebookType): ByteArray {
            // Request: N, TEL, EMAIL, ORG, NOTE
            val propertySelector = 0x00003FFF.toInt()
            return byteArrayOf(
                // Tag: PropertySelector
                0x01,
                // Length: 4 bytes
                0x04,
                (propertySelector shr 24).toByte(),
                (propertySelector shr 16).toByte(),
                (propertySelector shr 8).toByte(),
                propertySelector.toByte(),
                // Tag: Format
                0x02,
                // Length: 1 byte
                0x01,
                // vCard 2.1
                0x00.toByte(),
            )
        }

        /**
         * Parses vCard 2.1 entries from OBEX GET response body.
         * Extracts name, phone numbers, emails, organization, and notes.
         */
        private fun parseVcardEntries(
            data: ByteArray,
            type: PhonebookType,
        ): List<PhonebookEntry> {
            val entries = mutableListOf<PhonebookEntry>()
            val content = String(data, Charsets.UTF_8)
            val cards = content.split("BEGIN:VCARD").filter { it.contains("END:VCARD") }

            for (card in cards) {
                val entry = parseVcard(card, type)
                if (entry.name.isNotEmpty()) {
                    entries.add(entry)
                }
            }
            return entries
        }

        /**
         * Parses a single vCard entry, extracting fields.
         */
        private fun parseVcard(
            card: String,
            type: PhonebookType,
        ): PhonebookEntry {
            val lines = card.lines().map { it.trim() }.filter { it.isNotEmpty() }
            val phones = mutableListOf<String>()
            val emails = mutableListOf<String>()
            var name = ""
            var organization: String? = null
            var note: String? = null

            for (line in lines) {
                // Handle folded lines (continuation lines start with space/tab)
                if (line.startsWith("FN:") || line.startsWith("N:")) {
                    val value = extractVcardValue(line)
                    // Extract the primary name from N:Last;First;;; or FN:First Last
                    name = value.split(";").firstOrNull()?.trim() ?: value
                }
                if (line.startsWith("TEL")) {
                    val value = extractVcardValue(line)
                    if (value.isNotEmpty()) phones.add(value)
                }
                if (line.startsWith("EMAIL")) {
                    val value = extractVcardValue(line)
                    if (value.isNotEmpty()) emails.add(value)
                }
                if (line.startsWith("ORG:")) {
                    organization = extractVcardValue(line).ifBlank { null }
                }
                if (line.startsWith("NOTE:")) {
                    note = extractVcardValue(line).ifBlank { null }
                }
            }

            return PhonebookEntry(
                name = name,
                phoneNumbers = phones,
                emails = emails,
                organization = organization,
                note = note,
            )
        }

        /**
         * Extracts the value portion of a vCard property line.
         * Handles parameter prefixes like TEL;TYPE=CELL:+1234 → +1234
         */
        private fun extractVcardValue(line: String): String {
            val colonIdx = line.indexOf(':')
            if (colonIdx < 0) return ""
            // Skip past property parameters (everything before the colon after the property name)
            return line.substring(colonIdx + 1).trim()
        }

        companion object {
            private val PBAP_UUID: UUID = UUID.fromString("0000112F-0000-1000-8000-00805F9B34FB")
        }
    }
