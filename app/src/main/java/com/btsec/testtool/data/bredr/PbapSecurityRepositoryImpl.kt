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

            val sock = socket ?: return PbapAccessResult(
                phonebookType = phonebookType,
                accessible = false,
                entryCount = 0,
                entries = emptyList(),
                requiredAuth = true,
                testDurationMs = System.currentTimeMillis() - startTime,
            )

            return try {
                val obex = ObexClient(sock.inputStream, sock.outputStream)

                // Connect to PBAP service
                if (!obex.connect(UUID_PBAP)) {
                    Timber.w("PBAP OBEX connect failed")
                    return PbapAccessResult(
                        phonebookType = phonebookType,
                        accessible = false,
                        entryCount = 0,
                        entries = emptyList(),
                        requiredAuth = true,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                }

                // Build PBAP path (PCE path format)
                val pbapPath = when (phonebookType) {
                    PhonebookType.MAIN_CONTACTS -> "telecom/pb.vcf"
                    PhonebookType.INCOMING_CALLS -> "telecom/ich.vcf"
                    PhonebookType.OUTGOING_CALLS -> "telecom/och.vcf"
                    PhonebookType.MISSED_CALLS -> "telecom/mch.vcf"
                    PhonebookType.COMBINED_CALLS -> "telecom/cch.vcf"
                    PhonebookType.SPEED_DIAL -> "telecom/spd.vcf"
                    PhonebookType.FAVORITES -> "telecom/fav.vcf"
                }

                // Build application parameters
                // Format: [Tag(1)] [Length(1)] [Value]
                // Tag 0x01 = MaxListCount, Tag 0x02 = ListStartOffset
                val appParams = byteArrayOf(
                    0x01, 0x02, 0x00, 0x00, // MaxListCount = 0 (all entries)
                    0x02, 0x02, 0x00, 0x00, // ListStartOffset = 0
                )

                // Pull phonebook data via GET
                val vcfData = obex.get(pbapPath, appParams)

                if (vcfData != null) {
                    // Parse vCard entries (v2.1 or v3.0)
                    val entries = parseVCardEntries(vcfData)

                    obex.disconnect()

                    PbapAccessResult(
                        phonebookType = phonebookType,
                        accessible = true,
                        entryCount = entries.size,
                        entries = entries,
                        requiredAuth = false,
                        testDurationMs = System.currentTimeMillis() - startTime,
                    )
                } else {
                    obex.disconnect()
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
                Timber.e(e, "PBAP phonebook access failed")
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

        // ── Private helpers ──

        private fun parseVCardEntries(vcfData: ByteArray): List<PhonebookEntry> {
            val entries = mutableListOf<PhonebookEntry>()
            val vcf = String(vcfData, Charsets.UTF_8)

            // vCard entries are separated by BEGIN:VCARD and END:VCARD
            val vcardPattern = """BEGIN:VCARD.*?END:VCARD""".toRegex(RegexOption.DOT_MATCHES_ALL)
            val matches = vcardPattern.findAll(vcf)

            for (match in matches) {
                val vcard = match.value

                // Extract FN (Full Name) and TEL (Telephone) fields
                val fn = vcard.lines()
                    .find { it.startsWith("FN:") || it.startsWith("FN;") }
                    ?.substringAfter(":")
                    ?.trim()

                val tels = vcard.lines()
                    .filter { it.startsWith("TEL") }
                    .mapNotNull { line ->
                        val parts = line.split(":")
                        if (parts.size >= 2) parts.last().trim() else null
                    }

                val emails = vcard.lines()
                    .filter { it.startsWith("EMAIL") }
                    .mapNotNull { line ->
                        val parts = line.split(":")
                        if (parts.size >= 2) parts.last().trim() else null
                    }

                if (fn != null || tels.isNotEmpty()) {
                    entries.add(PhonebookEntry(
                        name = fn ?: "",
                        phoneNumbers = tels,
                        emails = emails,
                        organization = null,
                        note = null,
                    ))
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
            private const val UUID_PBAP = "0000112f-0000-1000-8000-00805f9b34fb"
        }
    }
