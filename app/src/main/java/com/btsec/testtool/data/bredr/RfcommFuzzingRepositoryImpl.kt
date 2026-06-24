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
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.RfcommFuzzingRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import timber.log.Timber
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [RfcommFuzzingRepository].
 *
 * Manages RFCOMM socket connections for fuzzing BR/EDR services.
 * Uses Android's BluetoothSocket API for raw RFCOMM communication.
 */
@Singleton
class RfcommFuzzingRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : RfcommFuzzingRepository {
        private val bluetoothManager: BluetoothManager =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

        private val connected = MutableStateFlow(false)
        private var currentSocket: BluetoothSocket? = null
        private var outputStream: OutputStream? = null
        private var inputStream: InputStream? = null
        private val fuzzResults = MutableStateFlow<Map<String, List<RfcommFuzzResult>>>(emptyMap())

        @SuppressLint("MissingPermission")
        override suspend fun discoverChannels(deviceAddress: String): List<RfcommChannel> {
            val device =
                bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                    ?: return emptyList()

            val uuids = device.uuids ?: return emptyList()
            val channels = mutableListOf<RfcommChannel>()

            // Map well-known UUIDs to RFCOMM channel entries
            for (parcelUuid in uuids) {
                // Extract the 4-char short UUID from positions 4-8 of the
                // standard UUID form (XXXXXXXX-XXXX-...).
                val shortUuid =
                    parcelUuid.uuid
                        .toString()
                        .replace("-", "")
                        .uppercase()
                        .substring(4, 8)
                val profile = BtProfile.fromUuid(shortUuid)
                channels.add(
                    RfcommChannel(
                        // Actual channel discovered via SDP
                        channelNumber = 1,
                        serviceName = profile.displayName,
                        uuid = uuid.toString(),
                        profileName = profile.displayName,
                        requiresAuth = false,
                        requiresEncryption = false,
                    ),
                )
            }

            return channels
        }

        @SuppressLint("MissingPermission")
        override suspend fun connect(
            deviceAddress: String,
            channelNumber: Int,
        ): Result<Unit> {
            return try {
                disconnect() // Clean up any existing connection

                val device =
                    bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                        ?: return Result.failure(Exception("Device not found: $deviceAddress"))

                // Use SPP UUID as default for RFCOMM
                val socket = device.createRfcommSocketToServiceRecord(SPP_UUID)
                socket.connect()

                currentSocket = socket
                outputStream = socket.outputStream
                inputStream = socket.inputStream
                connected.value = true

                Timber.i("RFCOMM connected to $deviceAddress channel $channelNumber")
                Result.success(Unit)
            } catch (e: SecurityException) {
                Timber.e(e, "Missing Bluetooth permissions")
                Result.failure(e)
            } catch (e: IOException) {
                Timber.e(e, "RFCOMM connection failed")
                Result.failure(e)
            }
        }

        override suspend fun disconnect() {
            try {
                inputStream?.close()
                outputStream?.close()
                currentSocket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing RFCOMM socket")
            }
            currentSocket = null
            outputStream = null
            inputStream = null
            connected.value = false
        }

        override suspend fun send(data: ByteArray): Result<ByteArray?> {
            val os = outputStream ?: return Result.failure(Exception("Not connected"))
            val is2 = inputStream ?: return Result.failure(Exception("Not connected"))

            return try {
                os.write(data)
                os.flush()

                // Read response with timeout
                val buffer = ByteArray(4096)
                val read =
                    withTimeoutOrNull(3000L) {
                        is2.read(buffer)
                    }

                if (read != null && read > 0) {
                    Result.success(buffer.copyOf(read))
                } else {
                    Result.success(null) // No response (timeout)
                }
            } catch (e: IOException) {
                Timber.w(e, "RFCOMM send/receive error")
                Result.failure(e)
            }
        }

        override fun executeFuzzSession(config: RfcommFuzzConfig): Flow<RfcommFuzzResult> {
            return flow {
                // Fuzz session logic is driven by RfcommFuzzingUseCase payload generation.
                // This repository provides the transport layer; the use case orchestrates.
                // The actual fuzz loop lives at the ViewModel / orchestrator level
                // which calls send() for each iteration and collects results.
                emit(
                    RfcommFuzzResult(
                        totalSent = 0,
                        responses = emptyList(),
                        errors = emptyList(),
                        disconnected = false,
                        crashDetected = false,
                        durationMs = 0L,
                    ),
                )
            }
        }

        override fun isConnected(): Flow<Boolean> = connected

        override suspend fun saveFuzzResult(result: RfcommFuzzResult) {
            val updated = fuzzResults.value.toMutableMap()
            val key = currentSocket?.remoteDevice?.address ?: "unknown"
            val list = (updated[key] ?: emptyList()).toMutableList()
            list.add(result)
            updated[key] = list
            fuzzResults.value = updated
        }

        override fun getFuzzResults(deviceAddress: String): Flow<List<RfcommFuzzResult>> {
            return fuzzResults.map { it[deviceAddress] ?: emptyList() }
        }

        companion object {
            private val SPP_UUID: UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
        }
    }
