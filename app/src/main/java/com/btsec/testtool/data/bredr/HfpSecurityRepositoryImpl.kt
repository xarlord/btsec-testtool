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
import com.btsec.testtool.domain.model.HfpTestSuite
import com.btsec.testtool.domain.repository.HfpSecurityRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withTimeoutOrNull
import timber.log.Timber
import java.io.IOException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [HfpSecurityRepository].
 *
 * Connects to HFP via RFCOMM and provides AT command send/receive
 * capabilities for security testing.
 */
@Singleton
class HfpSecurityRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : HfpSecurityRepository {
        private val bluetoothManager: BluetoothManager =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

        private val connected = MutableStateFlow(false)
        private var socket: BluetoothSocket? = null
        private val savedSuites = MutableStateFlow<Map<String, List<HfpTestSuite>>>(emptyMap())

        @SuppressLint("MissingPermission")
        override suspend fun connect(deviceAddress: String): Result<Unit> {
            return try {
                disconnect()
                val device =
                    bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                        ?: return Result.failure(Exception("Device not found: $deviceAddress"))

                val hfpSocket = device.createRfcommSocketToServiceRecord(HFP_UUID)
                hfpSocket.connect()

                socket = hfpSocket
                connected.value = true
                Timber.i("HFP connected to $deviceAddress")
                Result.success(Unit)
            } catch (e: SecurityException) {
                Timber.e(e, "Missing Bluetooth permissions")
                Result.failure(e)
            } catch (e: IOException) {
                Timber.e(e, "HFP connection failed")
                Result.failure(e)
            }
        }

        override suspend fun disconnect() {
            try {
                socket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing HFP socket")
            }
            socket = null
            connected.value = false
        }

        override suspend fun sendAtCommand(
            command: String,
            timeoutMs: Long,
        ): Result<String?> {
            val sock = socket ?: return Result.failure(Exception("Not connected"))
            return try {
                val output = sock.outputStream
                val input = sock.inputStream

                output.write("$command\r\n".toByteArray())
                output.flush()

                val buffer = ByteArray(4096)
                val response =
                    withTimeoutOrNull(timeoutMs) {
                        val read = input.read(buffer)
                        if (read > 0) String(buffer, 0, read) else null
                    }
                Result.success(response?.trim())
            } catch (e: IOException) {
                Timber.w(e, "AT command send failed: $command")
                Result.failure(e)
            }
        }

        override fun isHfpConnected(): Flow<Boolean> = connected

        override suspend fun saveTestSuite(suite: HfpTestSuite) {
            val updated = savedSuites.value.toMutableMap()
            val list = (updated[suite.deviceAddress] ?: emptyList()).toMutableList()
            list.add(suite)
            updated[suite.deviceAddress] = list
            savedSuites.value = updated
        }

        override fun getTestSuites(deviceAddress: String): Flow<List<HfpTestSuite>> {
            return savedSuites.map { it[deviceAddress] ?: emptyList() }
        }

        override fun getAllTestSuites(): Flow<List<HfpTestSuite>> {
            return savedSuites.map { it.values.flatten() }
        }

        companion object {
            private val HFP_UUID: UUID = UUID.fromString("0000111E-0000-1000-8000-00805F9B34FB")
        }
    }
