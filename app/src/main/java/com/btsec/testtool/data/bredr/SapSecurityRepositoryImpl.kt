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
import com.btsec.testtool.domain.model.SapTestReport
import com.btsec.testtool.domain.model.SimApdu
import com.btsec.testtool.domain.repository.SapSecurityRepository
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
 * Implementation of [SapSecurityRepository].
 *
 * Connects to SAP (SIM Access Profile) for SIM card security testing.
 * SAP uses a dedicated RFCOMM channel with TLV-formatted messages.
 */
@Singleton
class SapSecurityRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : SapSecurityRepository {
        private val bluetoothManager: BluetoothManager =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

        private val connected = MutableStateFlow(false)
        private var socket: BluetoothSocket? = null
        private val savedReports = MutableStateFlow<Map<String, List<SapTestReport>>>(emptyMap())

        @SuppressLint("MissingPermission")
        override suspend fun connect(deviceAddress: String): Result<Unit> {
            return try {
                disconnect()
                val device =
                    bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                        ?: return Result.failure(Exception("Device not found: $deviceAddress"))

                val sapSocket = device.createRfcommSocketToServiceRecord(SAP_UUID)
                sapSocket.connect()

                socket = sapSocket
                connected.value = true
                Timber.i("SAP connected to $deviceAddress")
                Result.success(Unit)
            } catch (e: SecurityException) {
                Timber.e(e, "Missing Bluetooth permissions")
                Result.failure(e)
            } catch (e: IOException) {
                Timber.e(e, "SAP connection failed")
                Result.failure(e)
            }
        }

        override suspend fun disconnect() {
            try {
                socket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing SAP socket")
            }
            socket = null
            connected.value = false
        }

        override suspend fun sendApdu(
            apdu: SimApdu,
            timeoutMs: Long,
        ): ByteArray? {
            val sock = socket ?: return null
            return try {
                val output = sock.outputStream
                val input = sock.inputStream

                // SAP TRANSFER_APDU_REQ message: TLV formatted
                val apduBytes = apdu.toBytes()
                val sapMsg = buildSapMessage(0x04, apduBytes) // 0x04 = TRANSFER_APDU_REQ
                output.write(sapMsg)
                output.flush()

                val buffer = ByteArray(4096)
                val response =
                    withTimeoutOrNull(timeoutMs) {
                        val read = input.read(buffer)
                        if (read > 0) buffer.copyOf(read) else null
                    }
                response
            } catch (e: IOException) {
                Timber.w(e, "SAP APDU send failed")
                null
            }
        }

        override suspend fun requestAtr(): ByteArray? {
            val sock = socket ?: return null
            return try {
                val output = sock.outputStream
                val input = sock.inputStream

                // SAP TRANSFER_ATR_REQ (0x06)
                val sapMsg = buildSapMessage(0x06, byteArrayOf())
                output.write(sapMsg)
                output.flush()

                val buffer = ByteArray(4096)
                withTimeoutOrNull(5000L) {
                    val read = input.read(buffer)
                    if (read > 0) buffer.copyOf(read) else null
                }
            } catch (e: IOException) {
                Timber.w(e, "SAP ATR request failed")
                null
            }
        }

        override suspend fun powerSimOff(): Result<Unit> {
            return sendSapCommand(0x08) // POWER_SIM_OFF_REQ
        }

        override suspend fun powerSimOn(): Result<Unit> {
            return sendSapCommand(0x0A) // POWER_SIM_ON_REQ
        }

        override suspend fun resetSim(): Result<Unit> {
            return sendSapCommand(0x0C) // RESET_SIM_REQ
        }

        override fun isSapConnected(): Flow<Boolean> = connected

        override suspend fun saveTestReport(report: SapTestReport) {
            val updated = savedReports.value.toMutableMap()
            val list = (updated[report.targetDevice] ?: emptyList()).toMutableList()
            list.add(report)
            updated[report.targetDevice] = list
            savedReports.value = updated
        }

        override fun getTestReports(deviceAddress: String): Flow<List<SapTestReport>> {
            return savedReports.map { it[deviceAddress] ?: emptyList() }
        }

        // ── Private helpers ──

        private suspend fun sendSapCommand(msgCode: Int): Result<Unit> {
            val sock = socket ?: return Result.failure(Exception("Not connected"))
            return try {
                val output = sock.outputStream
                val sapMsg = buildSapMessage(msgCode, byteArrayOf())
                output.write(sapMsg)
                output.flush()
                Result.success(Unit)
            } catch (e: IOException) {
                Timber.w(e, "SAP command 0x${msgCode.toString(16)} failed")
                Result.failure(e)
            }
        }

        /**
         * Build a minimal SAP message: [MsgCode(1)] [ParamId(1)] [ParamLen(2)] [Payload]
         */
        private fun buildSapMessage(
            msgCode: Int,
            payload: ByteArray,
        ): ByteArray {
            val msg = ByteArray(4 + payload.size)
            msg[0] = msgCode.toByte()
            msg[1] = 0x00 // Parameter ID placeholder
            msg[2] = ((payload.size shr 8) and 0xFF).toByte()
            msg[3] = (payload.size and 0xFF).toByte()
            if (payload.isNotEmpty()) {
                System.arraycopy(payload, 0, msg, 4, payload.size)
            }
            return msg
        }

        companion object {
            private val SAP_UUID: UUID = UUID.fromString("0000112D-0000-1000-8000-00805F9B34FB")
        }
    }
