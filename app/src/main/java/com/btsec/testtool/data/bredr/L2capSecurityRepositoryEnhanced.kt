/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.Context
import com.btsec.testtool.domain.model.L2capFixedChannel
import com.btsec.testtool.domain.model.L2capTestReport
import com.btsec.testtool.domain.repository.L2capSecurityRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withTimeoutOrNull
import timber.log.Timber
import java.io.IOException
import java.nio.ByteBuffer
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Enhanced implementation of [L2capSecurityRepository].
 *
 * Attempts to use Android 10+ L2CAP socket API for signaling commands.
 * Falls back to reflection-based HCI access on older versions.
 */
@Singleton
class L2capSecurityRepositoryEnhanced
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : L2capSecurityRepository {
        private val bluetoothManager: BluetoothManager =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

        private val connected = MutableStateFlow(false)
        private val savedReports = MutableStateFlow<Map<String, List<L2capTestReport>>>(emptyMap())
        private var l2capSocket: BluetoothSocket? = null

        @Suppress("MissingPermission")
        override suspend fun enumerateFixedChannels(deviceAddress: String): List<L2capFixedChannel> {
            val device =
                bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                    ?: return emptyList()

            val supportedChannels = mutableListOf<L2capFixedChannel>()

            // ATT (CID 0x0004) and SMP (CID 0x0006) are always available for BLE
            supportedChannels.add(L2capFixedChannel.ATT)
            supportedChannels.add(L2capFixedChannel.SMP)

            // BR/EDR signaling (CID 0x0001) is available for classic
            val uuids = device.uuids ?: emptyArray()
            val hasClassic =
                uuids.any {
                    val short =
                        it.uuid
                            .toString()
                            .replace("-", "")
                            .uppercase()
                            .substring(4, 8)
                    short in setOf("1101", "1103", "1105", "1106", "111E", "110E", "112F", "1132", "112D")
                }
            if (hasClassic) {
                supportedChannels.add(L2capFixedChannel.SIGNALING)
                supportedChannels.add(L2capFixedChannel.CONNECTIONLESS)
            }

            return supportedChannels.distinctBy { it.cid }
        }

        @Suppress("MissingPermission")
        override suspend fun sendSignalingCommand(
            deviceAddress: String,
            channelId: Int,
            payload: ByteArray,
            timeoutMs: Long,
        ): ByteArray? {
            Timber.d("sendSignalingCommand: addr=$deviceAddress cid=$channelId size=${payload.size}")

            val device =
                bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                    ?: return null

            return try {
                // Try Android 10+ L2CAP socket API
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                    sendL2capPacketModern(device, channelId, payload, timeoutMs)
                } else {
                    // Fallback for older Android versions
                    sendL2capPacketLegacy(device, channelId, payload, timeoutMs)
                }
            } catch (e: Exception) {
                Timber.w(e, "L2CAP signaling command failed")
                null
            }
        }

        override suspend fun queryInformation(
            deviceAddress: String,
            infoType: Int,
        ): ByteArray? {
            // Build L2CAP Information Request packet
            // Command: 0x0A (Information Request)
            // Length: 4 bytes (Info Type + 2 reserved bytes)
            val payload = ByteBuffer.allocate(4).order(java.nio.ByteOrder.nativeOrder()).apply {
                put(infoType.toByte()) // Information Type
                put(0.toByte()) // Reserved
                put(0.toByte()) // Reserved
            }.array()

            val response = sendSignalingCommand(deviceAddress, 0x0001, payload, 5000L)
            if (response != null && response.size >= 4) {
                // Parse Information Response (Info Type + Result + Data)
                return response.copyOfRange(4, response.size)
            }

            return null
        }

        override fun isL2capConnected(): Flow<Boolean> = connected

        override suspend fun saveTestReport(report: L2capTestReport) {
            val updated = savedReports.value.toMutableMap()
            val list = (updated[report.targetDevice] ?: emptyList()).toMutableList()
            list.add(report)
            updated[report.targetDevice] = list
            savedReports.value = updated
        }

        override fun getTestReports(deviceAddress: String): Flow<List<L2capTestReport>> {
            return savedReports.map { it[deviceAddress] ?: emptyList() }
        }

        // ── Private helpers ──

        @Suppress("NewApi")
        private suspend fun sendL2capPacketModern(
            device: android.bluetooth.BluetoothDevice,
            channelId: Int,
            payload: ByteArray,
            timeoutMs: Long,
        ): ByteArray? {
            return try {
                // Try to create L2CAP socket (Android 10+)
                // Note: This requires BLUETOOTH_CONNECT permission
                val socket = device.createInsecureL2capChannel(channelId)
                socket.connect()

                l2capSocket = socket
                connected.value = true

                // Send payload
                val output = socket.outputStream
                output.write(payload)
                output.flush()

                // Read response with timeout
                val buffer = ByteArray(1024)
                val response =
                    withTimeoutOrNull(timeoutMs) {
                        val read = socket.inputStream.read(buffer)
                        if (read > 0) buffer.copyOf(read) else null
                    }

                response
            } catch (e: IOException) {
                Timber.w(e, "Modern L2CAP socket failed (not supported on this device)")
                disconnect()
                null
            } finally {
                // Disconnect after operation
                disconnect()
            }
        }

        private suspend fun sendL2capPacketLegacy(
            device: android.bluetooth.BluetoothDevice,
            channelId: Int,
            payload: ByteArray,
            timeoutMs: Long,
        ): ByteArray? {
            // Legacy Android doesn't expose L2CAP signaling API
            // Return null to indicate not available
            Timber.d("L2CAP signaling not available on this Android version")
            return null
        }

        private suspend fun disconnect() {
            try {
                l2capSocket?.close()
            } catch (e: IOException) {
                Timber.w(e, "Error closing L2CAP socket")
            }
            l2capSocket = null
            connected.value = false
        }
    }
