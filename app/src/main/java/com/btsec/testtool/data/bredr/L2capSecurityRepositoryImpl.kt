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
import android.content.Context
import com.btsec.testtool.domain.model.L2capFixedChannel
import com.btsec.testtool.domain.model.L2capTestReport
import com.btsec.testtool.domain.repository.L2capSecurityRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [L2capSecurityRepository].
 *
 * L2CAP operations on Android are largely handled internally by the
 * Bluetooth stack. This implementation provides channel enumeration
 * via SDP and signaling command injection where the platform permits.
 *
 * Note: Raw L2CAP socket access requires L2CAP channel support
 * (Android 10+ with CO_SOCK or legacy createL2capChannel).
 */
@Singleton
class L2capSecurityRepositoryImpl
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) : L2capSecurityRepository {
        private val bluetoothManager: BluetoothManager =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

        private val connected = MutableStateFlow(false)
        private val savedReports = MutableStateFlow<Map<String, List<L2capTestReport>>>(emptyMap())

        @SuppressLint("MissingPermission")
        override suspend fun enumerateFixedChannels(deviceAddress: String): List<L2capFixedChannel> {
            val device =
                bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                    ?: return emptyList()

            // On Android, fixed channel support can be inferred from device features.
            // Full enumeration requires raw HCI access or reflection.
            val supportedChannels = mutableListOf<L2capFixedChannel>()

            // ATT (CID 0x0004) and SMP (CID 0x0006) are always available for BLE
            supportedChannels.add(L2capFixedChannel.ATT)
            supportedChannels.add(L2capFixedChannel.SMP)

            // BR/EDR signaling (CID 0x0001) is available for classic
            val uuids = device.uuids ?: emptyArray()
            val hasClassic =
                uuids.any {
                    // Extract the 4-char short UUID from positions 4-8.
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

        override suspend fun sendSignalingCommand(
            deviceAddress: String,
            channelId: Int,
            payload: ByteArray,
            timeoutMs: Long,
        ): ByteArray? {
            // Construct an L2CAP signaling packet for the given channel.
            // L2CAP signaling uses CID 0x0001 (BR/EDR) or 0x0005 (LE).
            // Format: length(2) | CID(2) | code(1) | identifier(1) | data-length(2) | data
            val signalCid = if (channelId == 0x0005 || channelId == 0x0006) 0x0005 else 0x0001

            val packet =
                java.nio.ByteBuffer
                    .allocate(4 + 4 + payload.size)
                    .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    .putShort((4 + payload.size).toShort()) // L2CAP payload length
                    .putShort(signalCid.toShort()) // Signaling CID
                    .put(payload.getOrElse(0) { 0 }.toByte()) // Command code (first byte of payload)
                    .put(generateIdentifier().toByte()) // Identifier
                    .putShort(payload.size.toShort()) // Data length
                    .put(payload)
                    .array()

            Timber.d("sendSignalingCommand: addr=$deviceAddress cid=$channelId size=${payload.size} packetSize=${packet.size}")

            // Attempt to send via L2CAP socket if available (Android 10+ LE CoC).
            // BR/EDR raw signaling requires root/HCI access.
            return try {
                val device =
                    bluetoothManager.adapter?.getRemoteDevice(deviceAddress)
                        ?: return null

                // Try createL2capChannel (Android 10+ via reflection for LE CoC)
                if (channelId >= 0x0040) {
                    sendViaL2capSocket(device, channelId, packet, timeoutMs)
                } else {
                    // BR/EDR signaling (CID 0x0001) requires raw socket access
                    // Log that we attempted; actual transmission needs native/HCI access
                    Timber.w("BR/EDR L2CAP signaling (CID=$channelId) requires native HCI access - packet constructed but not sent")
                    null
                }
            } catch (e: Exception) {
                Timber.w(e, "L2CAP signaling command failed for cid=$channelId")
                null
            }
        }

        override suspend fun queryInformation(
            deviceAddress: String,
            infoType: Int,
        ): ByteArray? {
            // Construct an L2CAP Information Request packet.
            // Format (signaling payload): code(1=0x0A) | id(1) | length(2) | info-type(2)
            val requestPayload =
                java.nio.ByteBuffer
                    .allocate(2)
                    .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    .putShort(infoType.toShort())
                    .array()

            val result = sendSignalingCommand(deviceAddress, 0x0001, requestPayload, 5000)
            if (result != null) {
                Timber.i("queryInformation: addr=$deviceAddress infoType=0x${infoType.toString(16)} response=${result.size} bytes")
            } else {
                Timber.w("queryInformation: no response for infoType=0x${infoType.toString(16)} (requires native HCI)")
            }
            return result
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

        private var signalIdentifier = 0

        private fun generateIdentifier(): Int {
            signalIdentifier = (signalIdentifier + 1) and 0xFF
            if (signalIdentifier == 0) signalIdentifier = 1 // 0 is invalid per spec
            return signalIdentifier
        }

        /**
         * Attempts to send an L2CAP packet via LE Connection-Oriented Channel.
         * Available on Android 10+ via createL2capChannel().
         *
         * @return The response bytes, or null if the socket could not be established.
         */
        @android.annotation.SuppressLint("MissingPermission")
        private suspend fun sendViaL2capSocket(
            device: android.bluetooth.BluetoothDevice,
            psm: Int,
            packet: ByteArray,
            timeoutMs: Long,
        ): ByteArray? {
            return try {
                // createInsecureL2capChannel is a hidden API on Android 10+.
                // Use reflection to access it for LE CoC L2CAP.
                val method =
                    device.javaClass.getMethod(
                        "createInsecureL2capChannel",
                        Int::class.javaPrimitiveType,
                    )
                val socket =
                    (method.invoke(device, psm) as? android.bluetooth.BluetoothSocket)
                        ?: return null

                socket.connect()
                socket.outputStream.write(packet)
                socket.outputStream.flush()

                val buffer = ByteArray(4096)
                val response =
                    kotlinx.coroutines.withTimeoutOrNull(timeoutMs) {
                        val read = socket.inputStream.read(buffer)
                        if (read > 0) buffer.copyOf(read) else null
                    }

                socket.close()
                response
            } catch (e: NoSuchMethodException) {
                Timber.d("createInsecureL2capChannel not available on this Android version")
                null
            } catch (e: Exception) {
                Timber.w(e, "L2CAP socket send failed for PSM=$psm")
                null
            }
        }
    }
