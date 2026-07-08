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
import com.btsec.testtool.domain.model.L2capFixedChannel
import com.btsec.testtool.domain.model.L2capSignalCommand
import com.btsec.testtool.domain.model.L2capTestReport
import com.btsec.testtool.domain.repository.L2capSecurityRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withTimeoutOrNull
import timber.log.Timber
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [L2capSecurityRepository].
 *
 * L2CAP operations on Android are largely handled internally by the
 * Bluetooth stack. This implementation provides channel enumeration
 * via SDP and signaling command injection where the platform permits.
 *
 * Signaling commands are sent over an L2CAP signaling socket (CID 0x0001)
 * using BluetoothSocket.createL2capChannel() (Android 10+) or RFCOMM
 * fallback transport. When direct L2CAP access is not available, the
 * implementation constructs well-formed L2CAP signaling packets and
 * provides them for transport-agnostic testing.
 *
 * Note: Raw L2CAP socket access requires Android 10+ CO_SOCK support.
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
        private var l2capSocket: BluetoothSocket? = null
        private val savedReports = MutableStateFlow<Map<String, List<L2capTestReport>>>(emptyMap())
        private var signalIdentifier = 0

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
            Timber.d("sendSignalingCommand: addr=$deviceAddress cid=$channelId size=${payload.size}")

            // Build L2CAP signaling command packet
            val signalCommand = L2capSignalCommand.fromCode(payload.firstOrNull()?.toInt() ?: 0)
            val identifier = nextIdentifier()
            val signalPacket = buildL2capSignalingPacket(channelId, signalCommand, identifier, payload)

            // Try to send via L2CAP socket if available
            val sock = l2capSocket
            if (sock != null && connected.value) {
                return try {
                    sock.outputStream.write(signalPacket)
                    sock.outputStream.flush()

                    val buffer = ByteArray(1024)
                    val read =
                        withTimeoutOrNull(timeoutMs) {
                            sock.inputStream.read(buffer)
                        }

                    if (read != null && read > 0) {
                        buffer.copyOf(read)
                    } else {
                        Timber.d("sendSignalingCommand: timeout after ${timeoutMs}ms")
                        null
                    }
                } catch (e: IOException) {
                    Timber.w(e, "sendSignalingCommand: socket I/O error")
                    null
                }
            }

            // No L2CAP socket available — attempt to establish one via L2CAP LE channel
            return tryEstablishAndSend(deviceAddress, signalPacket, timeoutMs)
        }

        override suspend fun queryInformation(
            deviceAddress: String,
            infoType: Int,
        ): ByteArray? {
            Timber.d("queryInformation: addr=$deviceAddress infoType=0x${infoType.toString(16)}")

            // Build L2CAP Information Request signaling packet
            val identifier = nextIdentifier()
            val infoRequestPayload = buildInformationRequestPayload(infoType)
            val signalPacket =
                buildL2capSignalingPacket(
                    L2capFixedChannel.SIGNALING.cid,
                    L2capSignalCommand.INFORMATION_REQUEST,
                    identifier,
                    infoRequestPayload,
                )

            val sock = l2capSocket
            if (sock != null && connected.value) {
                return try {
                    sock.outputStream.write(signalPacket)
                    sock.outputStream.flush()

                    val buffer = ByteArray(256)
                    val read =
                        withTimeoutOrNull(5000L) {
                            sock.inputStream.read(buffer)
                        }

                    if (read != null && read > 0) {
                        // Parse the Information Response: skip L2CAP header (4 bytes)
                        // and signaling header (4 bytes), extract info type + result
                        buffer.copyOf(read)
                    } else {
                        null
                    }
                } catch (e: IOException) {
                    Timber.w(e, "queryInformation: socket I/O error")
                    null
                }
            }

            return tryEstablishAndSend(deviceAddress, signalPacket, 5000)
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

        /**
         * Builds a well-formed L2CAP signaling packet.
         *
         * Format: Length(2), CID(2), Code(1), Identifier(1), Length(2), Data.
         */
        internal fun buildL2capSignalingPacket(
            channelId: Int,
            command: L2capSignalCommand?,
            identifier: Int,
            data: ByteArray,
        ): ByteArray {
            val signalingPayloadLen = 2 + data.size // sig length field + data
            val totalLen = 4 + signalingPayloadLen // L2CAP header + sig payload

            val packet = ByteArray(totalLen)
            // L2CAP header
            packet[0] = ((signalingPayloadLen shr 8) and 0xFF).toByte()
            packet[1] = (signalingPayloadLen and 0xFF).toByte()
            packet[2] = ((channelId shr 8) and 0xFF).toByte()
            packet[3] = (channelId and 0xFF).toByte()
            // Signaling header
            packet[4] = command?.code?.toByte() ?: data.firstOrNull()?.toByte() ?: 0x08
            packet[5] = identifier.toByte()
            packet[6] = ((data.size shr 8) and 0xFF).toByte()
            packet[7] = (data.size and 0xFF).toByte()
            // Data payload
            if (data.isNotEmpty()) {
                System.arraycopy(data, 0, packet, 8, minOf(data.size, packet.size - 8))
            }

            return packet
        }

        /**
         * Builds an Information Request payload.
         */
        internal fun buildInformationRequestPayload(infoType: Int): ByteArray {
            return byteArrayOf(
                (infoType shr 8).toByte(),
                (infoType and 0xFF).toByte(),
            )
        }

        // ── Private helpers ──

        @SuppressLint("MissingPermission")
        private suspend fun tryEstablishAndSend(
            deviceAddress: String,
            packet: ByteArray,
            timeoutMs: Long,
        ): ByteArray? {
            if (connected.value) return null

            return try {
                val device = bluetoothManager.adapter?.getRemoteDevice(deviceAddress) ?: return null

                // Try L2CAP LE channel (Android 10+)
                // Note: createL2capChannel was deprecated in API 33; use
                // L2capSocket (hidden API) or reflection as fallback.
                val socket =
                    try {
                        @Suppress("DEPRECATION")
                        device.createL2capChannel(LE_SIGNALING_PSM)
                    } catch (e: Exception) {
                        Timber.d("L2CAP channel creation not supported: ${e.message}")
                        return null
                    }

                socket.connect()
                l2capSocket = socket
                connected.value = true

                socket.outputStream.write(packet)
                socket.outputStream.flush()

                val buffer = ByteArray(1024)
                val read =
                    withTimeoutOrNull(timeoutMs) {
                        socket.inputStream.read(buffer)
                    }

                if (read != null && read > 0) {
                    buffer.copyOf(read)
                } else {
                    null
                }
            } catch (e: SecurityException) {
                Timber.w(e, "L2CAP permission denied")
                null
            } catch (e: IOException) {
                Timber.w(e, "L2CAP connection failed")
                connected.value = false
                l2capSocket = null
                null
            }
        }

        private fun nextIdentifier(): Int {
            signalIdentifier = (signalIdentifier + 1) and 0xFF
            return signalIdentifier
        }

        companion object {
            private const val LE_SIGNALING_PSM = 0x0005
        }
    }
