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
            // Raw L2CAP signaling requires socket-level access.
            // On Android 10+, use BluetoothSocket.createL2capChannel() for LE L2CAP.
            // For BR/EDR signaling, reflection or native HCI is needed.
            Timber.d("sendSignalingCommand: addr=$deviceAddress cid=$channelId size=${payload.size}")
            return null
        }

        override suspend fun queryInformation(
            deviceAddress: String,
            infoType: Int,
        ): ByteArray? {
            // L2CAP Information Request requires raw signaling access.
            Timber.d("queryInformation: addr=$deviceAddress infoType=$infoType")
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
    }
